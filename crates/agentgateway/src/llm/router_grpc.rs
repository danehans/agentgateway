use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use protos::model_router::model_router_client::ModelRouterClient;
use protos::model_router::{self as proto};

use crate::cel::{Expression, Value};
use crate::http::Request;
use crate::http::filters::BackendRequestTimeout;
use crate::http::transformation_cel::TransformationMetadata;
use crate::llm::router_callout::VirtualModelCalloutFailureMode;
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::types::agent::SimpleBackendReferenceWithPolicies;
use crate::*;

const METHOD: &str = "/agentgateway.dev.router.v1.ModelRouter/Route";
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// Typed unary model selection. No decision cache, retries, or request mutations
/// are performed by this strategy. Model responses do not traverse the router.
#[apply(schema!)]
pub struct GrpcCallout {
	#[serde(flatten)]
	pub target: SimpleBackendReferenceWithPolicies,
	/// Exact concrete model names the router may return (1..128). Wildcards and
	/// virtual targets are not allowed. Final model authorization still applies.
	pub candidates: Vec<String>,
	/// CEL expressions producing strings sent as trusted routing context.
	/// Authentication must establish any caller identity before this stage.
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub context: HashMap<String, Arc<Expression>>,
	/// Version of the routing policy. The router must echo this exact value.
	#[serde(default)]
	pub policy_generation: String,
	/// Total routing RPC deadline in milliseconds, including response decoding.
	#[serde(default = "default_timeout_ms")]
	pub timeout_ms: u32,
	/// Used for RPC/protocol failures only, never intentional router rejection.
	#[serde(default)]
	pub failure_mode: VirtualModelCalloutFailureMode,
}
fn default_timeout_ms() -> u32 {
	2000
}

pub enum Outcome {
	Selected(String),
	Rejected(proto::Rejection),
}

impl GrpcCallout {
	pub fn validate(&self) -> anyhow::Result<()> {
		ensure!(
			(1..=128).contains(&self.candidates.len()),
			"gRPC callout requires 1..128 candidates"
		);
		let mut names = HashSet::new();
		for name in &self.candidates {
			ensure!(
				!name.is_empty()
					&& name.len() <= 256
					&& !name.contains('*')
					&& name.trim() == name
					&& !name.chars().any(char::is_control),
				"invalid gRPC routing candidate"
			);
			ensure!(names.insert(name), "duplicate gRPC routing candidate");
		}
		ensure!(
			(1..=60_000).contains(&self.timeout_ms),
			"gRPC timeoutMs must be 1..60000"
		);
		ensure!(
			self.policy_generation.len() <= 256,
			"gRPC policyGeneration too long"
		);
		ensure!(self.context.len() <= 16, "at most 16 gRPC context entries");
		ensure!(
			self.context.keys().all(|k| valid_key(k)),
			"invalid gRPC context key"
		);
		if let VirtualModelCalloutFailureMode::Fallback(model) = &self.failure_mode {
			ensure!(
				self.candidates.contains(model),
				"gRPC fallback must be a candidate"
			);
		}
		Ok(())
	}

	pub async fn select(
		&self,
		client: &PolicyClient,
		req: &mut Request,
		body: Option<&serde_json::Value>,
		requested_model: &str,
	) -> anyhow::Result<Outcome> {
		let body = body.context("gRPC router requires a JSON body")?;
		let exec = cel::Executor::new_llm_request(req, body);
		let mut context = HashMap::new();
		for (key, expression) in &self.context {
			let Value::String(value) = exec.eval(expression)? else {
				bail!("gRPC context must be a string")
			};
			ensure!(value.len() <= 1024, "gRPC context value too long");
			context.insert(key.clone(), value.to_string());
		}
		let timeout = Duration::from_millis(u64::from(self.timeout_ms));
		let mut request = tonic::Request::new(proto::RouteRequest {
			request_id: uuid::Uuid::new_v4().to_string(),
			requested_model: requested_model.to_string(),
			input_format: "openai_chat".to_string(),
			request_json: serde_json::to_vec(body)?,
			candidates: self.candidates.clone(),
			context,
			policy_generation: self.policy_generation.clone(),
		});
		request.set_timeout(timeout);
		crate::telemetry::log::copy_span_writer(req.extensions(), request.extensions_mut());
		request
			.extensions_mut()
			.insert(BackendRequestTimeout(timeout));
		let client = client.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Callout);
		let mut span = client.start_grpc_span(&mut request, self.target.target.as_ref(), METHOD);
		let mut rpc = ModelRouterClient::new(self.target.grpc_channel(client))
			.max_decoding_message_size(MAX_RESPONSE_BYTES);
		let result = tokio::time::timeout(timeout, rpc.route(request)).await;
		let result = match result {
			Ok(result) => result,
			Err(_) => Err(tonic::Status::deadline_exceeded(
				"model routing deadline exceeded",
			)),
		};
		if let Some(span) = span.as_deref_mut() {
			span.record_grpc_result(&result);
		}
		let response = result?.into_inner();
		let outcome = self.validate_response(&response)?;

		let metadata = serde_json::json!({
				"policy_generation": response.policy_generation,
				"diagnostics": response.diagnostics,
				"action": match &outcome { Outcome::Selected(_) => "select", Outcome::Rejected(_) => "reject" },
				"model": match &outcome { Outcome::Selected(model) => Some(model), _ => None },
		});
		req
			.extensions_mut()
			.get_or_insert_with(TransformationMetadata::default)
			.0
			.insert("grpc_router".into(), metadata);
		Ok(outcome)
	}

	pub(super) fn record_failure(&self, req: &mut Request) {
		let (action, model) = match &self.failure_mode {
			VirtualModelCalloutFailureMode::Fallback(model) => ("fallback", Some(model)),
			VirtualModelCalloutFailureMode::FailClosed => ("error", None),
		};
		let metadata = serde_json::json!({
				"policy_generation": self.policy_generation,
				"action": action,
				"model": model,
				"diagnostics": {"reason": "callout_failed"},
		});
		req
			.extensions_mut()
			.get_or_insert_with(TransformationMetadata::default)
			.0
			.insert("grpc_router".into(), metadata);
	}

	fn validate_response(&self, response: &proto::RouteResponse) -> anyhow::Result<Outcome> {
		if response.policy_generation != self.policy_generation {
			return Ok(Outcome::Rejected(proto::Rejection {
				http_status: 409,
				code: "routing_policy_conflict".into(),
				message: "Router policy generation does not match gateway configuration".into(),
			}));
		}
		ensure!(
			response.diagnostics.len() <= 16
				&& response
					.diagnostics
					.iter()
					.all(|(k, v)| valid_key(k) && v.len() <= 256),
			"invalid routing diagnostics"
		);
		match response
			.outcome
			.as_ref()
			.context("missing routing outcome")?
		{
			proto::route_response::Outcome::Selection(selection) => {
				ensure!(
					self.candidates.contains(&selection.model),
					"router selected a model outside candidates"
				);
				Ok(Outcome::Selected(selection.model.clone()))
			},
			proto::route_response::Outcome::Rejection(rejection) => {
				ensure!(
					matches!(
						rejection.http_status,
						400 | 403 | 409 | 413 | 422 | 429 | 503
					) && valid_key(&rejection.code)
						&& rejection.message.len() <= 1024,
					"invalid routing rejection"
				);
				Ok(Outcome::Rejected(rejection.clone()))
			},
		}
	}
}
fn valid_key(s: &str) -> bool {
	!s.is_empty()
		&& s.len() <= 64
		&& s
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
pub(super) mod tests {
	use std::sync::Mutex;

	use proto::model_router_server::{ModelRouter, ModelRouterServer};
	use proto::route_response::Outcome as WireOutcome;

	use super::*;

	#[derive(Clone, Default)]
	struct Router {
		requests: Arc<Mutex<Vec<proto::RouteRequest>>>,
	}

	#[tonic::async_trait]
	impl ModelRouter for Router {
		async fn route(
			&self,
			req: tonic::Request<proto::RouteRequest>,
		) -> Result<tonic::Response<proto::RouteResponse>, tonic::Status> {
			assert!(req.metadata().contains_key("grpc-timeout"));
			let req = req.into_inner();
			self.requests.lock().unwrap().push(req.clone());
			let mut response = proto::RouteResponse {
				policy_generation: req.policy_generation,
				diagnostics: HashMap::from([("reason".into(), "test".into())]),
				outcome: Some(WireOutcome::Selection(proto::Selection {
					model: "premium-model".into(),
				})),
			};
			match req.requested_model.as_str() {
				"unavailable" | "closed" => return Err(tonic::Status::unavailable("test outage")),
				"deadline" => tokio::time::sleep(Duration::from_secs(5)).await,
				"reject" => {
					response.outcome = Some(WireOutcome::Rejection(proto::Rejection {
						http_status: 409,
						code: "session_conflict".into(),
						message: "Session belongs to a different model".into(),
					}))
				},
				"reject-unavailable" => {
					response.outcome = Some(WireOutcome::Rejection(proto::Rejection {
						http_status: 503,
						code: "session_store_unavailable".into(),
						message: "Session store unavailable".into(),
					}))
				},
				"missing" => response.outcome = None,
				"outside" => {
					response.outcome = Some(WireOutcome::Selection(proto::Selection {
						model: "unconfigured".into(),
					}))
				},
				"generation" => response.policy_generation = "stale".into(),
				"oversized" => {
					response
						.diagnostics
						.insert("too_large".into(), "x".repeat(MAX_RESPONSE_BYTES));
				},
				_ => {},
			}
			Ok(tonic::Response::new(response))
		}
	}

	pub(crate) struct TestServer {
		pub address: std::net::SocketAddr,
		pub requests: Arc<Mutex<Vec<proto::RouteRequest>>>,
		task: tokio::task::JoinHandle<()>,
	}
	impl Drop for TestServer {
		fn drop(&mut self) {
			self.task.abort();
		}
	}
	pub(crate) async fn start() -> TestServer {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		let router = Router::default();
		let requests = router.requests.clone();
		let task = tokio::spawn(async move {
			tonic::transport::Server::builder()
				.add_service(ModelRouterServer::new(router))
				.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
				.await
				.unwrap();
		});
		TestServer {
			address,
			requests,
			task,
		}
	}

	fn config() -> GrpcCallout {
		serde_json::from_value(serde_json::json!({
				"host": "127.0.0.1:50051", "candidates": ["economy-model", "premium-model"],
		}))
		.unwrap()
	}

	#[test]
	fn grpc_configuration_bounds() {
		let valid = config();
		valid.validate().unwrap();
		for candidates in [
			vec![],
			vec!["*".into()],
			vec!["model".into(), "model".into()],
			vec!["model\n".into()],
		] {
			let mut invalid = valid.clone();
			invalid.candidates = candidates;
			assert!(invalid.validate().is_err());
		}
		for timeout in [0, 60_001] {
			let mut invalid = valid.clone();
			invalid.timeout_ms = timeout;
			assert!(invalid.validate().is_err());
		}
		let mut invalid = valid.clone();
		invalid.failure_mode = VirtualModelCalloutFailureMode::Fallback("unknown".into());
		assert!(invalid.validate().is_err());
	}

	#[test]
	fn grpc_response_contract() {
		let config = config();
		let mut response = proto::RouteResponse::default();
		assert!(config.validate_response(&response).is_err());
		response.outcome = Some(WireOutcome::Selection(proto::Selection {
			model: "economy-model".into(),
		}));
		assert!(matches!(
			config.validate_response(&response),
			Ok(Outcome::Selected(_))
		));
		for status in [200, 302, 401, 500, u32::MAX] {
			response.outcome = Some(WireOutcome::Rejection(proto::Rejection {
				http_status: status,
				code: "bad".into(),
				message: "test".into(),
			}));
			assert!(config.validate_response(&response).is_err());
		}
		for code in ["", "bad code", "💥"] {
			response.outcome = Some(WireOutcome::Rejection(proto::Rejection {
				http_status: 409,
				code: code.into(),
				message: "test".into(),
			}));
			assert!(config.validate_response(&response).is_err());
		}
		response.policy_generation = "other".into();
		assert!(
			matches!(config.validate_response(&response), Ok(Outcome::Rejected(r)) if r.http_status == 409)
		);
	}
}
