use std::net::SocketAddr;
use std::sync::Mutex;

use agentgateway::test_helpers::{ateapimock, credprovidermock, extprocmock, oteltracemock};
use agentgateway::transport::stream::{SocketType, TLSConnectionInfo};
use agentgateway::transport::tls::TlsInfo;
use agentgateway::types::agent::{Backend, BackendWithPolicies, BindMode, TunnelProtocol};
use futures::FutureExt;
use protos::ateapi::{
	Actor, ActorState, ActorStatus, EgressPolicy, ResourceMetadata, ResumeActorResponse,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use tonic_types::{ErrorDetails, StatusExt};

use crate::common::prelude::*;

const ACTOR_UID: &str = "6f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f";
// Port 1 is privileged and outside the ephemeral range: nothing in the test process listens there.
const UNREACHABLE_ADDR: &str = "127.0.0.1:1";

#[test]
fn substrate_control_api_wire_tags() {
	assert_eq!(ActorState::Unspecified as i32, 0);
	assert_eq!(ActorState::Resuming as i32, 1);
	assert_eq!(ActorState::Running as i32, 2);
	assert_eq!(ActorState::Suspending as i32, 3);
	assert_eq!(ActorState::Suspended as i32, 4);
	assert_eq!(ActorState::Crashed as i32, 5);
	assert_eq!(ActorState::Deleting as i32, 6);
	assert_eq!(ActorState::Reverting as i32, 7);

	// Canonical Substrate tags: Actor.status=5 and MintActorJwtRequest fields=1,2,3.
	let actor = <Actor as prost::Message>::decode(&b"\x2a\x04\x08\x02\x12\x00"[..]).unwrap();
	let status = actor.status.unwrap();
	assert_eq!(status.state, ActorState::Running as i32);
	assert!(status.worker_assignment.is_some());
	let actor = Actor {
		metadata: Some(ResourceMetadata {
			uid: "u".into(),
			..Default::default()
		}),
		status: Some(ActorStatus {
			state: ActorState::Running as i32,
			activation_id: "a".into(),
			holds: vec![protos::ateapi::ActorHold {}],
			quarantine: Some(protos::ateapi::ActorQuarantine {}),
			..Default::default()
		}),
	};
	assert_eq!(
		prost::Message::encode_to_vec(&actor),
		b"\x0a\x03\x1a\x01u\x2a\x09\x08\x02\x42\x01a\x4a\x00\x52\x00"
	);

	let request = protos::ateapi::MintActorJwtRequest {
		actor: Some(protos::ateapi::ObjectRef {
			atespace: "a".into(),
			name: "b".into(),
		}),
		audiences: vec!["x".into()],
		expiration_seconds: 1,
	};
	assert_eq!(
		prost::Message::encode_to_vec(&request),
		b"\x0a\x06\x0a\x01a\x12\x01b\x12\x01x\x18\x01",
	);
}

async fn send_request(io: MemoryClient, method: Method, url: &str) -> Response {
	let authority = url
		.strip_prefix("http://")
		.and_then(|url| url.split('/').next())
		.expect("Substrate ingress test URL has an HTTP authority");
	let mut labels = authority.split('.');
	let actor = labels
		.next()
		.expect("Substrate ingress test URL has an actor");
	let atespace = labels
		.next()
		.expect("Substrate ingress test URL has an atespace");
	let target_actor = format!("{atespace}/{actor}");
	send_request_headers(
		io,
		method,
		url,
		&[("ate-target-actor", target_actor.as_str())],
	)
	.await
}

#[derive(Clone)]
struct IngressHandler {
	pod_ip: String,
	calls: Arc<AtomicUsize>,
	resumed: bool,
	uid: &'static str,
}

#[derive(Clone, Default)]
struct EgressHandler {
	uid: &'static str,
	state: Option<i32>,
	error: Option<tonic::Code>,
	activation_id: &'static str,
	quarantine: bool,
	held: bool,
}

#[derive(Clone)]
struct CredentialEgressHandler {
	policy: Result<EgressPolicy, tonic::Status>,
	state: ActorState,
	mint_calls: Option<Arc<AtomicUsize>>,
	mint_delay: Duration,
	jwt_expiration_seconds: i64,
}

#[async_trait::async_trait]
impl ateapimock::Handler for CredentialEgressHandler {
	async fn get_actor(
		&mut self,
		request: &protos::ateapi::GetActorRequest,
	) -> Result<Actor, tonic::Status> {
		let actor = request.actor.as_ref().unwrap();
		assert_eq!(
			(actor.atespace.as_str(), actor.name.as_str()),
			("demo", "my-actor")
		);
		Ok(Actor {
			metadata: Some(ResourceMetadata {
				uid: "uid-1".to_owned(),
				..Default::default()
			}),
			status: Some(ActorStatus {
				state: self.state as i32,
				worker_assignment: None,
				..Default::default()
			}),
		})
	}

	async fn get_actor_egress_policy(
		&mut self,
		request: &protos::ateapi::GetActorEgressPolicyRequest,
	) -> Result<EgressPolicy, tonic::Status> {
		if request.name != "default" {
			return Err(tonic::Status::invalid_argument("name must be default"));
		}
		let actor = request.actor.as_ref().unwrap();
		assert_eq!(
			(actor.atespace.as_str(), actor.name.as_str()),
			("demo", "my-actor")
		);
		self.policy.clone()
	}

	async fn mint_actor_jwt(
		&mut self,
		request: &protos::ateapi::MintActorJwtRequest,
	) -> Result<protos::ateapi::MintActorJwtResponse, tonic::Status> {
		let actor = request.actor.as_ref().unwrap();
		assert_eq!(
			(actor.atespace.as_str(), actor.name.as_str()),
			("demo", "my-actor")
		);
		assert_eq!(request.audiences, ["https://api.example.com"]);
		assert_eq!(request.expiration_seconds, self.jwt_expiration_seconds);
		self
			.mint_calls
			.as_ref()
			.unwrap()
			.fetch_add(1, Ordering::Relaxed);
		tokio::time::sleep(self.mint_delay).await;
		Ok(protos::ateapi::MintActorJwtResponse {
			actor_jwt: "minted-actor-jwt".to_owned(),
		})
	}
}

#[derive(Clone)]
struct CredentialHandler {
	calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl credprovidermock::Handler for CredentialHandler {
	async fn fetch_secret(
		&mut self,
		request: &protos::credprovider::FetchSecretRequest,
	) -> Result<protos::credprovider::FetchSecretResponse, tonic::Status> {
		assert_eq!(
			request.uri,
			"ate-secret://kubernetes.io/default/upstream-token"
		);
		assert_eq!(
			request.actor_spiffe_id,
			"spiffe://substrate-actor.local/actor/demo/my-actor"
		);
		self.calls.fetch_add(1, Ordering::Relaxed);
		Ok(protos::credprovider::FetchSecretResponse {
			opaque_bytes: b"injected-token".to_vec(),
		})
	}
}

#[async_trait::async_trait]
impl ateapimock::Handler for EgressHandler {
	async fn get_actor(
		&mut self,
		request: &protos::ateapi::GetActorRequest,
	) -> Result<Actor, tonic::Status> {
		let actor = request.actor.as_ref().unwrap();
		assert_eq!(
			(actor.atespace.as_str(), actor.name.as_str()),
			("demo", "my-actor")
		);
		if let Some(code) = self.error {
			return Err(tonic::Status::new(code, "GetActor failed"));
		}
		Ok(Actor {
			metadata: Some(ResourceMetadata {
				uid: self.uid.to_owned(),
				..Default::default()
			}),
			status: self.state.map(|state| ActorStatus {
				state,
				worker_assignment: None,
				activation_id: self.activation_id.to_owned(),
				quarantine: self
					.quarantine
					.then_some(protos::ateapi::ActorQuarantine {}),
				holds: if self.held {
					vec![protos::ateapi::ActorHold {}]
				} else {
					vec![]
				},
			}),
		})
	}
}

#[async_trait::async_trait]
impl ateapimock::Handler for IngressHandler {
	async fn resume_actor(
		&mut self,
		request: &protos::ateapi::ResumeActorRequest,
	) -> Result<ResumeActorResponse, tonic::Status> {
		let actor = request.actor.as_ref().unwrap();
		assert_eq!(actor.atespace, "demo");
		assert_eq!(actor.name, "my-actor");
		self.calls.fetch_add(1, Ordering::Relaxed);
		Ok(ResumeActorResponse {
			actor: Some(Actor {
				metadata: Some(ResourceMetadata {
					uid: self.uid.to_owned(),
					..Default::default()
				}),
				status: Some(ActorStatus {
					state: 0,
					worker_assignment: Some(protos::ateapi::WorkerAssignment {
						worker_pod_ips: vec![self.pod_ip.clone()],
					}),
					..Default::default()
				}),
			}),
			resumed: self.resumed,
		})
	}
}

#[derive(Clone)]
struct ParkingHandler {
	pod_ip: String,
	calls: Arc<AtomicUsize>,
	failures_before_success: usize,
	failure_code: tonic::Code,
	entered: Option<Arc<Notify>>,
	resumed: bool,
}

#[derive(Clone)]
struct RejectedResumeHandler {
	status: tonic::Status,
	calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ateapimock::Handler for RejectedResumeHandler {
	async fn resume_actor(
		&mut self,
		_request: &protos::ateapi::ResumeActorRequest,
	) -> Result<ResumeActorResponse, tonic::Status> {
		self.calls.fetch_add(1, Ordering::Relaxed);
		Err(self.status.clone())
	}
}

#[derive(Clone)]
struct SelectiveParkingHandler {
	pod_ip: String,
	parked_actor: String,
	entered: Arc<Notify>,
	release: Arc<Notify>,
	calls: Arc<AtomicUsize>,
	resumed: bool,
	uid: &'static str,
}

#[async_trait::async_trait]
impl ateapimock::Handler for SelectiveParkingHandler {
	async fn resume_actor(
		&mut self,
		request: &protos::ateapi::ResumeActorRequest,
	) -> Result<ResumeActorResponse, tonic::Status> {
		let actor = request.actor.as_ref().unwrap();
		self.calls.fetch_add(1, Ordering::Relaxed);
		if actor.name == self.parked_actor {
			self.entered.notify_one();
			self.release.notified().await;
		}
		Ok(ResumeActorResponse {
			actor: Some(Actor {
				metadata: Some(ResourceMetadata {
					uid: self.uid.to_owned(),
					..Default::default()
				}),
				status: Some(ActorStatus {
					state: 0,
					worker_assignment: Some(protos::ateapi::WorkerAssignment {
						worker_pod_ips: vec![self.pod_ip.clone()],
					}),
					..Default::default()
				}),
			}),
			resumed: self.resumed,
		})
	}
}

#[async_trait::async_trait]
impl ateapimock::Handler for ParkingHandler {
	async fn resume_actor(
		&mut self,
		_request: &protos::ateapi::ResumeActorRequest,
	) -> Result<ResumeActorResponse, tonic::Status> {
		let call = self.calls.fetch_add(1, Ordering::Relaxed);
		if call == 0 {
			self
				.entered
				.as_ref()
				.inspect(|entered| entered.notify_one());
		}
		if call < self.failures_before_success {
			return Err(tonic::Status::new(
				self.failure_code,
				"no free workers available",
			));
		}
		Ok(ResumeActorResponse {
			actor: Some(Actor {
				status: Some(ActorStatus {
					state: 0,
					worker_assignment: Some(protos::ateapi::WorkerAssignment {
						worker_pod_ips: vec![self.pod_ip.clone()],
					}),
					..Default::default()
				}),
				..Default::default()
			}),
			resumed: self.resumed,
		})
	}
}

#[tokio::test]
async fn actor_ingress_resolves_the_dynamic_backend() {
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;

	let dynamic = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic.into())
		.with_bind(simple_bind())
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api.address.to_string(),
				"connectTargetPort": actor.address().port(),
			}
		}))
		.await;

	let response = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		"http://my-actor.demo.actors.resources.substrate.ate.dev/",
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(calls.load(Ordering::Relaxed), 1);
	let actor_requests = actor.received_requests().await.unwrap();
	assert_eq!(
		actor_requests[0].headers.get("x-ate-target-port").unwrap(),
		"80"
	);
}

struct TraceparentHandler(IngressHandler, Arc<StdMutex<Vec<String>>>);

#[async_trait::async_trait]
impl ateapimock::Handler for TraceparentHandler {
	async fn resume_actor(
		&mut self,
		request: &protos::ateapi::ResumeActorRequest,
	) -> Result<ResumeActorResponse, tonic::Status> {
		self.0.resume_actor(request).await
	}

	fn resume_actor_metadata(&mut self, metadata: &tonic::metadata::MetadataMap) {
		let tp = metadata.get("traceparent").and_then(|v| v.to_str().ok());
		self.1.lock().unwrap().extend(tp.map(str::to_owned));
	}
}

struct TraceHandler {
	spans: Arc<StdMutex<Vec<opentelemetry_proto::tonic::trace::v1::Span>>>,
}

#[async_trait::async_trait]
impl oteltracemock::Handler for TraceHandler {
	async fn export(
		&mut self,
		request: &opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest,
	) -> Result<
		opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse,
		tonic::Status,
	> {
		self.spans.lock().unwrap().extend(
			request
				.resource_spans
				.iter()
				.flat_map(|resource| &resource.scope_spans)
				.flat_map(|scope| &scope.spans)
				.cloned(),
		);
		oteltracemock::ok_response()
	}
}

#[tokio::test]
async fn actor_ingress_propagates_trace_context_to_resume_actor() {
	unsafe {
		std::env::set_var("OTEL_BLRP_SCHEDULE_DELAY", "20");
		std::env::set_var("OTEL_BSP_SCHEDULE_DELAY", "20");
	}
	let spans = Arc::new(StdMutex::new(Vec::new()));
	let otel = oteltracemock::OtelTraceMock::new({
		let spans = Arc::clone(&spans);
		move || TraceHandler {
			spans: Arc::clone(&spans),
		}
	})
	.spawn()
	.await;
	let actor = simple_mock().await;
	let seen = Arc::new(StdMutex::new(Vec::new()));
	let api = ateapimock::AteApiMock::new({
		let (seen, pod_ip) = (seen.clone(), actor.address().ip().to_string());
		move || {
			let inner = IngressHandler {
				pod_ip: pod_ip.clone(),
				calls: Default::default(),
				resumed: true,
				uid: ACTOR_UID,
			};
			TraceparentHandler(inner, seen.clone())
		}
	})
	.spawn()
	.await;

	let dynamic = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic.into())
		.with_bind(simple_bind())
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_frontend_policy(json!({"tracing": {"host": otel.address.to_string()}}))
		.await;
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api.address.to_string(),
				"connectTargetPort": actor.address().port(),
			}
		}))
		.await;

	let client_tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
	let response = send_request_headers(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		"http://my-actor.demo.actors.resources.substrate.ate.dev/",
		&[
			("ate-target-actor", "demo/my-actor"),
			("traceparent", client_tp),
		],
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);

	// Same trace and sampled flag, but the gateway's own span as parent.
	let seen = seen.lock().unwrap().clone();
	assert_eq!(seen.len(), 1, "{seen:?}");
	assert_eq!(seen[0][..36], client_tp[..36]);
	assert_ne!(seen[0][36..52], client_tp[36..52]);
	assert!(seen[0].ends_with("-01"), "{}", seen[0]);

	tokio::time::timeout(Duration::from_secs(2), async {
		while spans.lock().unwrap().len() < 2 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();

	let spans = spans.lock().unwrap();
	let resume_actor = spans
		.iter()
		.find(|span| span.name == "substrate.ateapi.v1.Control/ResumeActor")
		.expect("ResumeActor client span should be exported");
	let request = spans
		.iter()
		.find(|span| {
			span.trace_id == resume_actor.trace_id && span.span_id == resume_actor.parent_span_id
		})
		.expect("parent request span should be exported");
	assert_eq!(resume_actor.trace_id, request.trace_id);
	assert_eq!(resume_actor.parent_span_id, request.span_id);
}

#[tokio::test]
async fn actor_ingress_parks_while_worker_capacity_recovers() {
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || ParkingHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			failures_before_success: 2,
			failure_code: tonic::Code::ResourceExhausted,
			entered: None,
			resumed: true,
		}
	})
	.spawn()
	.await;

	let dynamic = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic.into())
		.with_bind(simple_bind())
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api.address.to_string(),
				"connectTargetPort": actor.address().port(),
				"requestParking": {
					"budget": "1s",
					"max": 1,
					"retryInterval": "1ms",
					"retryFactor": 1.0,
				}
			}
		}))
		.await;

	let response = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		"http://my-actor.demo.actors.resources.substrate.ate.dev/",
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(calls.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn actor_ingress_sheds_when_request_parking_is_full() {
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let entered = Arc::new(Notify::new());
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let entered = entered.clone();
		let pod_ip = actor.address().ip().to_string();
		move || ParkingHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			failures_before_success: 2,
			failure_code: tonic::Code::FailedPrecondition,
			entered: Some(entered.clone()),
			resumed: true,
		}
	})
	.spawn()
	.await;

	let dynamic = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic.into())
		.with_bind(simple_bind())
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api.address.to_string(),
				"connectTargetPort": actor.address().port(),
				"requestParking": {
					"budget": "1s",
					"max": 1,
					"retryInterval": "100ms",
					"retryFactor": 1.0,
				}
			}
		}))
		.await;

	let first = tokio::spawn(send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		"http://my-actor.demo.actors.resources.substrate.ate.dev/",
	));
	entered.notified().await;
	let second = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		"http://another-actor.demo.actors.resources.substrate.ate.dev/",
	)
	.await;
	assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(first.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn actor_ingress_keeps_cached_actor_available_when_parking_is_full() {
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let entered = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let entered = entered.clone();
		let release = release.clone();
		let pod_ip = actor.address().ip().to_string();
		move || SelectiveParkingHandler {
			pod_ip: pod_ip.clone(),
			parked_actor: "cold-actor".to_string(),
			entered: entered.clone(),
			release: release.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;

	let dynamic = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic.into())
		.with_bind(simple_bind())
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api.address.to_string(),
				"connectTargetPort": actor.address().port(),
				"requestParking": {
					"budget": "1s",
					"max": 1,
				}
			}
		}))
		.await;

	let running_actor = "http://running-actor.demo.actors.resources.substrate.ate.dev/";
	assert_eq!(
		send_request(gateway.serve_http(BIND_KEY), Method::GET, running_actor)
			.await
			.status(),
		StatusCode::OK
	);

	let cold = tokio::spawn(send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		"http://cold-actor.demo.actors.resources.substrate.ate.dev/",
	));
	entered.notified().await;

	assert_eq!(
		send_request(gateway.serve_http(BIND_KEY), Method::GET, running_actor)
			.await
			.status(),
		StatusCode::OK
	);
	assert_eq!(calls.load(Ordering::Relaxed), 2);

	release.notify_one();
	assert_eq!(cold.await.unwrap().status(), StatusCode::OK);
}

/// Asserts the access log emitted `ate.router.resume` for the request that used `path`. Every
/// caller needs its own path: the capture buffer is process-global.
async fn assert_logged_resume(path: &str, want: &str) {
	agent_core::telemetry::testing::eventually_find(&[
		("scope", "request"),
		("http.path", path),
		("ate.router.resume", want),
	])
	.await
	.unwrap();
}

fn logged_route_duration(log: &Value) -> f64 {
	let duration = &log["ate.router.route.duration"];
	assert!(
		duration.as_str().is_none(),
		"the route duration must be a number, not a formatted string: {log:#?}"
	);
	duration
		.as_f64()
		.unwrap_or_else(|| panic!("no numeric ate.router.route.duration: {log:#?}"))
}

async fn find_request_log(path: &str) -> Value {
	agent_core::telemetry::testing::eventually_find(&[("scope", "request"), ("http.path", path)])
		.await
		.unwrap()
}

fn actor_url(actor: &str, path: &str) -> String {
	format!("http://{actor}.demo.actors.resources.substrate.ate.dev{path}")
}

async fn resume_disposition_gateway(
	api_address: std::net::SocketAddr,
	actor_port: u16,
) -> agentgateway::test_helpers::proxymock::TestBind {
	let dynamic = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic.into())
		.with_bind(simple_bind())
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api_address.to_string(),
				"connectTargetPort": actor_port,
			}
		}))
		.await;
	gateway
}

async fn actor_service_ingress_response(
	api_address: SocketAddr,
	request_parking: Value,
) -> Response {
	let dynamic = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic.into())
		.with_bind(simple_bind())
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api_address.to_string(),
				"connectTargetPort": 80,
				"requestParking": request_parking,
			}
		}))
		.await;
	send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		&actor_url("my-actor", "/"),
	)
	.await
}

#[tokio::test]
async fn actor_ingress_rejections_match_substrate_contract() {
	let response =
		actor_service_ingress_response(UNREACHABLE_ADDR.parse().unwrap(), json!({ "max": 0 })).await;
	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(response.headers()["ate-error-reason"], "API_UNAVAILABLE");

	let api = ateapimock::AteApiMock::new(|| RejectedResumeHandler {
		status: tonic::Status::unavailable("resume unavailable"),
		calls: Default::default(),
	})
	.spawn()
	.await;
	let response = actor_service_ingress_response(
		api.address,
		json!({
			"budget": "100ms",
			"max": 1,
			"retryInterval": "10ms",
			"retryFactor": 1.0,
		}),
	)
	.await;
	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(response.headers()["ate-error-reason"], "API_UNAVAILABLE");

	for (code, reason) in [
		(tonic::Code::ResourceExhausted, "NO_CAPACITY"),
		(tonic::Code::FailedPrecondition, "TERMINAL_STATE"),
	] {
		let calls = Arc::new(AtomicUsize::new(0));
		let status = tonic::Status::with_error_details(
			code,
			"resume refused",
			ErrorDetails::with_error_info(reason, "ate.dev", std::collections::HashMap::new()),
		);
		let api = ateapimock::AteApiMock::new({
			let calls = calls.clone();
			move || RejectedResumeHandler {
				status: status.clone(),
				calls: calls.clone(),
			}
		})
		.spawn()
		.await;
		let request_parking = if reason == "NO_CAPACITY" {
			json!({ "max": 0 })
		} else {
			json!({
				"budget": "100ms",
				"max": 1,
				"retryInterval": "10ms",
				"retryFactor": 1.0,
			})
		};
		let response = actor_service_ingress_response(api.address, request_parking).await;
		assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
		assert_eq!(response.headers()["ate-error-reason"], reason);
		if reason == "TERMINAL_STATE" {
			assert_eq!(calls.load(Ordering::Relaxed), 1);
		}
	}
}

#[tokio::test]
async fn actor_ingress_reports_a_triggered_resume_as_a_cold_start() {
	const PATH: &str = "/resume-triggered";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let mut trace_rx = agentgateway::proxy::dtrace::track_expression(Some(
		agentgateway::cel::Expression::new_strict(format!("request.path == '{PATH}'")).unwrap(),
	));
	let response = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		&actor_url("my-actor", PATH),
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(calls.load(Ordering::Relaxed), 1);

	assert_logged_resume(PATH, "triggered").await;

	let mut events = Vec::new();
	while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(50), trace_rx.recv()).await {
		events.push(serde_json::to_value(msg).unwrap())
	}
	let resumes: Vec<&serde_json::Value> = events
		.iter()
		.filter(|event| event["message"]["type"] == "policyEvent")
		.filter(|event| event["message"]["kind"] == "substrate")
		.map(|event| &event["message"]["details"]["resume"])
		.collect();
	assert_eq!(resumes, vec!["triggered"], "{events:#?}");
}

#[tokio::test]
async fn actor_ingress_reports_no_resume_when_the_actor_is_already_running() {
	const PATH: &str = "/resume-already-running";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: false,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let response = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		&actor_url("my-actor", PATH),
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(calls.load(Ordering::Relaxed), 1);
	assert_logged_resume(PATH, "none").await;
}

#[tokio::test]
async fn actor_ingress_reports_no_resume_for_a_cache_hit_after_a_cold_start() {
	const COLD_PATH: &str = "/resume-cache-cold";
	const WARM_PATH: &str = "/resume-cache-warm";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	for path in [COLD_PATH, WARM_PATH] {
		let response = send_request(
			gateway.serve_http(BIND_KEY),
			Method::GET,
			&actor_url("my-actor", path),
		)
		.await;
		assert_eq!(response.status(), StatusCode::OK);
	}

	assert_eq!(
		calls.load(Ordering::Relaxed),
		1,
		"the second request must be served from the assignment cache"
	);
	assert_logged_resume(COLD_PATH, "triggered").await;
	assert_logged_resume(WARM_PATH, "none").await;
}

#[tokio::test]
async fn actor_ingress_logs_the_actor_uid_on_a_cold_start() {
	const PATH: &str = "/actor-uid-cold";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let response = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		&actor_url("my-actor", PATH),
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(calls.load(Ordering::Relaxed), 1);

	let log = find_request_log(PATH).await;
	assert_eq!(log["ate.actor.uid"].as_str(), Some(ACTOR_UID), "{log:#?}");
}

#[tokio::test]
async fn actor_ingress_logs_the_actor_uid_from_the_assignment_cache() {
	const COLD_PATH: &str = "/actor-uid-cache-cold";
	const WARM_PATH: &str = "/actor-uid-cache-warm";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	for path in [COLD_PATH, WARM_PATH] {
		let response = send_request(
			gateway.serve_http(BIND_KEY),
			Method::GET,
			&actor_url("my-actor", path),
		)
		.await;
		assert_eq!(response.status(), StatusCode::OK);
	}

	assert_eq!(
		calls.load(Ordering::Relaxed),
		1,
		"the second request must be served from the assignment cache"
	);
	for path in [COLD_PATH, WARM_PATH] {
		let log = find_request_log(path).await;
		assert_eq!(
			log["ate.actor.uid"].as_str(),
			Some(ACTOR_UID),
			"{path}: {log:#?}"
		);
	}
}

#[tokio::test]
async fn actor_ingress_logs_actor_identity_under_the_upstream_spellings() {
	const PATH: &str = "/actor-identity-spelling";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let response = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		&actor_url("my-actor", PATH),
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);

	let log = find_request_log(PATH).await;
	assert_eq!(log["ate.actor.name"].as_str(), Some("my-actor"), "{log:#?}");
	assert_eq!(log["ate.actor.uid"].as_str(), Some(ACTOR_UID), "{log:#?}");
	assert_eq!(log["ate.atespace"].as_str(), Some("demo"), "{log:#?}");
	assert!(
		log.get("ate.actor.id").is_none(),
		"ate.actor.id was renamed to ate.actor.name: {log:#?}"
	);
}

#[tokio::test]
async fn actor_ingress_reports_a_joined_resume_for_a_follower_on_an_in_flight_resume() {
	const LEADER_PATH: &str = "/resume-join-leader";
	const FOLLOWER_PATH: &str = "/resume-join-follower";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let entered = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let entered = entered.clone();
		let release = release.clone();
		let pod_ip = actor.address().ip().to_string();
		move || SelectiveParkingHandler {
			pod_ip: pod_ip.clone(),
			parked_actor: "my-actor".to_string(),
			entered: entered.clone(),
			release: release.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let leader = tokio::spawn({
		let io = gateway.serve_http(BIND_KEY);
		let url = actor_url("my-actor", LEADER_PATH);
		async move { send_request(io, Method::GET, &url).await }
	});
	// The leader is inside ResumeActor, so the singleflight placeholder exists and the follower
	// cannot become a second leader or read a warm cache entry.
	entered.notified().await;
	let follower = tokio::spawn({
		let io = gateway.serve_http(BIND_KEY);
		let url = actor_url("my-actor", FOLLOWER_PATH);
		async move { send_request(io, Method::GET, &url).await }
	});
	tokio::time::sleep(Duration::from_millis(200)).await;
	release.notify_one();

	assert_eq!(leader.await.unwrap().status(), StatusCode::OK);
	assert_eq!(follower.await.unwrap().status(), StatusCode::OK);
	assert_eq!(
		calls.load(Ordering::Relaxed),
		1,
		"the follower must have joined the leader's resume, not started its own"
	);

	assert_logged_resume(LEADER_PATH, "triggered").await;
	assert_logged_resume(FOLLOWER_PATH, "joined").await;
}

#[tokio::test]
async fn actor_ingress_reports_the_activation_time_for_a_triggered_resume() {
	const PATH: &str = "/route-duration-triggered";
	const GATE: Duration = Duration::from_millis(300);
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let entered = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let entered = entered.clone();
		let release = release.clone();
		let pod_ip = actor.address().ip().to_string();
		move || SelectiveParkingHandler {
			pod_ip: pod_ip.clone(),
			parked_actor: "my-actor".to_string(),
			entered: entered.clone(),
			release: release.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let request = tokio::spawn({
		let io = gateway.serve_http(BIND_KEY);
		let url = actor_url("my-actor", PATH);
		async move { send_request(io, Method::GET, &url).await }
	});
	entered.notified().await;
	tokio::time::sleep(GATE).await;
	release.notify_one();
	assert_eq!(request.await.unwrap().status(), StatusCode::OK);

	assert_logged_resume(PATH, "triggered").await;
	let log = find_request_log(PATH).await;
	let duration = logged_route_duration(&log);
	assert!(
		duration >= 0.25,
		"a resume gated for {GATE:?} must report at least that long, got {duration}: {log:#?}"
	);
}

#[tokio::test]
async fn actor_ingress_reports_a_followers_own_wait_rather_than_the_leaders() {
	const LEADER_PATH: &str = "/route-duration-leader";
	const FOLLOWER_PATH: &str = "/route-duration-follower";
	const LEAD: Duration = Duration::from_millis(300);
	const FOLLOWER_WAIT: Duration = Duration::from_millis(200);
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let entered = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let entered = entered.clone();
		let release = release.clone();
		let pod_ip = actor.address().ip().to_string();
		move || SelectiveParkingHandler {
			pod_ip: pod_ip.clone(),
			parked_actor: "my-actor".to_string(),
			entered: entered.clone(),
			release: release.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let leader = tokio::spawn({
		let io = gateway.serve_http(BIND_KEY);
		let url = actor_url("my-actor", LEADER_PATH);
		async move { send_request(io, Method::GET, &url).await }
	});
	// The leader is inside ResumeActor. It stays there for LEAD before the follower is even sent,
	// so the two requests cannot have waited the same amount of time.
	entered.notified().await;
	tokio::time::sleep(LEAD).await;
	let follower = tokio::spawn({
		let io = gateway.serve_http(BIND_KEY);
		let url = actor_url("my-actor", FOLLOWER_PATH);
		async move { send_request(io, Method::GET, &url).await }
	});
	tokio::time::sleep(FOLLOWER_WAIT).await;
	release.notify_one();

	assert_eq!(leader.await.unwrap().status(), StatusCode::OK);
	assert_eq!(follower.await.unwrap().status(), StatusCode::OK);
	assert_eq!(
		calls.load(Ordering::Relaxed),
		1,
		"the follower must have joined the leader's resume, not started its own"
	);
	assert_logged_resume(LEADER_PATH, "triggered").await;
	assert_logged_resume(FOLLOWER_PATH, "joined").await;

	let leader_log = find_request_log(LEADER_PATH).await;
	let follower_log = find_request_log(FOLLOWER_PATH).await;
	let leader_duration = logged_route_duration(&leader_log);
	let follower_duration = logged_route_duration(&follower_log);
	assert!(
		leader_duration >= 0.45,
		"the leader waited {LEAD:?} + {FOLLOWER_WAIT:?}, got {leader_duration}: {leader_log:#?}"
	);
	assert!(
		follower_duration >= 0.15,
		"the follower parked on the guard for {FOLLOWER_WAIT:?}, got {follower_duration}: {follower_log:#?}"
	);
	assert!(
		leader_duration - follower_duration > 0.15,
		"a follower must report its own wait, not the leader's cached number: \
		 leader={leader_duration} follower={follower_duration}"
	);
}

#[tokio::test]
async fn actor_ingress_reports_a_near_zero_duration_for_a_cache_hit() {
	const COLD_PATH: &str = "/route-duration-cache-cold";
	const WARM_PATH: &str = "/route-duration-cache-warm";
	const GATE: Duration = Duration::from_millis(300);
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let entered = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let entered = entered.clone();
		let release = release.clone();
		let pod_ip = actor.address().ip().to_string();
		move || SelectiveParkingHandler {
			pod_ip: pod_ip.clone(),
			parked_actor: "my-actor".to_string(),
			entered: entered.clone(),
			release: release.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let cold = tokio::spawn({
		let io = gateway.serve_http(BIND_KEY);
		let url = actor_url("my-actor", COLD_PATH);
		async move { send_request(io, Method::GET, &url).await }
	});
	entered.notified().await;
	tokio::time::sleep(GATE).await;
	release.notify_one();
	assert_eq!(cold.await.unwrap().status(), StatusCode::OK);

	let warm = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		&actor_url("my-actor", WARM_PATH),
	)
	.await;
	assert_eq!(warm.status(), StatusCode::OK);
	assert_eq!(
		calls.load(Ordering::Relaxed),
		1,
		"the second request must be served from the assignment cache"
	);

	let cold_log = find_request_log(COLD_PATH).await;
	let warm_log = find_request_log(WARM_PATH).await;
	let cold_duration = logged_route_duration(&cold_log);
	let warm_duration = logged_route_duration(&warm_log);
	assert!(
		warm_duration < 0.05,
		"a cache hit resolves without ateapi, got {warm_duration}: {warm_log:#?}"
	);
	assert!(
		cold_duration - warm_duration > 0.15,
		"a cache hit must not inherit the cold start's duration: \
		 cold={cold_duration} warm={warm_duration}"
	);
}

#[tokio::test]
async fn actor_ingress_emits_the_route_duration_as_a_number_of_seconds() {
	const PATH: &str = "/route-duration-number";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let response = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		&actor_url("my-actor", PATH),
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);

	let log = find_request_log(PATH).await;
	assert!(
		log["ate.router.route.duration"].is_number(),
		"a latency panel queries this arithmetically: {log:#?}"
	);
	assert!(
		log["duration"].as_str().is_some(),
		"the sibling `duration` is the formatted style this key must not copy: {log:#?}"
	);
}

#[tokio::test]
async fn actor_ingress_reports_no_resume_when_the_resume_fails() {
	const PATH: &str = "/resume-failed";
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || ParkingHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			failures_before_success: 1,
			failure_code: tonic::Code::NotFound,
			entered: None,
			resumed: true,
		}
	})
	.spawn()
	.await;
	let gateway = resume_disposition_gateway(api.address, actor.address().port()).await;

	let mut trace_rx = agentgateway::proxy::dtrace::track_expression(Some(
		agentgateway::cel::Expression::new_strict(format!("request.path == '{PATH}'")).unwrap(),
	));
	let response = send_request(
		gateway.serve_http(BIND_KEY),
		Method::GET,
		&actor_url("my-actor", PATH),
	)
	.await;
	assert_eq!(response.status(), StatusCode::NOT_FOUND);
	assert_eq!(calls.load(Ordering::Relaxed), 1);

	assert_logged_resume(PATH, "none").await;

	let mut events = Vec::new();
	while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(50), trace_rx.recv()).await {
		events.push(serde_json::to_value(msg).unwrap())
	}
	let resumes: Vec<&serde_json::Value> = events
		.iter()
		.filter(|event| event["message"]["type"] == "policyEvent")
		.filter(|event| event["message"]["kind"] == "substrate")
		.map(|event| &event["message"]["details"]["resume"])
		.collect();
	assert_eq!(resumes, vec!["none"], "{events:#?}");
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
#[tokio::test]
async fn actor_ingress_uses_the_original_connect_target_actor(#[case] http2: bool) {
	let actor = simple_mock().await;
	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = actor.address().ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;

	let dynamic = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15012".parse().unwrap();
	outer.tunnel_protocol = TunnelProtocol::Connect;
	let mut inner = simple_bind();
	inner.key = strng::literal!("bind/wildcard");
	inner.mode = BindMode::Internal;
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic.into())
		.with_bind(outer)
		.with_bind(inner)
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api.address.to_string(),
				"connectTargetPort": actor.address().port(),
			}
		}))
		.await;

	let mut io = SocketType::Memory(gateway.serve_tunnel(strng::literal!("outer")));
	let connect_target = "application.example:9090";
	let mut connection = None;
	if http2 {
		let (mut sender, driver) =
			hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
				.handshake(hyper_util::rt::TokioIo::new(io))
				.await
				.unwrap();
		connection = Some(tokio::spawn(driver));
		let mut response = sender
			.send_request(
				::http::Request::builder()
					.method(Method::CONNECT)
					.uri(connect_target)
					.header("ate-target-actor", "demo/my-actor")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		io = SocketType::Upgraded(hyper_util::rt::TokioIo::new(
			hyper::upgrade::on(&mut response).await.unwrap(),
		));
	} else {
		io.write_all(
	format!(
		"CONNECT {connect_target} HTTP/1.1\r\nHost: unrelated.example:8080\r\nate-target-actor: demo/my-actor\r\n\r\n"
	)
	.as_bytes(),
	)
	.await
	.unwrap();
		let mut response = Vec::new();
		loop {
			let mut chunk = [0; 1024];
			let n = io.read(&mut chunk).await.unwrap();
			assert!(n > 0, "CONNECT response unexpectedly closed");
			response.extend_from_slice(&chunk[..n]);
			if response.windows(4).any(|window| window == b"\r\n\r\n") {
				break;
			}
		}
		assert!(
			String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK\r\n"),
			"unexpected CONNECT response: {}",
			String::from_utf8_lossy(&response),
		);
	}

	// The re-entered request's Host is unrelated to the actor. Native ingress
	// must use the original CONNECT routing header retained in SourceContext.
	io.write_all(b"GET / HTTP/1.1\r\nHost: irrelevant.example\r\nConnection: close\r\n\r\n")
		.await
		.unwrap();
	let mut tunneled = Vec::new();
	tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut tunneled))
		.await
		.expect("timed out waiting for tunneled response")
		.unwrap();
	assert!(
		String::from_utf8_lossy(&tunneled).starts_with("HTTP/1.1 200 OK\r\n"),
		"unexpected tunneled response: {}",
		String::from_utf8_lossy(&tunneled),
	);
	assert_eq!(calls.load(Ordering::Relaxed), 1);
	let actor_requests = actor.received_requests().await.unwrap();
	assert_eq!(
		actor_requests[0].headers.get("x-ate-target-port").unwrap(),
		"9090"
	);
	if let Some(connection) = connection {
		connection.abort();
	}
}

#[tokio::test]
async fn actor_ingress_uses_backend_tunnel_for_connect() {
	let actor = simple_mock().await;
	let actor_address = *actor.address();
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let atunnel_address = listener.local_addr().unwrap();
	let atunnel = tokio::spawn(async move {
		let (mut downstream, _) = listener.accept().await.unwrap();
		let mut request = Vec::new();
		loop {
			let mut chunk = [0; 1024];
			let n = downstream.read(&mut chunk).await.unwrap();
			assert!(n > 0, "CONNECT request unexpectedly closed");
			request.extend_from_slice(&chunk[..n]);
			if request.windows(4).any(|window| window == b"\r\n\r\n") {
				break;
			}
		}
		let request = String::from_utf8(request).unwrap();
		assert!(
			request.starts_with("CONNECT application.example:9090 HTTP/1.1\r\n"),
			"unexpected tunnel request: {request:?}"
		);
		assert!(
			request.contains("ate-target-actor: demo/my-actor\r\n"),
			"tunnel request is missing the actor header: {request:?}"
		);
		downstream
			.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
			.await
			.unwrap();
		let mut upstream = TcpStream::connect(actor_address).await.unwrap();
		let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
	});

	let calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let calls = calls.clone();
		let pod_ip = atunnel_address.ip().to_string();
		move || IngressHandler {
			pod_ip: pod_ip.clone(),
			calls: calls.clone(),
			resumed: true,
			uid: ACTOR_UID,
		}
	})
	.spawn()
	.await;

	let dynamic_backend = Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None);
	let dynamic_name = dynamic_backend.name();
	let dynamic = BackendWithPolicies {
		backend: dynamic_backend,
		inline_policies: vec![BackendTrafficPolicy::Tunnel(backend::Tunnel {
			proxy: Arc::new(SimpleBackendReference::Backend(dynamic_name.clone())),
			mode: backend::TunnelMode::Connect,
			policies: vec![],
		})],
	};
	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.tunnel_protocol = TunnelProtocol::Connect;
	let mut inner = simple_bind();
	inner.key = strng::literal!("bind/wildcard");
	inner.mode = BindMode::Internal;
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(dynamic)
		.with_bind(outer)
		.with_bind(inner)
		.with_route(basic_named_route(strng::literal!("/dynamic")));
	gateway
		.attach_route_policy(json!({
			"substrateIngress": {
				"host": api.address.to_string(),
				"connectTargetPort": atunnel_address.port(),
			}
		}))
		.await;
	let mut io = gateway.serve_tunnel(strng::literal!("outer"));
	let authority = "application.example:9090";
	io.write_all(
		format!(
			"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nate-target-actor: demo/my-actor\r\n\r\n"
		)
		.as_bytes(),
	)
	.await
	.unwrap();
	let mut response = [0; 128];
	let response_len = io.read(&mut response).await.unwrap();
	assert!(String::from_utf8_lossy(&response[..response_len]).starts_with("HTTP/1.1 200 OK\r\n"));

	io.write_all(b"GET / HTTP/1.1\r\nHost: irrelevant.example\r\nConnection: close\r\n\r\n")
		.await
		.unwrap();
	let mut response = Vec::new();
	tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut response))
		.await
		.expect("timed out waiting for tunneled response")
		.unwrap();
	assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK\r\n"));
	assert_eq!(calls.load(Ordering::Relaxed), 1);
	let actor_requests = actor.received_requests().await.unwrap();
	assert_eq!(actor_requests.len(), 1);
	assert_eq!(
		actor_requests[0].headers.get("x-ate-target-port").unwrap(),
		"9090"
	);
	drop(io);
	atunnel.abort();
}

fn actor_certificate(uri: &str) -> String {
	actor_certificate_with_identity(uri, Some("uid-1"), None)
}

fn actor_certificate_with_identity(
	uri: &str,
	uid: Option<&str>,
	activation_id: Option<&str>,
) -> String {
	actor_certificate_for("my-actor", uri, uid, activation_id)
}

fn actor_certificate_for(
	actor_name: &str,
	uri: &str,
	uid: Option<&str>,
	activation_id: Option<&str>,
) -> String {
	let mut params = rcgen::CertificateParams::default();
	params
		.subject_alt_names
		.push(rcgen::SanType::URI(uri.try_into().unwrap()));
	if let Some(uid) = uid {
		let mut identity = serde_json::json!({
			"Atespace": "demo",
			"ActorName": actor_name,
			"ActorUid": uid,
		});
		if let Some(activation_id) = activation_id {
			identity["ActivationId"] = activation_id.into();
		}
		params
			.custom_extensions
			.push(rcgen::CustomExtension::from_oid_content(
				&[1, 3, 6, 1, 4, 1, 11129, 2, 12, 2],
				serde_json::to_vec(&identity).unwrap(),
			));
	}
	params
		.self_signed(&rcgen::KeyPair::generate().unwrap())
		.unwrap()
		.pem()
}

async fn substrate_egress_connect_status(
	handler: EgressHandler,
	certificate_uri: &str,
	payload: &[u8],
) -> StatusCode {
	let api = ateapimock::AteApiMock::new(move || handler.clone())
		.spawn()
		.await;
	substrate_egress_connect_status_at(api.address, certificate_uri, payload).await
}

async fn substrate_egress_connect_status_at(
	api_address: std::net::SocketAddr,
	certificate_uri: &str,
	payload: &[u8],
) -> StatusCode {
	substrate_egress_connect_status_at_certificate(
		api_address,
		actor_certificate(certificate_uri),
		payload,
	)
	.await
}

async fn substrate_egress_connect_status_at_certificate(
	api_address: std::net::SocketAddr,
	certificate: String,
	payload: &[u8],
) -> StatusCode {
	substrate_egress_connect_response_at_certificate(api_address, certificate, payload)
		.await
		.0
}

async fn substrate_egress_connect_response_at_certificate(
	api_address: std::net::SocketAddr,
	certificate: String,
	payload: &[u8],
) -> (StatusCode, String) {
	let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	upstream.set_nonblocking(true).unwrap();
	let upstream_address = upstream.local_addr().unwrap();

	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15012".parse().unwrap();
	let mut inner = simple_bind();
	inner.address = "0.0.0.0:18080".parse().unwrap();
	inner.mode = BindMode::Internal;
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_backend(upstream_address)
		.with_bind(outer)
		.with_bind(inner)
		.with_route(basic_route(upstream_address))
		.with_connect_mode_on_port(agentgateway::types::frontend::ConnectMode::Tunnel, 15012);
	gateway
		.attach_frontend_policy(json!({
			"substrateEgressActorResolution": {
				"host": api_address.to_string(),
			}
		}))
		.await;

	let mut io = gateway.serve_tunnel_with_tls_info(
		strng::literal!("outer"),
		Some(TLSConnectionInfo {
			src_identity: Some(TlsInfo {
				certificate: Some(certificate.into()),
				..Default::default()
			}),
			..Default::default()
		}),
	);
	io.write_all(b"CONNECT allowed.example:18080 HTTP/1.1\r\nHost: allowed.example:18080\r\n\r\n")
		.await
		.unwrap();
	let mut response = Vec::new();
	loop {
		let mut chunk = [0; 1024];
		let n = io.read(&mut chunk).await.unwrap();
		assert!(n > 0, "CONNECT response unexpectedly closed");
		response.extend_from_slice(&chunk[..n]);
		if response.windows(4).any(|window| window == b"\r\n\r\n") {
			break;
		}
	}
	if response.starts_with(b"HTTP/1.1 200 OK\r\n") {
		io.write_all(payload).await.unwrap();
		(StatusCode::OK, String::from_utf8(response).unwrap())
	} else if response.starts_with(b"HTTP/1.1 403 Forbidden\r\n") {
		assert!(upstream.accept().is_err(), "denied CONNECT dialed upstream");
		let body_start = response
			.windows(4)
			.position(|window| window == b"\r\n\r\n")
			.unwrap()
			+ 4;
		let headers = String::from_utf8_lossy(&response[..body_start]);
		let body_length: usize = headers
			.lines()
			.find_map(|line| {
				line
					.to_ascii_lowercase()
					.strip_prefix("content-length:")
					.map(|value| value.trim().parse().unwrap())
			})
			.unwrap();
		while response.len() - body_start < body_length {
			let mut chunk = [0; 1024];
			let n = io.read(&mut chunk).await.unwrap();
			assert!(n > 0, "CONNECT body unexpectedly closed");
			response.extend_from_slice(&chunk[..n]);
		}
		(StatusCode::FORBIDDEN, String::from_utf8(response).unwrap())
	} else if response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n") {
		assert!(
			upstream.accept().is_err(),
			"unavailable CONNECT dialed upstream"
		);
		(
			StatusCode::SERVICE_UNAVAILABLE,
			String::from_utf8(response).unwrap(),
		)
	} else {
		panic!(
			"unexpected CONNECT response: {}",
			String::from_utf8_lossy(&response)
		)
	}
}

#[tokio::test]
async fn substrate_egress_actor_resolution_refreshes_on_long_lived_tunnel() {
	#[derive(Clone)]
	struct CountingHandler {
		calls: Arc<AtomicUsize>,
	}

	#[async_trait::async_trait]
	impl ateapimock::Handler for CountingHandler {
		async fn get_actor(
			&mut self,
			_request: &protos::ateapi::GetActorRequest,
		) -> Result<Actor, tonic::Status> {
			self.calls.fetch_add(1, Ordering::Relaxed);
			Ok(Actor {
				metadata: Some(ResourceMetadata {
					uid: "uid-1".to_owned(),
					..Default::default()
				}),
				status: Some(ActorStatus {
					state: ActorState::Running as i32,
					worker_assignment: None,
					..Default::default()
				}),
			})
		}
	}

	let first_calls = Arc::new(AtomicUsize::new(0));
	let first_api = ateapimock::AteApiMock::new({
		let calls = first_calls.clone();
		move || CountingHandler {
			calls: calls.clone(),
		}
	})
	.spawn()
	.await;
	let second_calls = Arc::new(AtomicUsize::new(0));
	let second_api = ateapimock::AteApiMock::new({
		let calls = second_calls.clone();
		move || CountingHandler {
			calls: calls.clone(),
		}
	})
	.spawn()
	.await;

	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15012".parse().unwrap();
	let mut inner = simple_bind();
	inner.address = "0.0.0.0:18080".parse().unwrap();
	inner.mode = BindMode::Internal;
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_bind(outer)
		.with_bind(inner)
		.with_connect_mode_on_port(agentgateway::types::frontend::ConnectMode::Tunnel, 15012);
	gateway
		.attach_frontend_policy(json!({
			"substrateEgressActorResolution": {
				"host": first_api.address.to_string(),
			}
		}))
		.await;

	let io = gateway.serve_tunnel_with_tls_info(
		strng::literal!("outer"),
		Some(TLSConnectionInfo {
			src_identity: Some(TlsInfo {
				certificate: Some(
					actor_certificate("spiffe://substrate-actor.local/worker-for-actor/demo/my-actor").into(),
				),
				..Default::default()
			}),
			..Default::default()
		}),
	);
	let (mut sender, connection) =
		hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
			.handshake(hyper_util::rt::TokioIo::new(io))
			.await
			.unwrap();
	let connection = tokio::spawn(connection);

	let connect = || {
		::http::Request::builder()
			.method(Method::CONNECT)
			.uri("allowed.example:18080")
			.body(Body::empty())
			.unwrap()
	};
	assert_eq!(
		sender.send_request(connect()).await.unwrap().status(),
		StatusCode::OK
	);
	assert_eq!(first_calls.load(Ordering::Relaxed), 1);

	gateway
		.pi
		.stores
		.binds
		.write()
		.remove_policy(strng::literal!("pol/1"));
	gateway
		.attach_frontend_policy(json!({
			"substrateEgressActorResolution": {
				"host": second_api.address.to_string(),
			}
		}))
		.await;

	assert_eq!(
		sender.send_request(connect()).await.unwrap().status(),
		StatusCode::OK
	);
	assert_eq!(first_calls.load(Ordering::Relaxed), 1);
	assert_eq!(second_calls.load(Ordering::Relaxed), 1);
	connection.abort();
}

async fn open_actor_egress_tunnel(gateway: &TestBind, port: u16) -> tokio::io::DuplexStream {
	match open_actor_egress_tunnel_protocol(gateway, port, false).await {
		tokio_util::either::Either::Left(io) => io,
		tokio_util::either::Either::Right(_) => unreachable!(),
	}
}

#[derive(Clone)]
struct PolicyContextHandler {
	policy: Arc<StdMutex<Option<EgressPolicy>>>,
}

#[async_trait::async_trait]
impl ateapimock::Handler for PolicyContextHandler {
	async fn get_actor(
		&mut self,
		_request: &protos::ateapi::GetActorRequest,
	) -> Result<Actor, tonic::Status> {
		Ok(Actor {
			metadata: Some(ResourceMetadata {
				uid: "uid-1".to_owned(),
				..Default::default()
			}),
			status: Some(ActorStatus {
				state: ActorState::Running as i32,
				worker_assignment: None,
				..Default::default()
			}),
		})
	}

	async fn get_actor_egress_policy(
		&mut self,
		_request: &protos::ateapi::GetActorEgressPolicyRequest,
	) -> Result<EgressPolicy, tonic::Status> {
		self
			.policy
			.lock()
			.unwrap()
			.clone()
			.ok_or_else(|| tonic::Status::not_found("actor egress policy deleted"))
	}
}

#[derive(Clone)]
struct PolicyContextExtProc {
	seen: Arc<StdMutex<Vec<prost_wkt_types::Struct>>>,
	opens: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl extprocmock::Handler for PolicyContextExtProc {
	async fn on_open(&mut self, _metadata: &tonic::metadata::MetadataMap) {
		self.opens.fetch_add(1, Ordering::Relaxed);
	}

	async fn on_request(&mut self, request: &agentgateway::http::ext_proc::proto::ProcessingRequest) {
		if matches!(
			request.request.as_ref(),
			Some(agentgateway::http::ext_proc::proto::processing_request::Request::RequestHeaders(_))
		) {
			let context = request.metadata_context.as_ref().unwrap();
			self
				.seen
				.lock()
				.unwrap()
				.push(context.filter_metadata["policy"].clone());
		}
	}
}

async fn policy_context_gateway(
	port: u16,
) -> (
	TestBind,
	Arc<StdMutex<Option<EgressPolicy>>>,
	Arc<StdMutex<Vec<prost_wkt_types::Struct>>>,
	Arc<AtomicUsize>,
	agentgateway::test_helpers::MockInstance,
	agentgateway::test_helpers::MockInstance,
) {
	let policy = Arc::new(StdMutex::new(Some(EgressPolicy {
		metadata: Some(ResourceMetadata {
			uid: "policy-1".to_owned(),
			version: 1,
		}),
		rules: vec![protos::ateapi::EgressRule {
			http: Some(protos::ateapi::HttpRule {
				hostnames: vec!["localhost".to_owned()],
				ports: Some(protos::ateapi::Ports {
					numbers: vec![i32::from(port)],
					..Default::default()
				}),
				effects: None,
			}),
			..Default::default()
		}],
	})));
	let api = ateapimock::AteApiMock::new({
		let policy = policy.clone();
		move || PolicyContextHandler {
			policy: policy.clone(),
		}
	})
	.spawn()
	.await;
	let seen = Arc::new(StdMutex::new(Vec::new()));
	let opens = Arc::new(AtomicUsize::new(0));
	let ext_proc = extprocmock::ExtProcMock::new({
		let seen = seen.clone();
		let opens = opens.clone();
		move || PolicyContextExtProc {
			seen: seen.clone(),
			opens: opens.clone(),
		}
	})
	.spawn()
	.await;
	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15013".parse().unwrap();
	outer.mode = BindMode::Internal;
	let mut inner = simple_bind();
	inner.address = std::net::SocketAddr::from(([0, 0, 0, 0], port));
	inner.mode = BindMode::Internal;
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(BackendWithPolicies {
			backend: Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None),
			inline_policies: vec![],
		})
		.with_bind(outer)
		.with_bind(inner)
		.with_route(basic_named_route("/dynamic".into()))
		.with_connect_mode_on_port(agentgateway::types::frontend::ConnectMode::Tunnel, 15013);
	gateway
		.attach_frontend_policy(json!({
			"substrateEgressActorResolution": { "host": api.address.to_string() }
		}))
		.await;
	gateway
		.attach_route_policy(json!({
			"substrateEgress": { "host": api.address.to_string() },
			"extProc": {
				"host": ext_proc.address.to_string(),
				"processingOptions": { "responseHeaderMode": "skip", "responseBodyMode": "none" },
				"metadataContext": {
					"policy": {
						"uid": "substrate.egressPolicy.uid",
						"version": "substrate.egressPolicy.version"
					}
				}
			}
		}))
		.await;
	(gateway, policy, seen, opens, api, ext_proc)
}

async fn request_policy_context(gateway: &TestBind, port: u16, host: &str) -> StatusCode {
	let mut io = open_actor_egress_tunnel(gateway, port).await;
	io.write_all(
		format!(
			"GET http://{host}/policy-context HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
		)
		.as_bytes(),
	)
	.await
	.unwrap();
	let mut response = Vec::new();
	tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut response))
		.await
		.unwrap()
		.unwrap();
	let response = String::from_utf8(response).unwrap();
	let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
	assert!(
		status == StatusCode::OK || status == StatusCode::FORBIDDEN,
		"{response}"
	);
	status
}

fn assert_policy_context(context: &prost_wkt_types::Struct, uid: &str, version: i64) {
	use prost_wkt_types::value::Kind;
	assert!(matches!(
		context.fields["uid"].kind.as_ref(),
		Some(Kind::StringValue(value)) if value == uid
	));
	assert!(matches!(
		context.fields["version"].kind.as_ref(),
		Some(Kind::NumberValue(value)) if *value == version as f64
	));
}

#[tokio::test]
async fn substrate_egress_ext_proc_gets_context_only_for_allowed_requests() {
	let upstream = simple_mock().await;
	let port = upstream.address().port();
	let (gateway, _policy, seen, opens, _api, _ext_proc) = policy_context_gateway(port).await;
	assert_eq!(
		request_policy_context(&gateway, port, "localhost").await,
		StatusCode::OK
	);
	assert_eq!(seen.lock().unwrap().len(), 1);
	assert_eq!(opens.load(Ordering::Relaxed), 1);
	assert_policy_context(&seen.lock().unwrap()[0], "policy-1", 1);
	assert_eq!(
		request_policy_context(&gateway, port, "denied.example").await,
		StatusCode::FORBIDDEN
	);
	assert_eq!(seen.lock().unwrap().len(), 1);
	assert_eq!(opens.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn substrate_egress_ext_proc_gets_updated_and_recreated_policy_context() {
	let upstream = simple_mock().await;
	let port = upstream.address().port();
	let (gateway, policy, seen, opens, _api, _ext_proc) = policy_context_gateway(port).await;
	for (index, version) in [1, 2].into_iter().enumerate() {
		{
			let mut policy = policy.lock().unwrap();
			let metadata = policy.as_mut().unwrap().metadata.as_mut().unwrap();
			metadata.version = version;
		}
		assert_eq!(
			request_policy_context(&gateway, port, "localhost").await,
			StatusCode::OK
		);
		let contexts = seen.lock().unwrap();
		assert_eq!(contexts.len(), index + 1);
		assert_policy_context(contexts.last().unwrap(), "policy-1", version);
	}
	let mut recreated = policy.lock().unwrap().take().unwrap();
	assert_eq!(
		request_policy_context(&gateway, port, "localhost").await,
		StatusCode::FORBIDDEN
	);
	assert_eq!(opens.load(Ordering::Relaxed), 2);
	recreated.metadata.as_mut().unwrap().uid = "policy-2".to_owned();
	recreated.metadata.as_mut().unwrap().version = 1;
	*policy.lock().unwrap() = Some(recreated);
	assert_eq!(
		request_policy_context(&gateway, port, "localhost").await,
		StatusCode::OK
	);
	let contexts = seen.lock().unwrap();
	assert_eq!(contexts.len(), 3);
	assert_policy_context(contexts.last().unwrap(), "policy-2", 1);
}

async fn open_actor_egress_tunnel_protocol(
	gateway: &TestBind,
	port: u16,
	http2: bool,
) -> tokio_util::either::Either<tokio::io::DuplexStream, TokioIo<hyper::upgrade::Upgraded>> {
	open_actor_egress_tunnel_certificate(
		gateway,
		port,
		http2,
		actor_certificate("spiffe://substrate-actor.local/worker-for-actor/demo/my-actor"),
	)
	.await
}
async fn open_actor_egress_tunnel_certificate(
	gateway: &TestBind,
	port: u16,
	http2: bool,
	certificate: String,
) -> tokio_util::either::Either<tokio::io::DuplexStream, TokioIo<hyper::upgrade::Upgraded>> {
	let mut io = gateway.serve_tunnel_with_tls_info(
		strng::literal!("outer"),
		Some(TLSConnectionInfo {
			src_identity: Some(TlsInfo {
				certificate: Some(certificate.into()),
				..Default::default()
			}),
			..Default::default()
		}),
	);
	if http2 {
		let (mut sender, connection) =
			hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
				.handshake(TokioIo::new(io))
				.await
				.unwrap();
		tokio::spawn(connection);
		let mut response = sender
			.send_request(
				::http::Request::builder()
					.method(Method::CONNECT)
					.uri(format!("127.0.0.2:{port}"))
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		return tokio_util::either::Either::Right(TokioIo::new(
			hyper::upgrade::on(&mut response).await.unwrap(),
		));
	}
	io.write_all(
		format!("CONNECT 127.0.0.2:{port} HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n").as_bytes(),
	)
	.await
	.unwrap();
	let mut response = Vec::new();
	while !response.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
		let mut buf = [0; 128];
		let n = io.read(&mut buf).await.unwrap();
		assert_ne!(n, 0, "CONNECT closed before responding");
		response.extend_from_slice(&buf[..n]);
	}
	assert!(
		String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK\r\n"),
		"{}",
		String::from_utf8_lossy(&response)
	);
	tokio_util::either::Either::Left(io)
}

#[cfg(feature = "crypto-aws-lc")]
#[rstest::rstest]
#[case(false, false, false, None)]
#[case(false, true, false, None)]
#[case(false, true, false, Some("0s"))]
#[case(true, false, false, None)]
#[case(true, true, false, None)]
#[case(false, true, true, None)]
#[tokio::test]
async fn substrate_egress_replaces_only_requested_credentials(
	#[case] https: bool,
	#[case] placeholder: bool,
	#[case] actor_jwt: bool,
	#[case] cache_ttl: Option<&str>,
	#[values(ActorState::Running, ActorState::Resuming)] state: ActorState,
	#[values(false, true)] outer_http2: bool,
) {
	let delayed_actor_jwt = actor_jwt && state == ActorState::Running;
	let jwt_expiration_seconds = if delayed_actor_jwt { 3 } else { 600 };
	let (upstream, backend_tls) = if https {
		let (upstream, certs) = tls_mock().await;
		let tls: agentgateway::http::backendtls::BackendTLS =
			agentgateway::http::backendtls::ResolvedBackendTLS {
				root: Some(certs.root_cert.pem().into_bytes()),
				hostname: Some("localhost".to_owned()),
				..Default::default()
			}
			.try_into()
			.unwrap();
		(upstream, vec![BackendTrafficPolicy::BackendTLS(tls)])
	} else {
		(simple_mock().await, vec![])
	};
	let port = upstream.address().port();
	let effects = Some(protos::ateapi::HttpRuleEffects {
		replace_headers: vec![protos::ateapi::CredentialHeader {
			header: "authorization".to_owned(),
			prefix: "Bearer ".to_owned(),
			credential_uri: if actor_jwt {
				String::new()
			} else {
				"ate-secret://kubernetes.io/default/upstream-token".to_owned()
			},
			actor_jwt: actor_jwt.then_some(protos::ateapi::ActorJwtSource {
				audiences: vec!["https://api.example.com".to_owned()],
				expiration_seconds: jwt_expiration_seconds,
			}),
		}],
	});
	let ports = Some(protos::ateapi::Ports {
		all: None,
		numbers: vec![i32::from(port)],
	});
	let rule = if https {
		protos::ateapi::EgressRule {
			https: Some(protos::ateapi::HttpsRule {
				hostnames: vec!["localhost".to_owned()],
				ports,
				effects,
			}),
			..Default::default()
		}
	} else {
		protos::ateapi::EgressRule {
			http: Some(protos::ateapi::HttpRule {
				hostnames: vec!["localhost".to_owned()],
				ports,
				effects,
			}),
			..Default::default()
		}
	};
	// A less specific rule has an unavailable provider. Only the winner may apply effects.
	let mut fallback = rule.clone();
	let fallback_effects = Some(protos::ateapi::HttpRuleEffects {
		replace_headers: vec![protos::ateapi::CredentialHeader {
			header: "authorization".to_owned(),
			credential_uri: "ate-secret://unconfigured/default/token".to_owned(),
			..Default::default()
		}],
	});
	let any_port = Some(protos::ateapi::Ports {
		all: Some(protos::ateapi::AllPorts {}),
		numbers: vec![],
	});
	if let Some(http) = fallback.http.as_mut() {
		http.ports = any_port.clone();
		http.effects = fallback_effects.clone();
	}
	if let Some(https) = fallback.https.as_mut() {
		https.ports = any_port;
		https.effects = fallback_effects;
	}
	let policy = EgressPolicy {
		rules: vec![fallback, rule],
		..Default::default()
	};
	let mint_calls = Arc::new(AtomicUsize::new(0));
	let api = ateapimock::AteApiMock::new({
		let mint_calls = mint_calls.clone();
		move || CredentialEgressHandler {
			policy: Ok(policy.clone()),
			state,
			mint_calls: actor_jwt.then(|| mint_calls.clone()),
			mint_delay: if delayed_actor_jwt {
				Duration::from_millis(1500)
			} else {
				Duration::ZERO
			},
			jwt_expiration_seconds,
		}
	})
	.spawn()
	.await;
	let credential_calls = Arc::new(AtomicUsize::new(0));
	let credential_provider = credprovidermock::CredentialProviderMock::new({
		let credential_calls = credential_calls.clone();
		move || CredentialHandler {
			calls: credential_calls.clone(),
		}
	})
	.spawn()
	.await;

	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15013".parse().unwrap();
	let inner = BindSnapshot::new(
		Bind {
			key: BIND_KEY,
			address: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
			protocol: if https {
				BindProtocol::tls
			} else {
				BindProtocol::http
			},
			tunnel_protocol: Default::default(),
			mode: BindMode::Internal,
		},
		ListenerSet::from_list([Listener {
			key: LISTENER_KEY,
			name: Default::default(),
			hostname: Default::default(),
			protocol: if https {
				ListenerProtocol::HTTPS(crate::tests::tls::test_server_tls_config())
			} else {
				ListenerProtocol::HTTP
			},
			..Default::default()
		}]),
	);
	let mut gateway = crate::tests::dfp::setup_dfp_bind()
		.with_raw_backend(BackendWithPolicies {
			backend: Backend::Dynamic(
				ResourceName::new("dynamic".into(), "".into()),
				Some(Arc::new(
					agentgateway::cel::Expression::new_strict(
						r#"destination.address + ":" + string(destination.port)"#,
					)
					.unwrap(),
				)),
			),
			inline_policies: backend_tls,
		})
		.with_bind(outer)
		.with_bind(inner)
		.with_connect_mode_on_port(agentgateway::types::frontend::ConnectMode::Tunnel, 15013);
	gateway
		.attach_frontend_policy(json!({
			"substrateEgressActorResolution": { "host": api.address.to_string() },
			"accessLog": {
				"add": {
					"substrate.connect.authority": "destination.address + \":\" + string(destination.port)"
				}
			}
		}))
		.await;
	let mut credential_provider_config = json!({
		"uriAuthority": "kubernetes.io",
		"target": { "host": credential_provider.address.to_string() }
	});
	if let Some(ttl) = cache_ttl {
		credential_provider_config["cacheTtl"] = json!(ttl);
	}
	gateway
		.attach_route_policy(json!({
			"substrateEgress": {
				"host": api.address.to_string(),
				"credentialProviders": [credential_provider_config]
			}
		}))
		.await;

	let io = open_actor_egress_tunnel_protocol(&gateway, port, outer_http2).await;

	let path = format!("/substrate-egress-credentials-{https}-{placeholder}-{port}-{outer_http2}");
	let authorization = if placeholder {
		"AuThOrIzAtIoN: Bearer actor-supplied\r\n"
	} else {
		""
	};
	// The request's port must neither select a rule nor change the dynamic dial target.
	// Deliberately use the opposite URI scheme to exercise transport-based matching.
	let scheme = if https { "http" } else { "https" };
	let request = format!(
		"GET {scheme}://localhost:1{path} HTTP/1.1\r\nHost: localhost:1\r\n{authorization}Connection: close\r\n\r\n"
	);
	async fn exchange(mut io: impl AsyncRead + AsyncWrite + Unpin, request: &str) {
		io.write_all(request.as_bytes()).await.unwrap();
		let mut response = Vec::new();
		tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut response))
			.await
			.expect("timed out waiting for tunneled response")
			.unwrap();
		assert!(
			String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK\r\n"),
			"{}",
			String::from_utf8_lossy(&response)
		);
	}
	if https {
		let tls: agentgateway::http::backendtls::BackendTLS =
			agentgateway::http::backendtls::ResolvedBackendTLS {
				root: Some(include_bytes!("../../../../examples/mcp-tls/certs/ca-cert.pem").to_vec()),
				insecure_host: true,
				alpn: Some(vec!["http/1.1".to_owned()]),
				..Default::default()
			}
			.try_into()
			.unwrap();
		let io = tokio_rustls::TlsConnector::from(tls.base_config().config)
			.connect(
				rustls_pki_types::ServerName::try_from("localhost").unwrap(),
				io,
			)
			.await
			.unwrap();
		exchange(io, &request).await;
	} else {
		exchange(io, &request).await;
	}

	assert_eq!(
		credential_calls.load(Ordering::Relaxed),
		usize::from(placeholder && !actor_jwt)
	);
	assert_eq!(
		mint_calls.load(Ordering::Relaxed),
		usize::from(placeholder && actor_jwt)
	);
	if delayed_actor_jwt {
		tokio::time::sleep(Duration::from_millis(700)).await;
		let io = open_actor_egress_tunnel_protocol(&gateway, port, outer_http2).await;
		exchange(io, &request).await;
		assert_eq!(mint_calls.load(Ordering::Relaxed), 2);
	}
	// A second request reuses the cached credential unless the provider's TTL is zero.
	let repeated = placeholder && !actor_jwt && !https;
	if repeated {
		let io = open_actor_egress_tunnel_protocol(&gateway, port, outer_http2).await;
		exchange(io, &request).await;
		assert_eq!(
			credential_calls.load(Ordering::Relaxed),
			1 + usize::from(cache_ttl == Some("0s"))
		);
	}
	let upstream_requests = upstream.received_requests().await.unwrap();
	assert_eq!(
		upstream_requests.len(),
		if delayed_actor_jwt || repeated { 2 } else { 1 }
	);
	assert_eq!(
		upstream_requests[0]
			.headers
			.get("authorization")
			.map(|v| v.to_str().unwrap()),
		placeholder.then_some(if actor_jwt {
			"Bearer minted-actor-jwt"
		} else {
			"Bearer injected-token"
		})
	);
	if actor_jwt {
		return;
	}
	let log = find_request_log(&path).await;
	assert_eq!(log["ate.actor.uid"].as_str(), Some("uid-1"), "{log:#?}");
	assert_eq!(log["ate.actor.name"].as_str(), Some("my-actor"), "{log:#?}");
	assert_eq!(log["ate.atespace"].as_str(), Some("demo"), "{log:#?}");
	assert_eq!(
		log["substrate.connect.authority"].as_str(),
		Some(format!("127.0.0.2:{port}").as_str()),
		"{log:#?}"
	);
	assert_eq!(log["http.status"].as_u64(), Some(200), "{log:#?}");
}

// Provide both TLS paths for the same name. The policy must choose between them,
// even when the HTTPS listener is a more specific static listener match.
async fn substrate_tls_gateway(
	policy: Result<EgressPolicy, tonic::Status>,
	state: ActorState,
	upstream: std::net::SocketAddr,
	root: Option<Vec<u8>>,
) -> (TestBind, agentgateway::test_helpers::MockInstance) {
	let api = ateapimock::AteApiMock::new(move || CredentialEgressHandler {
		policy: policy.clone(),
		state,
		mint_calls: None,
		mint_delay: Duration::ZERO,
		jwt_expiration_seconds: 600,
	})
	.spawn()
	.await;
	let gateway = substrate_tls_gateway_with_api(api.address, upstream, root, None).await;
	(gateway, api)
}

async fn substrate_tls_gateway_with_api(
	api: std::net::SocketAddr,
	upstream: std::net::SocketAddr,
	root: Option<Vec<u8>>,
	upstream_connections: Option<&str>,
) -> TestBind {
	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15013".parse().unwrap();
	outer.mode = BindMode::Internal;
	let tls_listener = strng::literal!("passthrough");
	let tcp_listener = strng::literal!("tcp");
	let inner = BindSnapshot::new(
		Bind {
			key: BIND_KEY,
			address: std::net::SocketAddr::from(([0, 0, 0, 0], upstream.port())),
			protocol: BindProtocol::auto,
			tunnel_protocol: Default::default(),
			mode: BindMode::Internal,
		},
		ListenerSet::from_list([
			Listener {
				key: LISTENER_KEY,
				name: Default::default(),
				hostname: "localhost".into(),
				protocol: ListenerProtocol::HTTPS(crate::tests::tls::test_server_tls_config()),
				..Default::default()
			},
			Listener {
				key: tls_listener.clone(),
				name: Default::default(),
				hostname: Default::default(),
				protocol: ListenerProtocol::TLS(None),
				..Default::default()
			},
			Listener {
				key: tcp_listener.clone(),
				name: Default::default(),
				hostname: Default::default(),
				protocol: ListenerProtocol::TCP,
				..Default::default()
			},
		]),
	);
	let backend_tls = root
		.map(|root| {
			let tls = agentgateway::http::backendtls::ResolvedBackendTLS {
				root: Some(root),
				hostname: Some("localhost".to_owned()),
				..Default::default()
			}
			.try_into()
			.unwrap();
			BackendTrafficPolicy::BackendTLS(tls)
		})
		.into_iter()
		.collect();
	let mut tls_route = basic_named_tcp_route("/passthrough".into());
	tls_route.key = "tls-route".into();
	let mut tcp_route = basic_named_tcp_route(strng::format!("/{upstream}"));
	tcp_route.key = "tcp-route".into();
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(BackendWithPolicies {
			backend: Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None),
			inline_policies: backend_tls,
		})
		.with_raw_backend(BackendWithPolicies {
			backend: Backend::Dynamic(ResourceName::new("passthrough".into(), "".into()), None),
			inline_policies: vec![],
		})
		.with_backend(upstream)
		.with_bind(outer)
		.with_bind(inner)
		.with_route(basic_named_route("/dynamic".into()))
		.with_tcp_route_for_listener(tls_listener, tls_route)
		.with_tcp_route_for_listener(tcp_listener, tcp_route)
		.with_connect_mode_on_port(agentgateway::types::frontend::ConnectMode::Tunnel, 15013);
	let mut resolution = json!({ "host": api.to_string() });
	if let Some(mode) = upstream_connections {
		resolution["upstreamConnections"] = mode.into();
	}
	gateway
		.attach_frontend_policy(json!({
				"substrateEgressActorResolution": resolution,
				"tls": { "handshakeTimeout": "1s" }
		}))
		.await;
	gateway
		.attach_route_policy(json!({ "substrateEgress": { "host": api.to_string() } }))
		.await;
	gateway
}

#[cfg(feature = "crypto-aws-lc")]
#[rstest::rstest]
#[case(true, true, false)]
#[case(false, true, false)]
#[case(false, true, true)]
#[case(true, false, false)]
#[tokio::test]
async fn substrate_egress_selects_tls_from_policy_and_rechecks_http(
	#[case] intercept: bool,
	#[case] allowed_request: bool,
	#[case] use_connect_ip: bool,
	#[values(ActorState::Running, ActorState::Resuming)] state: ActorState,
) {
	let (upstream, certs) = tls_mock().await;
	let port = upstream.address().port();
	let ports = Some(protos::ateapi::Ports {
		numbers: vec![i32::from(port)],
		..Default::default()
	});
	let https_name = if intercept { "localhost" } else { "*" };
	let tls_name = if intercept { "*" } else { "localhost" };
	let mut hostnames = vec![https_name.to_owned()];
	if allowed_request {
		hostnames.push("*".to_owned());
	}
	let policy = EgressPolicy {
		rules: vec![
			protos::ateapi::EgressRule {
				tls_passthrough: Some(protos::ateapi::TlsPassthroughRule {
					hostnames: vec![tls_name.to_owned()],
					ports: ports.clone(),
				}),
				..Default::default()
			},
			protos::ateapi::EgressRule {
				https: Some(protos::ateapi::HttpsRule {
					hostnames,
					ports,
					effects: None,
				}),
				..Default::default()
			},
		],
		..Default::default()
	};
	let (gateway, _api) = substrate_tls_gateway(
		Ok(policy),
		state,
		*upstream.address(),
		Some(certs.root_cert.pem().into_bytes()),
	)
	.await;
	let gateway = if use_connect_ip {
		gateway.with_raw_backend(BackendWithPolicies {
			backend: Backend::Dynamic(
				ResourceName::new("passthrough".into(), "".into()),
				Some(Arc::new(
					agentgateway::cel::Expression::new_strict(
						r#"destination.address + ":" + string(destination.port)"#,
					)
					.unwrap(),
				)),
			),
			inline_policies: vec![],
		})
	} else {
		gateway
	};
	let io = open_actor_egress_tunnel(&gateway, port).await;
	let mut roots = certs.root_cert.pem().into_bytes();
	roots.extend_from_slice(include_bytes!(
		"../../../../examples/mcp-tls/certs/ca-cert.pem"
	));
	let tls: agentgateway::http::backendtls::BackendTLS =
		agentgateway::http::backendtls::ResolvedBackendTLS {
			root: Some(roots),
			insecure_host: true,
			alpn: Some(vec!["http/1.1".to_owned()]),
			..Default::default()
		}
		.try_into()
		.unwrap();
	let mut io = tokio::time::timeout(
		Duration::from_secs(3),
		tokio_rustls::TlsConnector::from(tls.base_config().config).connect(
			rustls_pki_types::ServerName::try_from("localhost").unwrap(),
			io,
		),
	)
	.await
	.expect("TLS handshake timed out")
	.unwrap();
	let gateway_cert = pem::parse(include_bytes!(
		"../../../../examples/mcp-tls/certs/cert.pem"
	))
	.unwrap();
	assert_eq!(
		io.get_ref().1.peer_certificates().unwrap()[0].as_ref() == gateway_cert.contents(),
		intercept
	);
	// An HTTPS SNI match does not authorize a different request authority.
	// Passthrough forwards this request untouched; the gateway cannot inspect it.
	io.write_all(b"GET /tls-selection HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n")
		.await
		.unwrap();
	let mut response = Vec::new();
	tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut response))
		.await
		.unwrap()
		.unwrap();
	let expected = if allowed_request {
		"HTTP/1.1 200 OK"
	} else {
		"HTTP/1.1 403 Forbidden"
	};
	assert!(
		String::from_utf8_lossy(&response).starts_with(expected),
		"{}",
		String::from_utf8_lossy(&response)
	);
	assert_eq!(
		upstream.received_requests().await.unwrap().len(),
		usize::from(allowed_request)
	);
}

#[cfg(feature = "crypto-aws-lc")]
#[rstest::rstest]
#[case(false, "websocket")]
#[case(true, "websocket")]
#[case(false, "WebSocket")]
#[case(true, "WebSocket")]
#[case(false, "h2c\r\nUpgrade: websocket")]
#[case(true, "h2c\r\nUpgrade: websocket")]
#[case(false, "CONNECT")]
#[case(true, "CONNECT")]
#[case(false, "custom-protocol")]
#[case(true, "custom-protocol")]
#[tokio::test]
async fn substrate_egress_denies_http_upgrades_without_dialing(
	#[case] https: bool,
	#[case] upgrade: &str,
	#[values(false, true)] rejection_route: bool,
	#[values(false, true)] policy_allowed: bool,
) {
	let (upstream, root) = if https {
		let (upstream, certs) = tls_mock().await;
		(upstream, Some(certs.root_cert.pem().into_bytes()))
	} else {
		(simple_mock().await, None)
	};
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let port = address.port();
	let upstream_address = *upstream.address();
	let (connected, mut connections) = tokio::sync::mpsc::unbounded_channel();
	let forwarder = tokio::spawn(async move {
		loop {
			let (mut downstream, _) = listener.accept().await.unwrap();
			connected.send(()).unwrap();
			tokio::spawn(async move {
				let mut upstream = TcpStream::connect(upstream_address).await.unwrap();
				let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
			});
		}
	});
	let ports = Some(protos::ateapi::Ports {
		numbers: vec![i32::from(port)],
		..Default::default()
	});
	let rule = if https {
		protos::ateapi::EgressRule {
			https: Some(protos::ateapi::HttpsRule {
				hostnames: vec!["localhost".to_owned()],
				ports,
				effects: None,
			}),
			..Default::default()
		}
	} else {
		protos::ateapi::EgressRule {
			http: Some(protos::ateapi::HttpRule {
				hostnames: vec!["localhost".to_owned()],
				ports,
				effects: None,
			}),
			..Default::default()
		}
	};
	let (mut gateway, _api) = substrate_tls_gateway(
		Ok(EgressPolicy {
			rules: if policy_allowed { vec![rule] } else { vec![] },
			..Default::default()
		}),
		ActorState::Running,
		address,
		root,
	)
	.await;
	if rejection_route {
		gateway
			.attach_route(json!({
				"name": "reject-upgrades",
				"matches": if upgrade == "CONNECT" { json!([{ "method": "CONNECT" }]) } else { json!([{
					"path": { "exact": format!("/upgrade-{port}-true") },
					"headers": [{ "name": "upgrade", "value": { "regex": ".+" } }]
				}]) },
				"policies": {
					"directResponse": {
						"status": 403,
						"body": "WebSocket egress is not supported"
					}
				}
			}))
			.await;
	}
	let gateway = if https {
		gateway
	} else {
		let mut inner = simple_bind();
		inner.address = std::net::SocketAddr::from(([0, 0, 0, 0], port));
		inner.mode = BindMode::Internal;
		inner.protocol = BindProtocol::auto;
		gateway.with_bind(inner)
	};

	async fn exchange(mut io: impl AsyncRead + AsyncWrite + Unpin, request: &str) -> Vec<u8> {
		io.write_all(request.as_bytes()).await.unwrap();
		let mut response = Vec::new();
		while !response.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
			let mut buf = [0; 256];
			let n = io.read(&mut buf).await.unwrap();
			assert_ne!(n, 0, "connection closed before HTTP response headers");
			response.extend_from_slice(&buf[..n]);
		}
		let headers_end = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
		let content_length = std::str::from_utf8(&response[..headers_end])
			.unwrap()
			.lines()
			.filter_map(|line| line.split_once(':'))
			.find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
			.map(|(_, value)| value.trim().parse::<usize>().unwrap())
			.expect("response has a content length");
		let received = response.len();
		response.resize(headers_end + content_length, 0);
		io.read_exact(&mut response[received..]).await.unwrap();
		response
	}

	for upgrading in [false, true] {
		let path = format!("/upgrade-{port}-{upgrading}");
		let connect_host = format!("connect-{port}.example");
		let io = open_actor_egress_tunnel(&gateway, port).await;
		let headers = if upgrading {
			format!(
				"Connection: close, UpGrAdE\r\nUpGrAdE: {upgrade}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
			)
		} else {
			"Connection: close\r\n".to_owned()
		};
		let request = if upgrading && upgrade == "CONNECT" {
			format!(
				"CONNECT {connect_host}:443 HTTP/1.1\r\nHost: {connect_host}:443\r\nConnection: close\r\n\r\n"
			)
		} else {
			format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n")
		};
		let response = tokio::time::timeout(Duration::from_secs(3), async {
			if https {
				let tls: agentgateway::http::backendtls::BackendTLS =
					agentgateway::http::backendtls::ResolvedBackendTLS {
						root: Some(include_bytes!("../../../../examples/mcp-tls/certs/ca-cert.pem").to_vec()),
						alpn: Some(vec!["http/1.1".to_owned()]),
						..Default::default()
					}
					.try_into()
					.unwrap();
				let handshake = tokio_rustls::TlsConnector::from(tls.base_config().config)
					.connect(
						rustls_pki_types::ServerName::try_from("localhost").unwrap(),
						io,
					)
					.await;
				if !policy_allowed {
					assert!(handshake.is_err(), "denied TLS handshake completed");
					return Vec::new();
				}
				let io = handshake.unwrap();
				exchange(io, &request).await
			} else {
				exchange(io, &request).await
			}
		})
		.await
		.expect("timed out waiting for HTTP response");
		if https && !policy_allowed {
			assert!(response.is_empty());
			assert!(
				tokio::time::timeout(Duration::from_millis(50), connections.recv())
					.await
					.is_err(),
				"denied TLS opened an upstream connection"
			);
			assert!(upstream.received_requests().await.unwrap().is_empty());
			continue;
		}
		let expected = if upgrading || !policy_allowed {
			"HTTP/1.1 403 Forbidden\r\n"
		} else {
			"HTTP/1.1 200 OK\r\n"
		};
		assert!(
			response.starts_with(expected.as_bytes()),
			"{}",
			String::from_utf8_lossy(&response)
		);
		if upgrading || !policy_allowed {
			let body = response
				.split_at(response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4)
				.1;
			let expected = if !upgrading {
				"actor egress policy denied"
			} else if upgrade == "CONNECT" {
				"CONNECT egress is not supported"
			} else if upgrade.to_ascii_lowercase().contains("websocket") {
				"WebSocket egress is not supported"
			} else {
				"HTTP upgrades, including CONNECT, are denied for actor egress"
			};
			assert_eq!(body, expected.as_bytes());
		}
		if upgrading || !policy_allowed {
			assert!(
				tokio::time::timeout(Duration::from_millis(50), connections.recv())
					.await
					.is_err(),
				"denied upgrade opened an upstream connection"
			);
		} else {
			connections.recv().await.unwrap();
		}
		assert_eq!(
			upstream.received_requests().await.unwrap().len(),
			usize::from(policy_allowed)
		);
	}
	forwarder.abort();
}

#[cfg(feature = "crypto-aws-lc")]
#[rstest::rstest]
#[case("unmatched-sni")]
#[case("unmatched-port")]
#[case("passthrough-port")]
#[case("empty-policy")]
#[case("http-rule")]
#[case("before-network-authorization")]
#[case("before-network-ext-authz")]
#[case("before-gateway-ext-authz")]
#[case("before-route-ext-authz")]
#[case("before-cors")]
#[case("before-route-match")]
#[tokio::test]
async fn substrate_egress_tls_denial_closes_at_client_hello_without_dialing(
	#[case] kind: &str,
	#[values(false, true)] http2: bool,
) {
	let (upstream, certs) = tls_mock().await;
	let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
	let address = listener.local_addr().unwrap();
	let port = address.port();
	let upstream_address = *upstream.address();
	let (connected, mut connections) = tokio::sync::mpsc::unbounded_channel();
	let forwarding_listener = listener.clone();
	let mut forwarder = tokio::spawn(async move {
		loop {
			let (mut downstream, _) = forwarding_listener.accept().await.unwrap();
			connected.send(()).unwrap();
			tokio::spawn(async move {
				let mut upstream = TcpStream::connect(upstream_address).await.unwrap();
				let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
			});
		}
	});

	let authz = simple_mock().await;

	// The same destination must work when allowed, then fail the TLS handshake
	// without even opening a TCP connection when its policy disallows it.
	for allowed in [true, false] {
		let hostname = if !allowed && kind.starts_with("unmatched-sni") {
			"allowed.example"
		} else {
			"localhost"
		};
		let rule_port = if !allowed && matches!(kind, "unmatched-port" | "passthrough-port") {
			if port == 443 { 444 } else { 443 }
		} else {
			port
		};
		let ports = Some(protos::ateapi::Ports {
			numbers: vec![i32::from(rule_port)],
			..Default::default()
		});
		let rule = if !allowed && kind == "passthrough-port" {
			protos::ateapi::EgressRule {
				tls_passthrough: Some(protos::ateapi::TlsPassthroughRule {
					hostnames: vec![hostname.to_owned()],
					ports,
				}),
				..Default::default()
			}
		} else if !allowed && kind == "http-rule" {
			protos::ateapi::EgressRule {
				http: Some(protos::ateapi::HttpRule {
					hostnames: vec![hostname.to_owned()],
					ports,
					effects: None,
				}),
				..Default::default()
			}
		} else {
			protos::ateapi::EgressRule {
				https: Some(protos::ateapi::HttpsRule {
					hostnames: vec![hostname.to_owned()],
					ports,
					effects: None,
				}),
				..Default::default()
			}
		};
		let policy = EgressPolicy {
			rules: if !allowed && (kind == "empty-policy" || kind.starts_with("before-")) {
				vec![]
			} else {
				vec![rule]
			},
			..Default::default()
		};
		let (mut gateway, _api) = substrate_tls_gateway(
			Ok(policy),
			ActorState::Running,
			address,
			Some(certs.root_cert.pem().into_bytes()),
		)
		.await;
		let authz_policy = json!({
			"host": authz.address().to_string(),
			"protocol": { "http": {} }
		});
		match kind {
			"before-network-authorization" => {
				gateway
					.attach_frontend_policy_with_port(
						json!({
							"networkAuthorization": { "rules": [if allowed { "true" } else { "false" }] }
						}),
						Some(port),
					)
					.await;
			},
			"before-network-ext-authz" => {
				gateway
					.attach_frontend_policy_with_port(json!({ "networkExtAuthz": authz_policy }), Some(port))
					.await;
			},
			"before-gateway-ext-authz" => {
				gateway
					.attach_gateway_policy(json!({ "extAuthz": authz_policy }))
					.await;
			},
			"before-route-ext-authz" => {
				gateway
					.attach_route_policy(json!({ "extAuthz": authz_policy }))
					.await;
			},
			"before-cors" => {
				gateway
					.attach_route_policy(json!({
						"cors": { "allowOrigins": ["http://example.com"], "allowMethods": ["GET"] }
					}))
					.await;
			},
			"before-route-match" if !allowed => {
				gateway.pi.stores.binds.write().remove_route("route".into());
			},
			_ => {},
		}
		let io = open_actor_egress_tunnel(&gateway, port).await;
		let tls: agentgateway::http::backendtls::BackendTLS =
			agentgateway::http::backendtls::ResolvedBackendTLS {
				root: Some(include_bytes!("../../../../examples/mcp-tls/certs/ca-cert.pem").to_vec()),
				alpn: Some(vec![if http2 { "h2" } else { "http/1.1" }.to_owned()]),
				..Default::default()
			}
			.try_into()
			.unwrap();
		let io = tokio::time::timeout(
			Duration::from_secs(3),
			tokio_rustls::TlsConnector::from(tls.base_config().config).connect(
				rustls_pki_types::ServerName::try_from("localhost").unwrap(),
				io,
			),
		)
		.await
		.expect("TLS handshake timed out");
		if !allowed {
			let err = io.expect_err("gateway must reject denied TLS at ClientHello");
			assert!(
				matches!(
					err.kind(),
					std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
				),
				"expected connection closure at ClientHello, got {err}"
			);
			assert!(
				connections.try_recv().is_err(),
				"denied TLS opened an upstream connection"
			);
			assert!(
				listener.accept().now_or_never().is_none(),
				"denied TLS queued an upstream connection"
			);
			assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
			assert_eq!(
				authz.received_requests().await.unwrap().len(),
				usize::from(kind.ends_with("ext-authz")),
				"denied TLS must not call auth services"
			);
			continue;
		}
		let io = io.expect("allowed TLS handshake failed");
		let authority = "localhost";
		let request = ::http::Request::builder()
			.method(Method::GET)
			.uri(format!("https://{authority}/https-denial"))
			.header(header::HOST, authority)
			.header(header::ORIGIN, "http://example.com")
			.header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
			.body(Body::empty())
			.unwrap();
		let (response, connection) = tokio::time::timeout(Duration::from_secs(3), async {
			if http2 {
				let (mut sender, connection) =
					hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
						.handshake(TokioIo::new(io))
						.await
						.unwrap();
				let connection = tokio::spawn(connection);
				(sender.send_request(request).await.unwrap(), connection)
			} else {
				let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
					.await
					.unwrap();
				let connection = tokio::spawn(connection);
				(sender.send_request(request).await.unwrap(), connection)
			}
		})
		.await
		.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		if kind == "before-cors" {
			assert_eq!(
				response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
				Some(&::http::HeaderValue::from_static("http://example.com"))
			);
		}
		tokio::time::timeout(Duration::from_secs(3), response.into_body().collect())
			.await
			.unwrap()
			.unwrap();
		connections.recv().await.unwrap();
		assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
		assert_eq!(
			authz.received_requests().await.unwrap().len(),
			usize::from(kind.ends_with("ext-authz")),
			"denied HTTPS must not call auth services"
		);
		connection.abort();
		// Keep the listener open, but stop accepting before testing denial so
		// an upstream dial cannot hide behind a delayed accept notification.
		forwarder.abort();
		assert!((&mut forwarder).await.unwrap_err().is_cancelled());
	}
}

#[cfg(feature = "crypto-aws-lc")]
#[rstest::rstest]
#[case("opaque")]
#[case("server-first")]
#[case("missing-sni")]
#[case("missing-https-listener")]
#[case("api-unavailable")]
#[case("missing-policy")]
#[case("static-backend")]
#[tokio::test]
async fn substrate_egress_rejects_unrecognized_or_unauthorized_connections(
	#[case] kind: &str,
	#[values(ActorState::Running, ActorState::Resuming)] state: ActorState,
) {
	let (upstream, _certs) = tls_mock().await;
	let raw_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = if matches!(kind, "opaque" | "server-first" | "static-backend") {
		raw_upstream.local_addr().unwrap()
	} else {
		*upstream.address()
	};
	let port = address.port();
	let ports = Some(protos::ateapi::Ports {
		numbers: vec![i32::from(port)],
		..Default::default()
	});
	let rule = protos::ateapi::EgressRule {
		tls_passthrough: Some(protos::ateapi::TlsPassthroughRule {
			hostnames: vec!["localhost".to_owned()],
			ports,
		}),
		..Default::default()
	};
	let policy = if kind == "api-unavailable" {
		Err(tonic::Status::unavailable("control API unavailable"))
	} else if kind == "missing-policy" {
		Err(tonic::Status::not_found("actor has no egress policy"))
	} else {
		Ok(EgressPolicy {
			rules: vec![rule],
			..Default::default()
		})
	};
	let (gateway, _api) = substrate_tls_gateway(policy, state, address, None).await;
	let gateway = if kind == "static-backend" {
		gateway.with_raw_backend(BackendWithPolicies {
			backend: Backend::Opaque(
				ResourceName::new("passthrough".into(), "".into()),
				Target::Address(address),
			),
			inline_policies: vec![],
		})
	} else {
		gateway
	};

	let mut io = open_actor_egress_tunnel(&gateway, port).await;
	if kind == "opaque" || kind == "server-first" {
		if kind == "opaque" {
			io.write_all(b"opaque tcp").await.unwrap();
		}
		let mut buf = [0; 1];
		assert_eq!(
			tokio::time::timeout(Duration::from_secs(3), io.read(&mut buf))
				.await
				.unwrap()
				.unwrap(),
			0
		);
	} else {
		let tls: agentgateway::http::backendtls::BackendTLS =
			agentgateway::http::backendtls::ResolvedBackendTLS {
				insecure: true,
				..Default::default()
			}
			.try_into()
			.unwrap();
		let name = if kind == "missing-sni" {
			"127.0.0.1"
		} else if kind == "missing-https-listener" {
			"denied.example"
		} else {
			"localhost"
		};
		let result = tokio::time::timeout(
			Duration::from_secs(3),
			tokio_rustls::TlsConnector::from(tls.base_config().config).connect(
				rustls_pki_types::ServerName::try_from(name.to_owned()).unwrap(),
				io,
			),
		)
		.await
		.unwrap();
		assert!(result.is_err(), "unauthorized TLS handshake succeeded");
	}
	assert!(upstream.received_requests().await.unwrap().is_empty());
	assert!(
		tokio::time::timeout(Duration::from_millis(50), raw_upstream.accept())
			.await
			.is_err(),
		"denied traffic dialed the raw TCP backend"
	);
}

/// Records the `traceparent` each Substrate gRPC call receives, tagged by method.
#[derive(Clone)]
struct Traceparents<H> {
	inner: H,
	pending: Option<String>,
	seen: Arc<StdMutex<Vec<(&'static str, String)>>>,
}

impl<H> Traceparents<H> {
	fn new(inner: H, seen: Arc<StdMutex<Vec<(&'static str, String)>>>) -> Self {
		Self {
			inner,
			pending: None,
			seen,
		}
	}

	fn stash(&mut self, metadata: &tonic::metadata::MetadataMap) {
		self.pending = metadata
			.get("traceparent")
			.and_then(|v| v.to_str().ok())
			.map(str::to_owned);
	}

	fn record(&mut self, method: &'static str) {
		if let Some(tp) = self.pending.take() {
			self.seen.lock().unwrap().push((method, tp));
		}
	}
}

#[async_trait::async_trait]
impl ateapimock::Handler for Traceparents<CredentialEgressHandler> {
	fn metadata(&mut self, metadata: &tonic::metadata::MetadataMap) {
		self.stash(metadata);
	}

	async fn get_actor(
		&mut self,
		request: &protos::ateapi::GetActorRequest,
	) -> Result<Actor, tonic::Status> {
		self.record("GetActor");
		self.inner.get_actor(request).await
	}

	async fn get_actor_egress_policy(
		&mut self,
		request: &protos::ateapi::GetActorEgressPolicyRequest,
	) -> Result<EgressPolicy, tonic::Status> {
		self.record("GetActorEgressPolicy");
		self.inner.get_actor_egress_policy(request).await
	}
}

#[async_trait::async_trait]
impl credprovidermock::Handler for Traceparents<CredentialHandler> {
	fn metadata(&mut self, metadata: &tonic::metadata::MetadataMap) {
		self.stash(metadata);
	}

	async fn fetch_secret(
		&mut self,
		request: &protos::credprovider::FetchSecretRequest,
	) -> Result<protos::credprovider::FetchSecretResponse, tonic::Status> {
		self.record("FetchSecret");
		self.inner.fetch_secret(request).await
	}
}

struct CollectTraces(Arc<StdMutex<Vec<opentelemetry_proto::tonic::trace::v1::Span>>>);

#[async_trait::async_trait]
impl oteltracemock::Handler for CollectTraces {
	async fn export(
		&mut self,
		request: &opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest,
	) -> Result<
		opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse,
		tonic::Status,
	> {
		self.0.lock().unwrap().extend(
			request
				.resource_spans
				.iter()
				.flat_map(|resource| &resource.scope_spans)
				.flat_map(|scope| &scope.spans)
				.cloned(),
		);
		oteltracemock::ok_response()
	}
}

fn hex_id(id: &[u8]) -> String {
	id.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn substrate_egress_propagates_trace_context_to_policy_and_credential_calls() {
	unsafe {
		// Drop export time to make tests fast
		std::env::set_var("OTEL_BSP_SCHEDULE_DELAY", "20");
	}
	let spans = Arc::new(StdMutex::new(Vec::new()));
	let otel = oteltracemock::OtelTraceMock::new({
		let spans = spans.clone();
		move || CollectTraces(spans.clone())
	})
	.spawn()
	.await;
	let upstream = simple_mock().await;
	let port = upstream.address().port();
	let policy = EgressPolicy {
		rules: vec![protos::ateapi::EgressRule {
			http: Some(protos::ateapi::HttpRule {
				hostnames: vec!["localhost".to_owned()],
				ports: Some(protos::ateapi::Ports {
					numbers: vec![i32::from(port)],
					..Default::default()
				}),
				effects: Some(protos::ateapi::HttpRuleEffects {
					replace_headers: vec![protos::ateapi::CredentialHeader {
						header: "authorization".to_owned(),
						prefix: "Bearer ".to_owned(),
						credential_uri: "ate-secret://kubernetes.io/default/upstream-token".to_owned(),
						actor_jwt: None,
					}],
				}),
			}),
			..Default::default()
		}],
		..Default::default()
	};
	let seen = Arc::new(StdMutex::new(Vec::new()));
	let api = ateapimock::AteApiMock::new({
		let seen = seen.clone();
		move || {
			Traceparents::new(
				CredentialEgressHandler {
					policy: Ok(policy.clone()),
					state: ActorState::Running,
					mint_calls: None,
					mint_delay: Duration::ZERO,
					jwt_expiration_seconds: 600,
				},
				seen.clone(),
			)
		}
	})
	.spawn()
	.await;
	let credential_provider = credprovidermock::CredentialProviderMock::new({
		let seen = seen.clone();
		move || {
			Traceparents::new(
				CredentialHandler {
					calls: Default::default(),
				},
				seen.clone(),
			)
		}
	})
	.spawn()
	.await;

	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15014".parse().unwrap();
	let mut inner = simple_bind();
	inner.address = std::net::SocketAddr::from(([0, 0, 0, 0], port));
	inner.mode = BindMode::Internal;
	let mut gateway = crate::tests::dfp::setup_dfp_bind()
		.with_bind(outer)
		.with_bind(inner)
		.with_connect_mode_on_port(agentgateway::types::frontend::ConnectMode::Tunnel, 15014);
	gateway
		.attach_frontend_policy(json!({
			"tracing": { "host": otel.address.to_string() },
			"substrateEgressActorResolution": {
				"host": api.address.to_string(),
			}
		}))
		.await;
	gateway
		.attach_route_policy(json!({
			"substrateEgress": {
				"host": api.address.to_string(),
				"credentialProviders": [{
					"uriAuthority": "kubernetes.io",
					"target": { "host": credential_provider.address.to_string() }
				}]
			}
		}))
		.await;

	let mut io = gateway.serve_tunnel_with_tls_info(
		strng::literal!("outer"),
		Some(TLSConnectionInfo {
			src_identity: Some(TlsInfo {
				certificate: Some(
					actor_certificate("spiffe://substrate-actor.local/worker-for-actor/demo/my-actor").into(),
				),
				..Default::default()
			}),
			..Default::default()
		}),
	);
	io.write_all(
		format!("CONNECT 127.0.0.2:{port} HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n").as_bytes(),
	)
	.await
	.unwrap();
	let mut connect_response = [0; 128];
	let response_len = io.read(&mut connect_response).await.unwrap();
	assert!(
		String::from_utf8_lossy(&connect_response[..response_len]).starts_with("HTTP/1.1 200 OK\r\n")
	);

	let client_tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
	io.write_all(
		format!(
			"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer actor-supplied\r\ntraceparent: {client_tp}\r\nConnection: close\r\n\r\n"
		)
		.as_bytes(),
	)
	.await
	.unwrap();
	let mut response = Vec::new();
	tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut response))
		.await
		.expect("timed out waiting for tunneled response")
		.unwrap();
	assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK\r\n"));

	// CONNECT-time GetActor precedes any request trace, so only the two
	// request-path calls carry one. Each continues the client's sampled trace
	// under a gateway span.
	let seen = seen.lock().unwrap().clone();
	let methods: Vec<_> = seen.iter().map(|(method, _)| *method).collect();
	assert_eq!(methods, ["GetActorEgressPolicy", "FetchSecret"], "{seen:?}");
	for (method, tp) in &seen {
		assert_eq!(tp[..36], client_tp[..36], "{method}: {tp}");
		assert_ne!(tp[36..52], client_tp[36..52], "{method}: {tp}");
		assert!(tp.ends_with("-01"), "{method}: {tp}");
	}

	// The traceparent each server received names that call's exported client
	// span, which is a child of the gateway's request span.
	tokio::time::timeout(Duration::from_secs(2), async {
		while spans.lock().unwrap().len() < 3 {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("timed out waiting for exported spans");
	let spans = spans.lock().unwrap();
	let request = spans
		.iter()
		.find(|span| hex_id(&span.parent_span_id) == client_tp[36..52])
		.expect("request span should be exported");
	for (method, tp) in &seen {
		let path = match *method {
			"GetActorEgressPolicy" => "/substrate.ateapi.v1.Control/GetActorEgressPolicy",
			"FetchSecret" => "/substrate.credprovider.v1.CredentialProvider/FetchSecret",
			other => panic!("unexpected method {other}"),
		};
		let span = spans
			.iter()
			.find(|span| {
				span.name == "Substrate"
					&& span.attributes.iter().any(|attribute| {
						attribute.key == "http.path"
							&& matches!(
								attribute.value.as_ref().and_then(|value| value.value.as_ref()),
								Some(
									opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(
										value
									)
								) if value == path
							)
					})
			})
			.unwrap_or_else(|| panic!("{path} span should be exported"));
		assert_eq!(hex_id(&span.span_id), tp[36..52], "{path}");
		assert_eq!(span.parent_span_id, request.span_id, "{path}");
	}
}

#[tokio::test]
async fn substrate_egress_rejects_invalid_or_unavailable_actors_at_connect_time() {
	let running = Some(ActorState::Running as i32);
	assert_eq!(
		substrate_egress_connect_status(
			EgressHandler {
				uid: "uid-1",
				state: running,
				error: Some(tonic::Code::NotFound),
				..Default::default()
			},
			"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
			b"",
		)
		.await,
		StatusCode::FORBIDDEN,
	);
	for uri in [
		"spiffe://substrate-actor.local/actor/demo/my-actor",
		"spiffe://substrate-actor.local/ateom-for-actor/demo/my-actor",
	] {
		assert_eq!(
			substrate_egress_connect_status(
				EgressHandler {
					uid: "uid-1",
					state: running,
					error: None,
					..Default::default()
				},
				uri,
				b"",
			)
			.await,
			StatusCode::FORBIDDEN,
			"{uri}",
		);
	}
	assert_eq!(
		substrate_egress_connect_status(
			EgressHandler {
				uid: "uid-1",
				state: running,
				error: Some(tonic::Code::Unavailable),
				..Default::default()
			},
			"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
			b"",
		)
		.await,
		StatusCode::SERVICE_UNAVAILABLE,
	);
}

#[tokio::test]
async fn substrate_egress_binds_connect_to_current_actor_and_activation() {
	let uri = "spiffe://substrate-actor.local/worker-for-actor/demo/my-actor";
	let cases = [
		(
			"quarantined running",
			"uid-1",
			"run-1",
			true,
			false,
			Some("uid-1"),
			Some("run-1"),
			StatusCode::FORBIDDEN,
		),
		(
			"quarantined resuming",
			"uid-1",
			"run-1",
			true,
			false,
			Some("uid-1"),
			Some("run-1"),
			StatusCode::FORBIDDEN,
		),
		(
			"replacement actor",
			"uid-2",
			"run-1",
			false,
			false,
			Some("uid-1"),
			Some("run-1"),
			StatusCode::FORBIDDEN,
		),
		(
			"earlier activation",
			"uid-1",
			"run-2",
			false,
			false,
			Some("uid-1"),
			Some("run-1"),
			StatusCode::FORBIDDEN,
		),
		(
			"missing extension",
			"uid-1",
			"run-1",
			false,
			false,
			None,
			None,
			StatusCode::FORBIDDEN,
		),
		(
			"current activation",
			"uid-1",
			"run-1",
			false,
			false,
			Some("uid-1"),
			Some("run-1"),
			StatusCode::OK,
		),
		(
			"held actor",
			"uid-1",
			"run-1",
			false,
			true,
			Some("uid-1"),
			Some("run-1"),
			StatusCode::OK,
		),
		(
			"base certificate",
			"uid-1",
			"run-1",
			false,
			false,
			Some("uid-1"),
			None,
			StatusCode::OK,
		),
	];
	for (
		name,
		uid,
		activation_id,
		quarantine,
		held,
		certificate_uid,
		certificate_activation,
		expected,
	) in cases
	{
		let api = ateapimock::AteApiMock::new(move || EgressHandler {
			uid,
			state: Some(if name == "quarantined resuming" {
				ActorState::Resuming
			} else {
				ActorState::Running
			} as i32),
			activation_id,
			quarantine,
			held,
			..Default::default()
		})
		.spawn()
		.await;
		let certificate = actor_certificate_with_identity(uri, certificate_uid, certificate_activation);
		let (status, response) =
			substrate_egress_connect_response_at_certificate(api.address, certificate, b"").await;
		assert_eq!(status, expected, "{name}");
		if expected == StatusCode::OK {
			for reason in [
				"actor-quarantined",
				"actor-uid-mismatch",
				"activation-mismatch",
			] {
				assert!(!response.contains(reason), "{name} leaked {reason}");
			}
		}
	}
}

#[rstest::rstest]
#[case::quarantine(true, "uid-1", "run-1", "actor-quarantined")]
#[case::replacement(false, "uid-2", "run-1", "actor-uid-mismatch")]
#[case::earlier_activation(false, "uid-1", "run-2", "activation-mismatch")]
#[case::quarantined_replacement(true, "uid-2", "run-2", "actor-uid-mismatch")]
#[case::quarantined_earlier_activation(true, "uid-1", "run-2", "activation-mismatch")]
#[tokio::test]
async fn substrate_egress_connect_refusal_has_a_stable_reason(
	#[case] quarantine: bool,
	#[case] uid: &'static str,
	#[case] activation: &'static str,
	#[case] reason: &str,
) {
	let uri = "spiffe://substrate-actor.local/worker-for-actor/demo/my-actor";
	let api = ateapimock::AteApiMock::new(move || EgressHandler {
		uid,
		state: Some(ActorState::Running as i32),
		activation_id: activation,
		quarantine,
		..Default::default()
	})
	.spawn()
	.await;
	let certificate = actor_certificate_with_identity(uri, Some("uid-1"), Some("run-1"));
	let (status, response) =
		substrate_egress_connect_response_at_certificate(api.address, certificate, b"").await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let body = response.split_once("\r\n\r\n").unwrap().1;
	assert_eq!(body, reason);
}

#[tokio::test]
async fn substrate_egress_connect_without_authority_is_bad_request() {
	let api = ateapimock::AteApiMock::new(|| EgressHandler {
		uid: "uid-1",
		state: Some(ActorState::Running as i32),
		..Default::default()
	})
	.spawn()
	.await;
	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15012".parse().unwrap();
	let mut inner = simple_bind();
	inner.address = "0.0.0.0:18080".parse().unwrap();
	inner.mode = BindMode::Internal;
	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_bind(outer)
		.with_bind(inner)
		.with_connect_mode_on_port(agentgateway::types::frontend::ConnectMode::Tunnel, 15012);
	gateway
		.attach_frontend_policy(json!({
			"substrateEgressActorResolution": { "host": api.address.to_string() }
		}))
		.await;
	let certificate =
		actor_certificate("spiffe://substrate-actor.local/worker-for-actor/demo/my-actor");
	let tls = || TLSConnectionInfo {
		src_identity: Some(TlsInfo {
			certificate: Some(certificate.clone().into()),
			..Default::default()
		}),
		..Default::default()
	};

	let mut http1 = gateway.serve_tunnel_with_tls_info(strng::literal!("outer"), Some(tls()));
	http1
		.write_all(b"CONNECT /x HTTP/1.1\r\nHost: allowed.example:18080\r\n\r\n")
		.await
		.unwrap();
	let mut response = [0; 256];
	let n = tokio::time::timeout(Duration::from_secs(5), http1.read(&mut response))
		.await
		.unwrap()
		.unwrap();
	assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 400 Bad Request\r\n"));

	let http2 = gateway.serve_tunnel_with_tls_info(strng::literal!("outer"), Some(tls()));
	let (mut client, connection) = h2::client::handshake(http2).await.unwrap();
	let connection = tokio::spawn(connection);
	let request = ::http::Request::builder()
		.method(Method::CONNECT)
		.uri("/x")
		.version(Version::HTTP_11)
		.body(())
		.unwrap();
	match client.send_request(request, true) {
		Ok((response, _)) => match response.await {
			Ok(response) => assert_eq!(response.status(), StatusCode::BAD_REQUEST),
			Err(error) => assert!(
				error.is_remote() && error.reason() == Some(h2::Reason::PROTOCOL_ERROR),
				"unexpected HTTP/2 error: {error}"
			),
		},
		Err(error) => assert!(
			error.is_library() && error.reason() == Some(h2::Reason::PROTOCOL_ERROR),
			"unexpected HTTP/2 error: {error}"
		),
	}
	connection.abort();
}

#[tokio::test]
async fn substrate_egress_reports_an_unreachable_actor_service_as_unavailable() {
	let closed = UNREACHABLE_ADDR.parse().unwrap();
	assert_eq!(
		substrate_egress_connect_status_at(
			closed,
			"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
			b"",
		)
		.await,
		StatusCode::SERVICE_UNAVAILABLE,
	);
}

#[rstest::rstest]
#[case::unavailable(tonic::Code::Unavailable, StatusCode::SERVICE_UNAVAILABLE)]
#[case::deadline(tonic::Code::DeadlineExceeded, StatusCode::SERVICE_UNAVAILABLE)]
#[case::not_found(tonic::Code::NotFound, StatusCode::FORBIDDEN)]
#[case::unauthenticated(tonic::Code::Unauthenticated, StatusCode::FORBIDDEN)]
#[case::permission_denied(tonic::Code::PermissionDenied, StatusCode::FORBIDDEN)]
#[case::internal(tonic::Code::Internal, StatusCode::FORBIDDEN)]
#[tokio::test]
async fn substrate_egress_control_api_failures_refuse_before_dialing(
	#[case] error: tonic::Code,
	#[case] expected: StatusCode,
) {
	let api = ateapimock::AteApiMock::new(move || EgressHandler {
		uid: "uid-1",
		state: Some(ActorState::Running as i32),
		activation_id: "run-1",
		error: Some(error),
		..Default::default()
	})
	.spawn()
	.await;
	let certificate = actor_certificate_with_identity(
		"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
		Some("uid-1"),
		Some("run-1"),
	);
	let (status, response) = substrate_egress_connect_response_at_certificate(
		api.address,
		certificate,
		b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
	)
	.await;
	assert_eq!(status, expected);
	assert!(!response.contains("actor-uid-mismatch"));
	assert!(!response.contains("activation-mismatch"));
	assert!(!response.contains("actor-quarantined"));
}

#[rstest::rstest]
#[case::unspecified(Some(ActorState::Unspecified as i32))]
#[case::suspending(Some(ActorState::Suspending as i32))]
#[case::suspended(Some(ActorState::Suspended as i32))]
#[case::crashed(Some(ActorState::Crashed as i32))]
#[case::deleting(Some(ActorState::Deleting as i32))]
#[case::reverting(Some(ActorState::Reverting as i32))]
#[case::unknown(Some(999))]
#[case::missing_status(None)]
#[tokio::test]
async fn substrate_egress_rejects_actor_states_without_worker_placement(
	#[case] state: Option<i32>,
) {
	assert_eq!(
		substrate_egress_connect_status(
			EgressHandler {
				uid: "uid-1",
				state,
				error: None,
				..Default::default()
			},
			"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
			b"",
		)
		.await,
		StatusCode::FORBIDDEN,
	);
}

#[rstest::rstest]
#[case::running(ActorState::Running)]
#[case::resuming(ActorState::Resuming)]
#[tokio::test]
async fn substrate_egress_accepts_valid_actor_connect_before_protocol_detection(
	#[case] state: ActorState,
) {
	for payload in [
		b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n".as_slice(),
		b"\x16\x03\x03\x00\x01\x00".as_slice(),
		b"opaque tcp".as_slice(),
	] {
		assert_eq!(
			substrate_egress_connect_status(
				EgressHandler {
					uid: "uid-1",
					state: Some(state as i32),
					error: None,
					..Default::default()
				},
				"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
				payload,
			)
			.await,
			StatusCode::OK,
		);
	}
}

#[derive(Clone)]
struct RevocationHandler {
	policy: Option<EgressPolicy>,
	view: Arc<Mutex<EgressHandler>>,
	calls: Arc<AtomicUsize>,
	delay_ms: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl ateapimock::Handler for RevocationHandler {
	async fn get_actor_egress_policy(
		&mut self,
		_: &protos::ateapi::GetActorEgressPolicyRequest,
	) -> Result<EgressPolicy, tonic::Status> {
		Ok(self.policy.clone().unwrap_or_default())
	}
	async fn get_actor(
		&mut self,
		request: &protos::ateapi::GetActorRequest,
	) -> Result<Actor, tonic::Status> {
		let mut view = self.view.lock().unwrap().clone();
		self.calls.fetch_add(1, Ordering::Relaxed);
		let delay = self.delay_ms.load(Ordering::Relaxed);
		tokio::time::sleep(Duration::from_millis(delay as u64)).await;
		view.get_actor(request).await
	}
}

#[rstest::rstest]
#[case("quarantine")]
#[case("uid")]
#[case("activation")]
#[case("outage")]
#[case("slow")]
#[tokio::test]
async fn substrate_revocation_closes_running_actor_tunnels(
	#[case] trigger: &str,
	#[values(0, 1, 2, 3, 4)] trial: usize,
) {
	let view = Arc::new(Mutex::new(EgressHandler {
		uid: "uid-1",
		activation_id: "run-1",
		state: Some(ActorState::Running as i32),
		..Default::default()
	}));
	let calls = Arc::new(AtomicUsize::new(0));
	let delay_ms = Arc::new(AtomicUsize::new(0));
	let upstream = simple_mock().await;
	let address = *upstream.address();
	let port = address.port();
	let handler = RevocationHandler {
		policy: Some(EgressPolicy {
			rules: vec![protos::ateapi::EgressRule {
				http: Some(protos::ateapi::HttpRule {
					hostnames: vec!["localhost".to_owned()],
					ports: Some(protos::ateapi::Ports {
						numbers: vec![i32::from(port)],
						..Default::default()
					}),
					effects: None,
				}),
				..Default::default()
			}],
			..Default::default()
		}),
		view: view.clone(),
		calls: calls.clone(),
		delay_ms: delay_ms.clone(),
	};
	let api = ateapimock::AteApiMock::new(move || handler.clone())
		.spawn()
		.await;

	let gateway = q6_http_gateway(api.address, port).await;
	let certificate = actor_certificate_with_identity(
		"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
		Some("uid-1"),
		Some("run-1"),
	);
	let mut tunnels = Vec::new();
	for _ in 0..3 {
		let mut io = open_q6_tcp_tunnel(&gateway, &certificate, port).await;
		q6_http_request(&mut io, "before", port).await;
		tunnels.push(io);
	}
	assert_eq!(calls.load(Ordering::Relaxed), 3);
	view.lock().unwrap().held = true;
	let lookup_sample = std::time::Instant::now();
	tokio::time::sleep(Duration::from_millis(5200)).await;
	assert_eq!(
		calls.load(Ordering::Relaxed),
		4,
		"three tunnels must share one lookup"
	);
	println!(
		"Q6 A=1 T=3 R=1 trial={trial} continuing_lookups=1 sample_seconds={:.6} continuing_lookups_per_second={:.6}",
		lookup_sample.elapsed().as_secs_f64(),
		1.0 / lookup_sample.elapsed().as_secs_f64()
	);
	for io in &mut tunnels {
		q6_http_request(io, "held", port).await;
	}
	match trigger {
		"quarantine" => view.lock().unwrap().quarantine = true,
		"uid" => {
			let mut v = view.lock().unwrap();
			v.uid = "uid-2";
			v.quarantine = true;
		},
		"activation" => {
			let mut v = view.lock().unwrap();
			v.activation_id = "run-2";
			v.quarantine = true;
		},
		"outage" => view.lock().unwrap().error = Some(tonic::Code::Unavailable),
		"slow" => delay_ms.store(3000, Ordering::Relaxed),
		_ => unreachable!(),
	}
	let start = std::time::Instant::now();
	for io in &mut tunnels {
		let mut b = [0; 1];
		let closed = tokio::time::timeout(Duration::from_secs(8), io.read(&mut b))
			.await
			.expect("close budget exceeded");
		assert!(
			matches!(closed, Ok(0) | Err(_)),
			"revoked tunnel passed bytes"
		);
	}
	println!(
		"Q6 A=1 T=3 R=1 trigger={trigger} trial={trial} close_ms={} lookups={}",
		start.elapsed().as_millis(),
		calls.load(Ordering::Relaxed)
	);
	*view.lock().unwrap() = EgressHandler {
		uid: "uid-1",
		activation_id: "run-1",
		state: Some(ActorState::Running as i32),
		..Default::default()
	};
	delay_ms.store(0, Ordering::Relaxed);
	let mut reopened = open_q6_tcp_tunnel(&gateway, &certificate, port).await;
	q6_http_request(&mut reopened, "released", port).await;
}

#[rstest::rstest]
#[case::quarantine("quarantine")]
#[case::uid_replaced("uid")]
#[case::ordinary_hold("hold")]
#[case::activation_changed("activation")]
#[case::deleted("deleted")]
#[case::failed_check("outage")]
#[case::late_check("slow")]
#[tokio::test]
async fn substrate_revocation_without_activation(#[case] trigger: &str) {
	let view = Arc::new(Mutex::new(EgressHandler {
		uid: "uid-1",
		activation_id: "run-1",
		state: Some(ActorState::Running as i32),
		..Default::default()
	}));
	let calls = Arc::new(AtomicUsize::new(0));
	let delay_ms = Arc::new(AtomicUsize::new(0));
	let upstream = simple_mock().await;
	let port = upstream.address().port();
	let handler = RevocationHandler {
		policy: Some(q6_http_policy(port)),
		view: view.clone(),
		calls: calls.clone(),
		delay_ms: delay_ms.clone(),
	};
	let api = ateapimock::AteApiMock::new(move || handler.clone())
		.spawn()
		.await;
	let gateway = q6_http_gateway(api.address, port).await;
	let certificate = actor_certificate_with_identity(
		"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
		Some("uid-1"),
		None,
	);
	let mut tunnels = Vec::new();
	for _ in 0..2 {
		let mut io = open_q6_tcp_tunnel(&gateway, &certificate, port).await;
		q6_http_request(&mut io, "before", port).await;
		tunnels.push(io);
	}
	assert_eq!(calls.load(Ordering::Relaxed), 2);
	match trigger {
		"quarantine" => view.lock().unwrap().quarantine = true,
		"uid" => view.lock().unwrap().uid = "uid-2",
		"hold" => {
			let mut actor = view.lock().unwrap();
			actor.held = true;
		},
		"activation" => view.lock().unwrap().activation_id = "run-2",
		"deleted" => view.lock().unwrap().error = Some(tonic::Code::NotFound),
		"outage" => view.lock().unwrap().error = Some(tonic::Code::Unavailable),
		"slow" => delay_ms.store(3000, Ordering::Relaxed),
		_ => unreachable!(),
	}
	if matches!(trigger, "hold" | "activation") {
		tokio::time::sleep(Duration::from_millis(5200)).await;
		for io in &mut tunnels {
			q6_http_request(io, "held-with-new-activation", port).await;
		}
		assert_eq!(
			calls.load(Ordering::Relaxed),
			3,
			"one continuing actor lookup"
		);
	} else {
		let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
		for io in &mut tunnels {
			let mut b = [0; 1];
			let closed = tokio::time::timeout_at(deadline, io.read(&mut b))
				.await
				.expect("certificate without activation exceeded close budget");
			assert!(
				matches!(closed, Ok(0) | Err(_)),
				"revoked tunnel passed bytes"
			);
		}
		assert_eq!(
			calls.load(Ordering::Relaxed),
			3,
			"one shared revocation lookup"
		);
	}
}

#[rstest::rstest]
#[tokio::test]
async fn substrate_revocation_mixed_activation_certificates_share_actor_lookup(
	#[values(false, true)] rotate: bool,
) {
	let view = Arc::new(Mutex::new(EgressHandler {
		uid: "uid-1",
		activation_id: "run-1",
		state: Some(ActorState::Running as i32),
		..Default::default()
	}));
	let calls = Arc::new(AtomicUsize::new(0));
	let upstream = simple_mock().await;
	let port = upstream.address().port();
	let handler = RevocationHandler {
		policy: Some(q6_http_policy(port)),
		view: view.clone(),
		calls: calls.clone(),
		delay_ms: Arc::new(AtomicUsize::new(0)),
	};
	let api = ateapimock::AteApiMock::new(move || handler.clone())
		.spawn()
		.await;
	let gateway = q6_http_gateway(api.address, port).await;
	let mut tunnels = Vec::new();
	for activation in [Some("run-1"), None, None] {
		let certificate = actor_certificate_with_identity(
			"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
			Some("uid-1"),
			activation,
		);
		let mut io = open_q6_tcp_tunnel(&gateway, &certificate, port).await;
		q6_http_request(&mut io, "before", port).await;
		tunnels.push(io);
	}
	assert_eq!(calls.load(Ordering::Relaxed), 3);
	{
		let mut actor = view.lock().unwrap();
		actor.held = true;
		if rotate {
			actor.activation_id = "run-2";
		}
	}
	if rotate {
		let mut activation_tunnel = tunnels.remove(0);
		let mut b = [0; 1];
		let closed = tokio::time::timeout(Duration::from_secs(8), activation_tunnel.read(&mut b))
			.await
			.expect("activation-bound tunnel must close on rotation");
		assert!(matches!(closed, Ok(0) | Err(_)));
		// Cross two poll intervals after rotating the activation. Only the certified
		// activation expires; UID-only handles keep the same actor poll alive.
		tokio::time::sleep(Duration::from_millis(10200)).await;
		assert_eq!(
			calls.load(Ordering::Relaxed),
			6,
			"one poll per actor, including UID-only tunnels"
		);
		for io in &mut tunnels {
			q6_http_request(io, "uid-only-after-rotation", port).await;
		}
		let certificate = actor_certificate_with_identity(
			"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
			Some("uid-1"),
			Some("run-2"),
		);
		let mut replacement = open_q6_tcp_tunnel(&gateway, &certificate, port).await;
		q6_http_request(&mut replacement, "new-activation", port).await;
		tunnels.push(replacement);
		assert_eq!(
			calls.load(Ordering::Relaxed),
			7,
			"one new CONNECT admission"
		);
	} else {
		tokio::time::sleep(Duration::from_millis(5200)).await;
		assert_eq!(calls.load(Ordering::Relaxed), 4, "one mixed actor poll");
		for io in &mut tunnels {
			q6_http_request(io, "held", port).await;
		}
	}
	view.lock().unwrap().quarantine = true;
	let mut b = [0; 1];
	let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
	for io in &mut tunnels {
		let closed = tokio::time::timeout_at(deadline, io.read(&mut b))
			.await
			.expect("mixed tunnel must close on quarantine");
		assert!(matches!(closed, Ok(0) | Err(_)));
	}
	assert_eq!(
		calls.load(Ordering::Relaxed),
		if rotate { 8 } else { 5 },
		"one mixed quarantine poll"
	);
}

fn q6_http_policy(port: u16) -> EgressPolicy {
	EgressPolicy {
		rules: vec![protos::ateapi::EgressRule {
			http: Some(protos::ateapi::HttpRule {
				hostnames: vec!["localhost".to_owned()],
				ports: Some(protos::ateapi::Ports {
					numbers: vec![i32::from(port)],
					..Default::default()
				}),
				effects: None,
			}),
			..Default::default()
		}],
		..Default::default()
	}
}

#[cfg(feature = "crypto-aws-lc")]
#[rstest::rstest]
#[case::passthrough(true)]
#[case::mitm(false)]
#[tokio::test]
async fn substrate_revocation_closes_tls_and_pooled_h2(
	#[case] passthrough: bool,
	#[values(0, 1, 2, 3, 4)] trial: usize,
) {
	let (upstream, certs) = tls_mock().await;
	wiremock::Mock::given(wiremock::matchers::path("/pending"))
		.respond_with(wiremock::ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
		.with_priority(1)
		.mount(&upstream)
		.await;
	let address = *upstream.address();
	let port = address.port();
	let ports = Some(protos::ateapi::Ports {
		numbers: vec![i32::from(port)],
		..Default::default()
	});
	let rule = if passthrough {
		protos::ateapi::EgressRule {
			tls_passthrough: Some(protos::ateapi::TlsPassthroughRule {
				hostnames: vec!["localhost".to_owned()],
				ports,
			}),
			..Default::default()
		}
	} else {
		protos::ateapi::EgressRule {
			https: Some(protos::ateapi::HttpsRule {
				hostnames: vec!["localhost".to_owned()],
				ports,
				effects: None,
			}),
			..Default::default()
		}
	};
	let (mut gateway, _native_api) = substrate_tls_gateway(
		Ok(EgressPolicy {
			rules: vec![rule.clone()],
			..Default::default()
		}),
		ActorState::Running,
		address,
		Some(certs.root_cert.pem().into_bytes()),
	)
	.await;
	let view = Arc::new(Mutex::new(EgressHandler {
		uid: "uid-1",
		activation_id: "run-1",
		state: Some(ActorState::Running as i32),
		..Default::default()
	}));
	let handler = RevocationHandler {
		policy: Some(EgressPolicy {
			rules: vec![rule],
			..Default::default()
		}),
		view: view.clone(),
		calls: Default::default(),
		delay_ms: Default::default(),
	};
	let api = ateapimock::AteApiMock::new(move || handler.clone())
		.spawn()
		.await;
	gateway
		.attach_frontend_policy_with_port(
			json!({ "substrateEgressActorResolution": { "host": api.address.to_string() } }),
			Some(15013),
		)
		.await;
	let certificate = actor_certificate_with_identity(
		"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
		Some("uid-1"),
		Some("run-1"),
	);
	let io = open_actor_egress_tunnel_certificate(&gateway, port, true, certificate).await;
	let root = if passthrough {
		certs.root_cert.pem().into_bytes()
	} else {
		include_bytes!("../../../../examples/mcp-tls/certs/ca-cert.pem").to_vec()
	};
	let tls: agentgateway::http::backendtls::BackendTLS =
		agentgateway::http::backendtls::ResolvedBackendTLS {
			root: Some(root),
			alpn: Some(vec!["h2".to_owned()]),
			..Default::default()
		}
		.try_into()
		.unwrap();
	let io = tokio_rustls::TlsConnector::from(tls.base_config().config)
		.connect(
			rustls_pki_types::ServerName::try_from("localhost").unwrap(),
			io,
		)
		.await
		.unwrap();
	let (mut sender, connection) =
		hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
			.handshake(TokioIo::new(io))
			.await
			.unwrap();
	let connection = tokio::spawn(connection);
	for _ in 0..3 {
		let response = sender
			.send_request(
				::http::Request::builder()
					.uri("https://localhost/pooled")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		response.into_body().collect().await.unwrap();
	}
	let pending = sender.send_request(
		::http::Request::builder()
			.uri("https://localhost/pending")
			.body(Body::empty())
			.unwrap(),
	);
	let pending = tokio::spawn(pending);
	tokio::time::timeout(Duration::from_secs(3), async {
		loop {
			if upstream
				.received_requests()
				.await
				.unwrap()
				.iter()
				.any(|request| request.url.path() == "/pending")
			{
				break;
			}
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("pending request was not forwarded before quarantine");
	view.lock().unwrap().quarantine = true;
	let start = std::time::Instant::now();
	let result = tokio::time::timeout(Duration::from_secs(8), pending)
		.await
		.expect("in-flight H2 stream survived revocation")
		.unwrap();
	assert!(result.is_err());
	assert!(
		sender
			.send_request(
				::http::Request::builder()
					.uri("https://localhost/after")
					.body(Body::empty())
					.unwrap()
			)
			.await
			.is_err()
	);
	println!(
		"Q6 A=1 T=1 R=1 passthrough={passthrough} trial={trial} pooled_h2_close_ms={}",
		start.elapsed().as_millis()
	);
	connection.abort();
}

async fn open_q6_tcp_tunnel(
	gateway: &TestBind,
	certificate: &str,
	port: u16,
) -> tokio::io::DuplexStream {
	let mut io = gateway.serve_tunnel_with_tls_info(
		strng::literal!("outer"),
		Some(TLSConnectionInfo {
			src_identity: Some(TlsInfo {
				certificate: Some(certificate.to_owned().into()),
				..Default::default()
			}),
			..Default::default()
		}),
	);
	io.write_all(
		format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes(),
	)
	.await
	.unwrap();
	let mut response = Vec::new();
	while !response.windows(4).any(|w| w == b"\r\n\r\n") {
		let mut b = [0; 256];
		let n = io.read(&mut b).await.unwrap();
		assert_ne!(n, 0);
		response.extend_from_slice(&b[..n]);
	}
	assert!(response.starts_with(b"HTTP/1.1 200"));
	io
}

async fn q6_http_request(io: &mut tokio::io::DuplexStream, path: &str, port: u16) {
	io.write_all(format!("GET /{path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes())
		.await
		.unwrap();
	let mut response = Vec::new();
	loop {
		let mut b = [0; 1024];
		let n = tokio::time::timeout(Duration::from_secs(3), io.read(&mut b))
			.await
			.unwrap()
			.unwrap();
		assert_ne!(n, 0, "HTTP connection closed before response");
		response.extend_from_slice(&b[..n]);
		if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
			let headers = String::from_utf8_lossy(&response[..end]);
			assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
			let length = headers
				.lines()
				.find_map(|line| {
					line
						.to_ascii_lowercase()
						.strip_prefix("content-length:")
						.map(|s| s.trim().parse::<usize>().unwrap())
				})
				.unwrap();
			if response.len() >= end + 4 + length {
				break;
			}
		}
	}
}

async fn q6_http_gateway(api_address: SocketAddr, port: u16) -> TestBind {
	let mut outer = simple_bind();
	outer.key = strng::literal!("outer");
	outer.address = "127.0.0.1:15012".parse().unwrap();
	outer.mode = BindMode::Internal;
	let mut inner = simple_bind();
	inner.address = std::net::SocketAddr::from(([0, 0, 0, 0], port));
	inner.mode = BindMode::Internal;

	let mut gateway = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(BackendWithPolicies {
			backend: Backend::Dynamic(ResourceName::new("dynamic".into(), "".into()), None),
			inline_policies: vec![],
		})
		.with_bind(outer)
		.with_bind(inner)
		.with_route(basic_named_route("/dynamic".into()))
		.with_connect_mode_on_port(agentgateway::types::frontend::ConnectMode::Tunnel, 15012);
	gateway
		.attach_frontend_policy(
			json!({ "substrateEgressActorResolution": { "host": api_address.to_string() } }),
		)
		.await;
	gateway
		.attach_route_policy(json!({ "substrateEgress": { "host": api_address.to_string() } }))
		.await;
	gateway
}

#[tokio::test]
async fn substrate_revocation_connect_quarantine_race() {
	let upstream = simple_mock().await;
	let port = upstream.address().port();
	let view = Arc::new(Mutex::new(EgressHandler {
		uid: "uid-1",
		activation_id: "run-1",
		state: Some(ActorState::Running as i32),
		..Default::default()
	}));
	let calls = Arc::new(AtomicUsize::new(0));
	let handler = RevocationHandler {
		policy: None,
		view: view.clone(),
		calls: calls.clone(),
		delay_ms: Arc::new(AtomicUsize::new(250)),
	};
	let api = ateapimock::AteApiMock::new(move || handler.clone())
		.spawn()
		.await;
	let gateway = q6_http_gateway(api.address, port).await;
	let certificate = actor_certificate_with_identity(
		"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
		Some("uid-1"),
		Some("run-1"),
	);
	let connect = open_q6_tcp_tunnel(&gateway, &certificate, port);
	let mutate = async {
		tokio::time::timeout(Duration::from_secs(2), async {
			while calls.load(Ordering::Relaxed) == 0 {
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
		view.lock().unwrap().quarantine = true;
	};
	let (mut tunnel, ()) = tokio::join!(connect, mutate);
	let mut b = [0; 1];
	let result = tokio::time::timeout(Duration::from_secs(8), tunnel.read(&mut b))
		.await
		.expect("CONNECT race left tunnel authorized");
	assert!(matches!(result, Ok(0) | Err(_)));
}

#[tokio::test]
async fn substrate_revocation_gateway_runtime_loss_closes_tunnel() {
	let upstream = simple_mock().await;
	let port = upstream.address().port();
	let handler = RevocationHandler {
		policy: Some(EgressPolicy {
			rules: vec![protos::ateapi::EgressRule {
				http: Some(protos::ateapi::HttpRule {
					hostnames: vec!["localhost".to_owned()],
					ports: Some(protos::ateapi::Ports {
						numbers: vec![i32::from(port)],
						..Default::default()
					}),
					effects: None,
				}),
				..Default::default()
			}],
			..Default::default()
		}),
		view: Arc::new(Mutex::new(EgressHandler {
			uid: "uid-1",
			activation_id: "run-1",
			state: Some(ActorState::Running as i32),
			..Default::default()
		})),
		calls: Default::default(),
		delay_ms: Default::default(),
	};
	let api = ateapimock::AteApiMock::new(move || handler.clone())
		.spawn()
		.await;
	let address = api.address;
	let (ready, receive) = tokio::sync::oneshot::channel();
	let (stop, stopped) = tokio::sync::oneshot::channel();
	let thread = std::thread::spawn(move || {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap();
		runtime.block_on(async {
			let gateway = q6_http_gateway(address, port).await;
			let certificate = actor_certificate_with_identity(
				"spiffe://substrate-actor.local/worker-for-actor/demo/my-actor",
				Some("uid-1"),
				Some("run-1"),
			);
			let tunnel = open_q6_tcp_tunnel(&gateway, &certificate, port).await;
			ready.send(tunnel).unwrap();
			stopped.await.unwrap();
		});
		// Dropping this isolated runtime aborts every gateway task, including upgraded CONNECTs.
	});
	let mut tunnel = tokio::time::timeout(Duration::from_secs(3), receive)
		.await
		.unwrap()
		.unwrap();
	q6_http_request(&mut tunnel, "before-loss", port).await;
	stop.send(()).unwrap();
	let mut b = [0; 1];
	let result = tokio::time::timeout(Duration::from_secs(3), tunnel.read(&mut b))
		.await
		.expect("gateway runtime loss left tunnel open");
	assert!(matches!(result, Ok(0) | Err(_)));
	thread.join().unwrap();
}

/// An HTTP/2 TLS origin that reports which connection served a request and
/// when each connection ended, independently of any client's account.
#[cfg(feature = "crypto-aws-lc")]
#[derive(Clone, Default)]
struct RecordingOrigin(Arc<Mutex<Vec<Arc<std::sync::atomic::AtomicBool>>>>);

#[cfg(feature = "crypto-aws-lc")]
impl RecordingOrigin {
	async fn spawn(certs: &wiremock::tls_certs::MockTlsCertificates) -> (Self, SocketAddr) {
		struct Ended(Arc<std::sync::atomic::AtomicBool>);
		impl Drop for Ended {
			fn drop(&mut self) {
				self.0.store(true, Ordering::SeqCst);
			}
		}
		let mut config =
			rustls::ServerConfig::builder_with_provider(agentgateway::transport::tls::provider())
				.with_protocol_versions(agentgateway::transport::tls::ALL_TLS_VERSIONS)
				.unwrap()
				.with_no_client_auth()
				.with_single_cert(
					vec![certs.server_cert_der().clone().into_owned()],
					certs.server_private_keypair_der().clone_key(),
				)
				.unwrap();
		config.alpn_protocols = vec![b"h2".to_vec()];
		let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		let origin = Self::default();
		let connections = origin.0.clone();
		tokio::spawn(async move {
			while let Ok((socket, _)) = listener.accept().await {
				let acceptor = acceptor.clone();
				let connections = connections.clone();
				tokio::spawn(async move {
					let Ok(socket) = acceptor.accept(socket).await else {
						return;
					};
					let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
					let id = {
						let mut connections = connections.lock().unwrap();
						connections.push(ended.clone());
						connections.len() - 1
					};
					let _ended = Ended(ended);
					let service = service_fn(
						move |_: ::http::Request<hyper::body::Incoming>| async move {
							Ok::<_, Infallible>(
								::http::Response::builder()
									.header("x-origin-connection", id.to_string())
									.body(http_body_util::Full::new(bytes::Bytes::from_static(b"ok")))
									.unwrap(),
							)
						},
					);
					let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
						.serve_connection(TokioIo::new(socket), service)
						.await;
				});
			}
		});
		(origin, address)
	}

	fn opened(&self) -> usize {
		self.0.lock().unwrap().len()
	}

	fn ended(&self, id: usize) -> bool {
		self.0.lock().unwrap()[id].load(Ordering::SeqCst)
	}

	async fn ends_within(&self, id: usize, limit: Duration) -> bool {
		tokio::time::timeout(limit, async {
			while !self.ended(id) {
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		})
		.await
		.is_ok()
	}
}

#[derive(Clone)]
struct ScopedActors {
	policy: EgressPolicy,
	actors: Arc<Mutex<std::collections::HashMap<&'static str, EgressHandler>>>,
}
#[async_trait::async_trait]
impl ateapimock::Handler for ScopedActors {
	async fn get_actor_egress_policy(
		&mut self,
		_: &protos::ateapi::GetActorEgressPolicyRequest,
	) -> Result<EgressPolicy, tonic::Status> {
		Ok(self.policy.clone())
	}
	async fn get_actor(
		&mut self,
		request: &protos::ateapi::GetActorRequest,
	) -> Result<Actor, tonic::Status> {
		let name = request.actor.as_ref().unwrap().name.as_str();
		let view = self.actors.lock().unwrap().get(name).cloned();
		let view = view.ok_or_else(|| tonic::Status::not_found("actor"))?;
		Ok(Actor {
			metadata: Some(ResourceMetadata {
				uid: view.uid.to_owned(),
				..Default::default()
			}),
			status: Some(ActorStatus {
				state: ActorState::Running as i32,
				worker_assignment: None,
				activation_id: view.activation_id.to_owned(),
				quarantine: view
					.quarantine
					.then_some(protos::ateapi::ActorQuarantine {}),
				holds: if view.held {
					vec![protos::ateapi::ActorHold {}]
				} else {
					vec![]
				},
			}),
		})
	}
}

#[cfg(feature = "crypto-aws-lc")]
struct InterceptedTunnel {
	sender: hyper::client::conn::http2::SendRequest<Body>,
	connection: tokio::task::JoinHandle<()>,
}
#[cfg(feature = "crypto-aws-lc")]
impl InterceptedTunnel {
	async fn open(gateway: &TestBind, port: u16, actor: &str, uid: &str, run: Option<&str>) -> Self {
		let certificate = actor_certificate_for(
			actor,
			&format!("spiffe://substrate-actor.local/worker-for-actor/demo/{actor}"),
			Some(uid),
			run,
		);
		let io = open_actor_egress_tunnel_certificate(gateway, port, true, certificate).await;
		let tls: agentgateway::http::backendtls::BackendTLS =
			agentgateway::http::backendtls::ResolvedBackendTLS {
				root: Some(include_bytes!("../../../../examples/mcp-tls/certs/ca-cert.pem").to_vec()),
				alpn: Some(vec!["h2".to_owned()]),
				..Default::default()
			}
			.try_into()
			.unwrap();
		let io = tokio_rustls::TlsConnector::from(tls.base_config().config)
			.connect(
				rustls_pki_types::ServerName::try_from("localhost").unwrap(),
				io,
			)
			.await
			.unwrap();
		let (sender, connection) =
			hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
				.handshake(TokioIo::new(io))
				.await
				.unwrap();
		let connection = tokio::spawn(async move {
			let _ = connection.await;
		});
		Self { sender, connection }
	}

	/// The origin connection that served one request, or None if it failed.
	async fn request(&mut self) -> Option<usize> {
		let request = ::http::Request::builder()
			.uri("https://localhost/pooled")
			.body(Body::empty())
			.unwrap();
		let response = self.sender.send_request(request).await.ok()?;
		if response.status() != StatusCode::OK {
			return None;
		}
		let id = response
			.headers()
			.get("x-origin-connection")?
			.to_str()
			.ok()?
			.parse()
			.ok()?;
		response.into_body().collect().await.ok()?;
		Some(id)
	}

	/// Three requests that must share one origin connection.
	async fn pooled(&mut self) -> usize {
		let id = self.request().await.expect("request through open tunnel");
		for _ in 0..2 {
			assert_eq!(self.request().await, Some(id), "requests were not pooled");
		}
		id
	}

	async fn close(self) {
		drop(self.sender);
		self.connection.abort();
		let _ = self.connection.await;
	}
}

#[cfg(feature = "crypto-aws-lc")]
type ScopedActorViews = Arc<Mutex<std::collections::HashMap<&'static str, EgressHandler>>>;

/// Two running actors that may reach one recording origin over intercepted HTTPS.
#[cfg(feature = "crypto-aws-lc")]
async fn scoped_upstream_fixture(
	setting: Option<&str>,
) -> (
	RecordingOrigin,
	SocketAddr,
	TestBind,
	ScopedActorViews,
	agentgateway::test_helpers::MockInstance,
) {
	let (_unused, certs) = tls_mock().await;
	let (origin, address) = RecordingOrigin::spawn(&certs).await;
	let port = address.port();
	let policy = EgressPolicy {
		rules: vec![protos::ateapi::EgressRule {
			https: Some(protos::ateapi::HttpsRule {
				hostnames: vec!["localhost".to_owned()],
				ports: Some(protos::ateapi::Ports {
					numbers: vec![i32::from(port)],
					..Default::default()
				}),
				effects: None,
			}),
			..Default::default()
		}],
		..Default::default()
	};
	let actors = Arc::new(Mutex::new(std::collections::HashMap::from([
		(
			"my-actor",
			EgressHandler {
				uid: "uid-1",
				activation_id: "run-1",
				..Default::default()
			},
		),
		(
			"other-actor",
			EgressHandler {
				uid: "uid-2",
				activation_id: "run-9",
				..Default::default()
			},
		),
	])));
	let handler = ScopedActors {
		policy,
		actors: actors.clone(),
	};
	let api = ateapimock::AteApiMock::new(move || handler.clone())
		.spawn()
		.await;
	let gateway = substrate_tls_gateway_with_api(
		api.address,
		address,
		Some(certs.root_cert.pem().into_bytes()),
		setting,
	)
	.await;
	// The caller keeps the control API alive for the continuing actor checks.
	(origin, address, gateway, actors, api)
}

// The origin, not the actor, decides whether an intercepted connection ended.
// Each certificate-bound execution owns its upstream connections: they end
// with its authorization or its last tunnel, and never serve another execution.
#[cfg(feature = "crypto-aws-lc")]
#[rstest::rstest]
#[case::quarantine("quarantine", None)]
#[case::explicit("quarantine", Some("perExecution"))]
#[case::activation("activation", None)]
#[case::hold("hold", None)]
#[case::last_tunnel("last-tunnel", None)]
#[tokio::test]
async fn substrate_upstream_connections_follow_the_execution(
	#[case] trigger: &str,
	#[case] setting: Option<&str>,
) {
	let (origin, address, gateway, actors, _api) = scoped_upstream_fixture(setting).await;
	let port = address.port();

	let mut bound = InterceptedTunnel::open(&gateway, port, "my-actor", "uid-1", Some("run-1")).await;
	let mut second =
		InterceptedTunnel::open(&gateway, port, "my-actor", "uid-1", Some("run-1")).await;
	let mut uid_only = InterceptedTunnel::open(&gateway, port, "my-actor", "uid-1", None).await;
	let mut other =
		InterceptedTunnel::open(&gateway, port, "other-actor", "uid-2", Some("run-9")).await;
	let bound_id = bound.pooled().await;
	assert_eq!(
		second.pooled().await,
		bound_id,
		"tunnels of one execution share its upstream connection"
	);
	let uid_only_id = uid_only.pooled().await;
	let other_id = other.pooled().await;
	assert_ne!(
		bound_id, uid_only_id,
		"bindings shared an upstream connection"
	);
	assert_ne!(bound_id, other_id, "actors shared an upstream connection");
	assert_ne!(
		uid_only_id, other_id,
		"actors shared an upstream connection"
	);
	assert_eq!(origin.opened(), 3);

	let budget = Duration::from_secs(8);
	let start = std::time::Instant::now();
	match trigger {
		"quarantine" => {
			actors
				.lock()
				.unwrap()
				.get_mut("my-actor")
				.unwrap()
				.quarantine = true;
			assert!(
				origin.ends_within(bound_id, budget).await,
				"bound upstream survived"
			);
			assert!(
				origin.ends_within(uid_only_id, budget).await,
				"UID-only upstream survived"
			);
			assert_eq!(bound.request().await, None);
			assert_eq!(uid_only.request().await, None);
		},
		"activation" => {
			actors
				.lock()
				.unwrap()
				.get_mut("my-actor")
				.unwrap()
				.activation_id = "run-2";
			assert!(
				origin.ends_within(bound_id, budget).await,
				"bound upstream survived"
			);
			assert_eq!(bound.request().await, None);
			assert_eq!(second.request().await, None);
			// A UID-only binding is not revoked by an activation change.
			assert_eq!(uid_only.request().await, Some(uid_only_id));
			assert!(!origin.ended(uid_only_id));
			bound = InterceptedTunnel::open(&gateway, port, "my-actor", "uid-1", Some("run-2")).await;
			let resumed_id = bound.pooled().await;
			assert_ne!(resumed_id, bound_id);
			assert_ne!(resumed_id, uid_only_id);
			assert_ne!(resumed_id, other_id);
		},
		"hold" => {
			actors.lock().unwrap().get_mut("my-actor").unwrap().held = true;
			tokio::time::sleep(Duration::from_millis(7500)).await;
			assert_eq!(bound.request().await, Some(bound_id));
			assert_eq!(uid_only.request().await, Some(uid_only_id));
		},
		"last-tunnel" => {
			bound.close().await;
			tokio::time::sleep(Duration::from_millis(500)).await;
			assert_eq!(
				second.request().await,
				Some(bound_id),
				"upstream ended while the execution still had a tunnel"
			);
			second.close().await;
			assert!(
				origin.ends_within(bound_id, Duration::from_secs(3)).await,
				"upstream outlived the execution's last tunnel"
			);
			assert_eq!(uid_only.request().await, Some(uid_only_id));
			bound = InterceptedTunnel::open(&gateway, port, "my-actor", "uid-1", Some("run-1")).await;
			let reopened = bound.pooled().await;
			assert_ne!(reopened, bound_id);
			assert_eq!(origin.opened(), 4);
		},
		_ => unreachable!(),
	}
	println!(
		"Q6 upstream scope trigger={trigger} elapsed_ms={}",
		start.elapsed().as_millis()
	);
	// Another actor's upstream connection is never affected.
	assert_eq!(other.request().await, Some(other_id));
	assert!(!origin.ended(other_id));
	assert_eq!(
		origin.opened(),
		if matches!(trigger, "last-tunnel" | "activation") {
			4
		} else {
			3
		}
	);
}

// The opt-out keeps one pool for every actor. Revocation still cuts the
// actor's tunnels, but the pooled upstream connection is not the actor's to
// lose: it stays open and keeps serving others.
#[cfg(feature = "crypto-aws-lc")]
#[tokio::test]
async fn substrate_shared_upstream_connections_outlive_revocation() {
	let (origin, address, gateway, actors, _api) = scoped_upstream_fixture(Some("shared")).await;
	let port = address.port();
	let mut bound = InterceptedTunnel::open(&gateway, port, "my-actor", "uid-1", Some("run-1")).await;
	let mut uid_only = InterceptedTunnel::open(&gateway, port, "my-actor", "uid-1", None).await;
	let mut other =
		InterceptedTunnel::open(&gateway, port, "other-actor", "uid-2", Some("run-9")).await;
	let shared = bound.pooled().await;
	assert_eq!(uid_only.pooled().await, shared);
	assert_eq!(other.pooled().await, shared);
	assert_eq!(origin.opened(), 1);

	actors
		.lock()
		.unwrap()
		.get_mut("my-actor")
		.unwrap()
		.quarantine = true;
	tokio::time::timeout(Duration::from_secs(8), async {
		while bound.request().await.is_some() || uid_only.request().await.is_some() {
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	})
	.await
	.expect("quarantine left the actor's tunnels open");
	assert!(
		!origin.ended(shared),
		"shared upstream ended with one actor"
	);
	assert_eq!(other.request().await, Some(shared));
	assert_eq!(origin.opened(), 1);
}
