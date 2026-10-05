//! A deterministic routing service and mock inference backend. No model or API key is required.
use std::collections::HashMap;

use axum::Json;
use axum::response::{IntoResponse, Response};
use protos::model_router::model_router_server::{ModelRouter, ModelRouterServer};
use protos::model_router::{Rejection, RouteRequest, RouteResponse, Selection, route_response};
use serde_json::{Value, json};

struct Router;

#[tonic::async_trait]
impl ModelRouter for Router {
	async fn route(
		&self,
		request: tonic::Request<RouteRequest>,
	) -> Result<tonic::Response<RouteResponse>, tonic::Status> {
		let request = request.into_inner();
		if request.input_format != "openai_chat" {
			return Err(tonic::Status::invalid_argument("unsupported input format"));
		}
		let body: Value = serde_json::from_slice(&request.request_json)
			.map_err(|_| tonic::Status::invalid_argument("invalid request JSON"))?;
		let text = body["messages"]
			.as_array()
			.into_iter()
			.flatten()
			.filter_map(|message| message["content"].as_str())
			.collect::<Vec<_>>()
			.join(" ");
		// Demonstrate the difference between an RPC failure and a deliberate rejection.
		if text == "outage" {
			return Err(tonic::Status::unavailable("simulated router outage"));
		}
		let outcome = if text == "conflict" {
			route_response::Outcome::Rejection(Rejection {
				http_status: 409,
				code: "session_conflict".into(),
				message: "Simulated session ownership conflict".into(),
			})
		} else {
			let model = if text.contains("complex") {
				"premium-model"
			} else {
				"economy-model"
			};
			if !request
				.candidates
				.iter()
				.any(|candidate| candidate == model)
			{
				return Err(tonic::Status::failed_precondition(
					"demo model missing from candidates",
				));
			}
			route_response::Outcome::Selection(Selection {
				model: model.into(),
			})
		};
		Ok(tonic::Response::new(RouteResponse {
			policy_generation: request.policy_generation,
			diagnostics: HashMap::from([("reason".into(), "demo_rule".into())]),
			outcome: Some(outcome),
		}))
	}
}

async fn inference(Json(body): Json<Value>) -> Response {
	let model = body["model"].as_str().unwrap_or("unknown");
	if body["stream"] == true {
		let first = json!({"id":"demo", "object":"chat.completion.chunk", "created":0, "model":model,
            "choices":[{"index":0,"delta":{"role":"assistant","content":"Hello from the mock backend"},"finish_reason":null}]});
		let last = json!({"id":"demo", "object":"chat.completion.chunk", "created":0, "model":model,
            "choices":[{"index":0,"delta":{},"finish_reason":"stop"}]});
		return (
			[("content-type", "text/event-stream")],
			format!("data: {first}\n\ndata: {last}\n\ndata: [DONE]\n\n"),
		)
			.into_response();
	}
	Json(json!({"id":"demo", "object":"chat.completion", "created":0, "model":model,
        "choices":[{"index":0,"message":{"role":"assistant","content":"Hello from the mock backend"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}})).into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let inference_addr =
		std::env::var("MOCK_INFERENCE_ADDR").unwrap_or_else(|_| "0.0.0.0:3001".into());
	let router_addr = std::env::var("GRPC_ROUTER_ADDR").unwrap_or_else(|_| "0.0.0.0:50051".into());
	let listener = tokio::net::TcpListener::bind(&inference_addr).await?;
	let app = axum::Router::new().route("/v1/chat/completions", axum::routing::post(inference));
	println!("Routing RPC: {router_addr}; mock inference: {inference_addr}");
	tokio::try_join!(
		async {
			axum::serve(listener, app)
				.await
				.map_err(anyhow::Error::from)
		},
		async {
			tonic::transport::Server::builder()
				.add_service(ModelRouterServer::new(Router))
				.serve(router_addr.parse()?)
				.await
				.map_err(anyhow::Error::from)
		},
	)?;
	Ok(())
}
