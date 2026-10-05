# Typed gRPC model routing

A client requests `auto`. Agentgateway sends one unary `ModelRouter.Route` RPC,
checks the returned model, and forwards the inference request to that model's
backend. The routing service never receives the inference response.

This example runs a small Rust router and a mock OpenAI backend. It needs no API
keys or model downloads. The rule selects `premium-model` when a message contains
`complex`, and `economy-model` otherwise. It demonstrates the protocol; it does
not perform semantic classification or store sessions.

## Run locally

Use a build from this branch; released agentgateway images do not contain this
API. From the repository root, start the router and mock backend:

```sh
cargo run --profile ci -p agentgateway --example grpc-model-router
```

In another terminal, start agentgateway from the same checkout:

```sh
cargo run --profile ci --bin agentgateway -- -f examples/llm-callout-grpc/config.yaml
```

Send a request:

```sh
curl -sS http://localhost:4000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"auto","messages":[{"role":"user","content":"Solve a complex problem"}]}'
```

The response uses `premium-model`. Replace the message with `hello` to select
`economy-model`. Add `"stream":true` to the request and use `curl -N` to see SSE
chunks and the final `[DONE]` event.

Two exact messages exercise error handling:

| Message | Result |
| --- | --- |
| `outage` | The RPC returns `UNAVAILABLE`; configured fallback selects `economy-model`. |
| `conflict` | The router deliberately rejects the request; the client receives HTTP 409, even with fallback configured. |

Remove `failureMode` from the config to make `outage` return HTTP 503. Both
concrete models are internal, so clients must use the virtual model.

## Kubernetes

[kubernetes.yaml](kubernetes.yaml) shows the corresponding Gateway API
configuration. It uses the same router and mock backend, exposed by one Service.
Run the example binary in a Pod labelled `app: grpc-model-router` with ports 50051
and 3001, then apply the manifest. Supply your own image containing the example
binary; the manifest deliberately does not reference a nonexistent published image.

The controller, data plane, and AgentgatewayModel CRD must all be built from this
branch. Enable `AGW_ENABLE_AGENTGATEWAY_MODELS=true` on the controller. After the
Gateway is programmed, send the same requests to its HTTP listener. Concrete and
virtual models must attach to the same listener. In a production deployment,
model backends and routing services normally run separately.

## Build a routing service

Implement the unary RPC in
[model_router.proto](../../crates/protos/proto/model_router.proto). Rust bindings
are exported by `protos::model_router`; generated Go bindings are in `api`.
See [the protocol guide](../../docs/grpc-model-routing.md) for validation rules,
deadlines, error handling, and session protection considerations.

## Automated smoke test

From the repository root:

```sh
cargo build --profile ci --bin agentgateway -p agentgateway-app
cargo build --profile ci -p agentgateway --example grpc-model-router
python3 examples/llm-callout-grpc/smoke.py
```

The test starts both processes on temporary ports, checks selection, fallback,
rejection, SSE, and direct access to internal models, then stops its processes.
Use `--gateway` and `--router` to point to binaries in a custom Cargo target directory.
