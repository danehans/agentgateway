## Semantic Routing Example

This example shows how to configure native semantic routing for OpenAI-compatible chat completions.
It includes examples with no token bounds, `maxInputTokens`, `minInputTokens`, and both token bounds.

### Prerequisites

Set an OpenAI API key:

```bash
export OPENAI_API_KEY=...
```

Build the local binary:

```bash
# TODO: remove this local build step when semantic routing is merged upstream
# and available in the released agentgateway binary.
cargo build -p agentgateway-app
```

### Running the example

```bash
./target/debug/agentgateway \
  --file examples/semantic-routing/config.yaml \
  2>&1 | tee semantic-routing.log
```

Semantic route embeddings warm up automatically after config activation. Confirm warmup:

```bash
grep 'semantic route index warmup' semantic-routing.log | jq .
```

### Minimal semantic routing

The `semantic-basic` virtual model shows the smallest useful semantic routing config.
It relies on the default `scoreThreshold` and has no token bounds.

Coding prompts route to `gpt-4o-mini`:

```bash
curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "semantic-basic",
    "messages": [{"role": "user", "content": "Write Rust code for a small HTTP handler."}]
  }' | jq '{response_model: .model}'
```

Unmatched prompts fall back to `gpt-3.5-turbo`:

```bash
curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "semantic-basic",
    "messages": [{"role": "user", "content": "Say hello in one sentence."}]
  }' | jq '{response_model: .model}'
```

### maxInputTokens

The `semantic-max-tokens` virtual model adds `scoreThreshold` and routes matching architecture
prompts to `gpt-4.1-mini` only when the estimated input token count is at or below
`maxInputTokens`.

Short prompt, expected to route to `gpt-4.1-mini`:

```bash
curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "semantic-max-tokens",
    "messages": [{"role": "user", "content": "Compare Redis and Postgres for a job queue."}]
  }' | jq '{response_model: .model}'
```

Long prompt, expected to fall back to `gpt-3.5-turbo`:

```bash
LONG_PROMPT=$(python3 - <<'PY'
print("Compare Redis and Postgres for a job queue. " +
      "Discuss durability, latency, retries, ordering, backpressure, observability, operational complexity, and failure recovery. " * 20)
PY
)

curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "$(jq -nc --arg prompt "$LONG_PROMPT" \
    '{model:"semantic-max-tokens",messages:[{role:"user",content:$prompt}]}')" \
  | jq '{response_model: .model}'
```

### minInputTokens

The `semantic-min-tokens` virtual model adds `scoreThreshold` and routes matching architecture
prompts to `gpt-4.1-mini` only when the estimated input token count is at or above
`minInputTokens`.

Short prompt, expected to fall back to `gpt-3.5-turbo`:

```bash
curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "semantic-min-tokens",
    "messages": [{"role": "user", "content": "Redis or Postgres queue?"}]
  }' | jq '{response_model: .model}'
```

Long prompt, expected to route to `gpt-4.1-mini`:

```bash
LONG_PROMPT=$(python3 - <<'PY'
print("Compare Redis and Postgres for a job queue. " +
      "Discuss durability, latency, retries, ordering, backpressure, observability, operational complexity, and failure recovery. " * 12)
PY
)

curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "$(jq -nc --arg prompt "$LONG_PROMPT" \
    '{model:"semantic-min-tokens",messages:[{role:"user",content:$prompt}]}')" \
  | jq '{response_model: .model}'
```

### Token range

The `semantic-token-range` virtual model combines `minInputTokens` and `maxInputTokens`.
The target is eligible only when the estimated input token count is inside the configured range.

Too short, expected to fall back to `gpt-3.5-turbo`:

```bash
curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "semantic-token-range",
    "messages": [{"role": "user", "content": "Redis queue?"}]
  }' | jq '{response_model: .model}'
```

Inside range, expected to route to `gpt-4.1-mini`:

```bash
curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "semantic-token-range",
    "messages": [{"role": "user", "content": "Compare Redis and Postgres for a job queue. Discuss durability, latency, retries, backpressure, observability, ordering guarantees, operations, and failure recovery in a concise architecture review."}]
  }' | jq '{response_model: .model}'
```

Too long, expected to fall back to `gpt-3.5-turbo`:

```bash
LONG_PROMPT=$(python3 - <<'PY'
print("Compare Redis and Postgres for a job queue. " +
      "Discuss durability, latency, retries, ordering, backpressure, observability, operational complexity, and failure recovery. " * 30)
PY
)

curl -s http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "$(jq -nc --arg prompt "$LONG_PROMPT" \
    '{model:"semantic-token-range",messages:[{role:"user",content:$prompt}]}')" \
  | jq '{response_model: .model}'
```

### Inspecting routing decisions

The example enables JSON debug logging. Use these logs to confirm model selection and token bounds:

```bash
grep 'semantic virtual model' semantic-routing.log \
  | jq -c '{message,target_model,best_target_model,score,best_score,input_tokens,min_input_tokens,max_input_tokens,phrase,best_phrase,default_model}'
```
