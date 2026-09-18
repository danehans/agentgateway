# Response Cache with Redis Open Source

These examples combine agentgateway v1.5.0, [vLLM Semantic Router
(vSR)](https://vllm-sr.ai/docs/tutorials/plugin/response-cache/), and Redis
Open Source to reuse responses to semantically equivalent product-support
questions. Both run a deterministic HomeHub backend without LLM credentials.

## Choose a deployment

- [Kubernetes](kubernetes/README.md): local kind cluster, Gateway API,
  agentgateway controller, and Redis persistent storage.
- [Standalone](standalone/README.md): Docker Compose with standalone
  agentgateway, vSR, Redis, and the same Python backend.

Each deployment has its own `versions.env`. vSR intentionally uses `latest`
(and chart `0.0.0-latest` on Kubernetes): release v0.3.0 lacks required ExtProc
streaming changes. The `version: v0.3` YAML field selects the configuration
schema, not the runtime release. Record the resolved image digests when reporting
results. See the [validation record](VALIDATION.md) for a tested run.

## How it works

```text
Client --> agentgateway --> HomeHub backend (cache miss)
                 |                 |
                 v                 |
             vSR ExtProc <---------+ response stored on a miss
                 |
                 v
               Redis
```

On a hit, vSR returns the cached completion through ExtProc and agentgateway
responds without calling HomeHub. On a miss, agentgateway calls HomeHub and
passes the complete response through vSR to populate Redis. ExtProc request
streaming is enabled; the mock backend returns non-streaming completions.

The route-local `response_cache` plugin uses `mode: semantic`, including for
identical requests, and `scope: global` for these non-personalized mock answers.
The store is configured under `global.stores.response_cache`. Redis provides
shared, persistent state; vSR also supports an in-memory backend.

Both verification scripts check an initial miss, an identical-request hit,
a paraphrase hit, and an uncached outdoor-use question. Backend invocation
counts prove that hits bypass HomeHub. Optional checks verify reuse from a
fresh vSR instance and persistence across a Redis restart.

The [shared backend](shared/support-backend.py) uses only Python's standard
library. Kubernetes loads it from a ConfigMap; Compose mounts it into the
Python image. No custom image build or registry publication is required.

The demonstration threshold, 0.70, is not a production recommendation.
Similar product identifiers such as X2 and X3 can produce unsafe false hits;
calibrate thresholds and isolation against your real requests. Global scope
is appropriate only for responses safe to share with every caller. The local
examples use cleartext Redis and ExtProc connections; see the Kubernetes
README for production considerations.
