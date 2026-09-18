# Validation record

Validated on 2026-09-17 with Docker on ARM64 and a two-node kind cluster
running Kubernetes v1.36.1. Both deployment modes used agentgateway v1.5.0,
Redis 8.10.0-alpine, and Python 3.12-alpine.

Both commands passed:

```bash
examples/llm-semantic-routing/response-cache/standalone/verify.sh --shared-vsr --redis-restart
examples/llm-semantic-routing/response-cache/kubernetes/verify.sh --shared-vsr --redis-restart
```

The checks verified the initial miss, exact-repeat and paraphrase hits,
uncached support decision, backend invocation counts, Redis Search indexes,
reuse from a fresh vSR instance, and persistence across a Redis restart.
The Kubernetes check additionally scaled to two vSR replicas and removed
the original pod before checking reuse.

These are the resolved vSR artifacts from that run, not deployment pins.
The examples continue to track `latest` for required ExtProc streaming fixes.

| Artifact | Tag/version | Resolved digest |
| --- | --- | --- |
| `ghcr.io/vllm-project/semantic-router/vllm-sr` (standalone) | `latest` | `sha256:3c805d8313dd03a53ff2b54a3a4a508c8e1b439b6820807d3dd0715cae665025` |
| `ghcr.io/vllm-project/semantic-router/extproc` (Kubernetes) | `latest` | `sha256:9ed9298b72d3dc314e0a6d8642fc84db00bf3fe88c655ed094f8c8fd57ef65d3` |
| `ghcr.io/vllm-project/charts/semantic-router` | `0.0.0-latest` | `sha256:c832ca74217c53616b53741163fdbe7a57d38df89407fe874fa6287acb6680e0` |

ShellCheck, YAML parsing, standalone agentgateway schema validation, and local
Markdown link checks also passed. After moving the unchanged deployment files
to a topic branch based on `main`, ShellCheck, Compose configuration, and local
Markdown links were checked again.
