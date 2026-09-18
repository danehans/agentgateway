# Standalone Response Cache

Run agentgateway v1.5.0, vSR, Redis Open Source, and the deterministic HomeHub
backend with Docker Compose. No Kubernetes cluster, custom image build, or
LLM provider credentials are required. See the [shared overview](../README.md)
for the request flow and cache policy, or the [Kubernetes example](../kubernetes/README.md).

## Prerequisites

Install Docker with Compose v2, curl, and jq. Allocate at least 6 CPUs, 10 GiB
of memory, and 15 GiB of free disk space to Docker. vSR downloads the embedding
model on first startup; this can take several minutes.

## Start

From the repository root:

```bash
cd examples/llm-semantic-routing/response-cache/standalone
docker compose --env-file versions.env up -d --wait --wait-timeout 650
```

`versions.env` selects agentgateway v1.5.0 and vSR `latest`. Keep vSR on `latest`
because v0.3.0 lacks required ExtProc streaming changes. Compose pulls the
current vSR image on startup. Inspect the actual image used with:

```bash
docker inspect "$(docker compose --env-file versions.env ps -q semantic-router)" \
  --format '{{.Image}}'
```

The gateway listens on `127.0.0.1:3000`. To use another port, export `PORT`
before starting and verifying. Redis, HomeHub, and vSR are internal to the
Compose network. The shared Python script is mounted read-only into
`python:3.12-alpine` and served as `support-backend:8080`.

## Verify

```bash
./verify.sh
./verify.sh --shared-vsr --redis-restart
```

Verification resets the dedicated example cache and HomeHub counters. It
checks that the first factory-reset request invokes HomeHub, while an exact
repeat and a paraphrase reuse its response. An outdoor-use question selects
the uncached decision and increments the counter.

`--shared-vsr` recreates vSR after the cache is populated, proving that a fresh
instance reuses Redis entries. It retains the tested image and model volume.
The Kubernetes variant additionally exercises multiple replicas.
`--redis-restart` saves Redis data, restarts Redis, and checks another hit.
These checks use backend invocation counts and vSR debug headers.

Send a request manually:

```bash
curl -i "http://127.0.0.1:${PORT:-3000}/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -H 'X-VSR-Debug: true' \
  -d '{"model":"auto","messages":[{"role":"user","content":"How do I factory-reset my HomeHub X2?"}],"max_tokens":96}'
```

## Troubleshoot

```bash
docker compose --env-file versions.env ps -a
docker compose --env-file versions.env logs --tail=100 semantic-router agentgateway
docker compose --env-file versions.env exec redis redis-cli --raw FT._LIST
docker compose --env-file versions.env exec support-backend python -c \
  'import urllib.request; print(urllib.request.urlopen("http://localhost:8080/stats").read().decode())'
```

If vSR exits, inspect its logs for configuration or model-download errors.
If startup exceeds the timeout, allow the download to finish and rerun the
startup command. The configured embedding dimension and model must agree.
Paraphrase similarity depends on the embedding model; do not lower the
threshold without evaluating false hits. The shared overview explains why
these fixed public answers use global cache scope.

## Cleanup

Stop the stack while preserving cached responses and downloaded models:

```bash
docker compose --env-file versions.env down
```

To also delete the example's Redis data and model volumes:

```bash
docker compose --env-file versions.env down --volumes
```
