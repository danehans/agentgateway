#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
kubectl apply -f "${SCRIPT_DIR}/support-backend.yaml"
kubectl create configmap support-backend -n homehub \
  --from-file="server.py=${SCRIPT_DIR}/../shared/support-backend.py" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/support-backend -n homehub
kubectl rollout status deployment/support-backend -n homehub --timeout=120s
