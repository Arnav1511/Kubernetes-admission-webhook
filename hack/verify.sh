#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pass() {
  echo "[pass] $1"
}

run() {
  local name="$1"
  shift
  echo "[run] $name"
  "$@"
  pass "$name"
}

if command -v gofmt >/dev/null 2>&1; then
  echo "[run] gofmt check"
  unformatted="$(gofmt -l .)"
  if [[ -n "$unformatted" ]]; then
    echo "$unformatted"
    echo "[fail] gofmt check"
    exit 1
  fi
  pass "gofmt check"
else
  echo "[fail] gofmt is required"
  exit 1
fi

run "go vet" go vet ./...
run "go test -race" go test -race ./...

if command -v helm >/dev/null 2>&1; then
  run "helm lint" helm lint deploy/helm
  run "helm template with cert-manager" helm template k8s-policy-webhook deploy/helm \
    --namespace k8s-policy-webhook \
    --set certManager.enabled=true
  run "helm template with external TLS" helm template k8s-policy-webhook deploy/helm \
    --namespace k8s-policy-webhook \
    --set certManager.enabled=false \
    --set tls.existingSecretName=k8s-policy-webhook-tls \
    --set webhook.caBundle=Y2EtYnVuZGxl
else
  echo "[skip] helm not found; skipping Helm lint and rendering"
fi

if command -v docker >/dev/null 2>&1; then
  run "docker build" docker build -t k8s-policy-webhook:verify .
else
  echo "[skip] docker not found; skipping Docker build"
fi

pass "verification complete"
