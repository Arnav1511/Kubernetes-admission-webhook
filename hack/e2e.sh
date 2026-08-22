#!/usr/bin/env bash
# End-to-end test: deploy the webhook into a throwaway kind cluster and assert
# that it actually admits and denies real API server requests.
#
# helm template and helm lint cannot catch deployment-time failures such as a
# webhook deadlocking on its own namespace or a kubelet refusing a non-numeric
# USER. This does, because it uses a real API server.
#
# Usage: hack/e2e.sh [cluster-name]
#   KEEP_CLUSTER=1 hack/e2e.sh   # leave the cluster up for debugging

set -euo pipefail

CLUSTER="${1:-policy-e2e}"
NAMESPACE="webhook-system"
TEST_NS="policy-test"
IMAGE="k8s-policy-webhook:e2e"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
for c in kind kubectl helm docker openssl; do require_cmd "$c"; done

cleanup() {
  rm -rf "$WORKDIR"
  if [ "${KEEP_CLUSTER:-0}" != "1" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

PASS=0
FAIL=0

# assert <name> <allow|deny> <command...>
assert() {
  local name="$1" expect="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)" && rc=0 || rc=$?
  if { [ "$expect" = "allow" ] && [ "$rc" -eq 0 ]; } ||
     { [ "$expect" = "deny" ]  && [ "$rc" -ne 0 ]; }; then
    echo "PASS  $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $name (expected $expect, rc=$rc)"
    echo "$out" | head -3 | sed 's/^/        /'
    FAIL=$((FAIL + 1))
  fi
}

echo "==> Creating kind cluster '$CLUSTER'"
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 120s

echo "==> Building and loading image"
docker build -t "$IMAGE" "$REPO_ROOT"
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "==> Generating serving certificates"
bash "$REPO_ROOT/hack/gen-certs.sh" k8s-policy-webhook "$NAMESPACE" "$WORKDIR/certs" >/dev/null

echo "==> Installing chart"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NAMESPACE" create secret tls k8s-policy-webhook-tls \
  --cert="$WORKDIR/certs/tls.crt" --key="$WORKDIR/certs/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

helm upgrade --install k8s-policy-webhook "$REPO_ROOT/deploy/helm" \
  --namespace "$NAMESPACE" \
  --set certManager.enabled=false \
  --set tls.existingSecretName=k8s-policy-webhook-tls \
  --set webhook.caBundle="$(base64 -w0 < "$WORKDIR/certs/ca.crt")" \
  --set image.repository=k8s-policy-webhook \
  --set image.tag=e2e \
  --set image.pullPolicy=Never \
  --set replicaCount=1 \
  --set podDisruptionBudget.enabled=false >/dev/null

# A webhook that excludes its own namespace can roll out unassisted. If this
# times out, suspect the namespaceSelector or the image's USER directive.
echo "==> Waiting for webhook to become ready"
kubectl -n "$NAMESPACE" rollout status deploy/k8s-policy-webhook --timeout=180s

kubectl create namespace "$TEST_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo
echo "==> Policy enforcement"
assert "compliant pod is admitted"        allow kubectl -n "$TEST_NS" apply -f "$REPO_ROOT/examples/good-pod.yaml"
assert "pod using :latest is denied"      deny  kubectl -n "$TEST_NS" apply -f "$REPO_ROOT/examples/bad-pod.yaml"
assert "over-replicated deploy is denied" deny  kubectl -n "$TEST_NS" apply -f "$REPO_ROOT/examples/bad-deployment.yaml"

echo
echo "==> Compliant pod actually starts"
assert "compliant pod reaches Ready" allow \
  kubectl -n "$TEST_NS" wait --for=condition=Ready pod/good-pod --timeout=180s

# Ready alone is not enough: with no readiness probe a container that crashes
# after a second still passes the wait above during its brief running window.
stays_up() {
  sleep 15
  local restarts
  restarts="$(kubectl -n "$TEST_NS" get pod good-pod \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null)"
  [ "${restarts:-1}" = "0" ] || {
    echo "good-pod restarted ${restarts} time(s); it is not staying up" >&2
    kubectl -n "$TEST_NS" logs good-pod --tail=20 --previous 2>/dev/null >&2 || true
    return 1
  }
}
assert "compliant pod stays up (no crash loop)" allow stays_up

echo
echo "==> Ephemeral containers (pods/ephemeralcontainers subresource)"
assert "ephemeral container using :latest is denied" deny \
  kubectl -n "$TEST_NS" debug good-pod --image=busybox:latest --target=web -q
assert "privileged ephemeral container is denied" deny \
  kubectl -n "$TEST_NS" patch pod good-pod --subresource=ephemeralcontainers --type=strategic \
    -p '{"spec":{"ephemeralContainers":[{"name":"evil","image":"busybox:1.36.1","securityContext":{"privileged":true},"terminationMessagePolicy":"File","imagePullPolicy":"IfNotPresent"}]}}'
assert "pinned ephemeral container is allowed" allow \
  kubectl -n "$TEST_NS" debug good-pod --image=busybox:1.36.1 --target=web -q

echo
echo "==================================="
echo "  passed: $PASS   failed: $FAIL"
echo "==================================="
[ "$FAIL" -eq 0 ]
