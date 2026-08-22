# k8s-policy-webhook

[![CI](https://github.com/Arnav1511/Kubernetes-admission-webhook/actions/workflows/ci.yml/badge.svg)](https://github.com/Arnav1511/Kubernetes-admission-webhook/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Arnav1511/Kubernetes-admission-webhook)](go.mod)
[![GHCR](https://img.shields.io/badge/GHCR-k8s--policy--webhook-blue)](https://github.com/Arnav1511/Kubernetes-admission-webhook/pkgs/container/k8s-policy-webhook)
[![Interactive Walkthrough](https://img.shields.io/badge/interactive-walkthrough-blue)](https://arnav1511.github.io/Kubernetes-admission-webhook/)

`k8s-policy-webhook` is a focused Kubernetes validating admission webhook written in Go. It intercepts Pod and Deployment create/update requests and rejects workloads that violate a small, configurable set of deployment policies.

This project is intentionally lightweight and educational. It can be useful for simple cluster policy demonstrations or focused enforcement, but it is not a complete replacement for mature policy engines such as Kyverno, OPA Gatekeeper, or ValidatingAdmissionPolicy in every production use case.

## Names

| Thing | Value |
| --- | --- |
| GitHub repository | `https://github.com/Arnav1511/Kubernetes-admission-webhook` |
| Go module | `github.com/Arnav1511/k8s-policy-webhook` |
| Application and binary | `k8s-policy-webhook` |
| Helm release examples | `k8s-policy-webhook` |
| GHCR image | `ghcr.io/arnav1511/k8s-policy-webhook` |

## Policies

| Policy | What it catches | Why it matters |
| --- | --- | --- |
| Block `:latest` and untagged images | Rejects `nginx`, `nginx:latest`, and malformed references | Encourages reproducible deployments |
| Allow digest-pinned images | Allows valid references such as `nginx@sha256:<digest>` | Supports immutable image pinning |
| Require resource limits | Rejects containers missing CPU or memory limits | Reduces noisy-neighbor risk |
| Require labels | Rejects pods missing labels such as `app` and `owner` | Improves ownership and observability |
| Block privilege escalation | Rejects privileged containers or `allowPrivilegeEscalation: true` | Hardens runtime posture |
| Block hostNetwork | Rejects pods using host networking | Reduces node network exposure |
| Block registries | Rejects images from configured registry prefixes | Helps enforce supply-chain policy |
| Max replica count | Caps Deployment replicas | Prevents accidental resource spikes |
| Exempt namespaces | Skips configured system namespaces | Avoids breaking cluster components |

## Local Quick Start

Prerequisites: Go 1.22 or newer. Docker, Helm, kubectl, OpenSSL, and Bash are needed for the full local verification and cluster workflow.

```bash
git clone https://github.com/Arnav1511/Kubernetes-admission-webhook.git
cd Kubernetes-admission-webhook

go test ./...
go build -o k8s-policy-webhook ./cmd/webhook

./hack/gen-certs.sh k8s-policy-webhook default certs
./k8s-policy-webhook \
  --cert=certs/tls.crt \
  --key=certs/tls.key \
  --config=deploy/policy.yaml \
  --port=8443
```

In another terminal:

```bash
curl -k https://localhost:8443/healthz
curl -k https://localhost:8443/readyz
```

## Helm Install

The chart supports two TLS modes. Use exactly one.

### Mode A: cert-manager

Use this mode when cert-manager is installed in the cluster and should issue the webhook serving certificate.

```bash
helm upgrade --install k8s-policy-webhook deploy/helm \
  --namespace k8s-policy-webhook \
  --create-namespace \
  --set certManager.enabled=true \
  --set image.tag=1.0.0
```

The chart renders an Issuer by default, a cert-manager Certificate, mounts the generated Secret, and annotates the ValidatingWebhookConfiguration with `cert-manager.io/inject-ca-from`.

### Mode B: externally provided certificate

Use this mode when you create the TLS Secret yourself. The CA bundle is required and must be base64 encoded.

```bash
./hack/gen-certs.sh k8s-policy-webhook k8s-policy-webhook certs

kubectl create namespace k8s-policy-webhook --dry-run=client -o yaml | kubectl apply -f -
kubectl -n k8s-policy-webhook create secret tls k8s-policy-webhook-tls \
  --cert=certs/tls.crt \
  --key=certs/tls.key \
  --dry-run=client -o yaml | kubectl apply -f -

CA_BUNDLE="$(base64 < certs/ca.crt | tr -d '\n')"

helm upgrade --install k8s-policy-webhook deploy/helm \
  --namespace k8s-policy-webhook \
  --set certManager.enabled=false \
  --set tls.existingSecretName=k8s-policy-webhook-tls \
  --set webhook.caBundle="${CA_BUNDLE}" \
  --set image.tag=1.0.0
```

## Verify The Webhook

```bash
kubectl -n k8s-policy-webhook get pods,svc
kubectl get validatingwebhookconfigurations k8s-policy-webhook
kubectl -n k8s-policy-webhook logs deploy/k8s-policy-webhook
```

Rejected example:

```bash
kubectl apply -f examples/bad-pod.yaml
```

Accepted example:

```bash
kubectl apply -f examples/good-pod.yaml
```

## Configuration

Edit `deploy/policy.yaml` for local runs or `policy` values in `deploy/helm/values.yaml` for Helm installs.

```yaml
blockLatestTag: true
requireResourceLimits: true
blockHostNetwork: true
requireLabels:
  - app
  - owner
blockedRegistries:
  - "untrusted.io/"
blockPrivilegeEscalation: true
maxReplicaCount: 50
exemptNamespaces:
  - kube-system
  - kube-public
  - kube-node-lease
```

## Development

```bash
make fmt
make test
make lint
make helm-lint
make docker-build
make verify
```

The Go policy behavior is covered by a table-driven test suite.

CI is defined in `.github/workflows/ci.yml` and runs Go formatting, vet, race-enabled tests, golangci-lint, Helm lint/rendering, Docker image builds, and Trivy scans. The badge at the top reflects the actual workflow result after GitHub Actions runs it.

### End-to-end tests

`hack/e2e.sh` installs the chart into a throwaway kind cluster and asserts admit/deny against a real API server, including the `pods/ephemeralcontainers` path. It runs in CI as the `Cluster E2E` job, and `publish-image` depends on it so an image that cannot deploy is never published. Run it locally with `hack/e2e.sh`, or `KEEP_CLUSTER=1 hack/e2e.sh` to leave the cluster up for debugging. It needs `kind`, `kubectl`, `helm`, `docker` and `openssl`.

`helm lint` and `helm template` only render YAML, so deployment-time faults are invisible to them. Run the e2e suite before releasing, and after any change to `deploy/helm`, the `Dockerfile`, or the webhook rules.

### Keeping the build green

The Trivy gates run with `ignore-unfixed`, so anything they report already has an upstream fix. Two automations apply those fixes:

- **`auto-remediate.yml`** (Mondays 05:00 UTC) bumps vulnerable Go modules, including indirect ones — the gap Dependabot does not cover, and where these gates usually break. It verifies the bump and re-scans before opening a PR.
- **`dependabot-auto-merge.yml`** enables auto-merge on Dependabot's patch and minor updates. Major bumps are left for a human.

Neither merges anything without the full CI suite passing.

> **One-time setup:** `auto-remediate.yml` needs a repository secret named `AUTOMATION_TOKEN` — a fine-grained PAT with `contents: read/write` and `pull requests: read/write` on this repository. A pull request opened with the default `GITHUB_TOKEN` does not start CI, so auto-merge would never fire and the PR would sit forever. Without the secret the workflow still opens the PR; it just has to be merged by hand.

## Troubleshooting

Empty `caBundle`: when `certManager.enabled=false`, set `webhook.caBundle` to the base64-encoded CA certificate that signed the webhook server certificate. Helm intentionally fails when this value is missing.

Certificate SAN mismatch: regenerate the certificate with the actual Service name and namespace: `./hack/gen-certs.sh k8s-policy-webhook k8s-policy-webhook certs`. The certificate must include `<service>`, `<service>.<namespace>`, `<service>.<namespace>.svc`, and `<service>.<namespace>.svc.cluster.local`.

Webhook timeout: check that the pod is Ready, the Service selects the pod, the API server can reach port 443, and any NetworkPolicy permits API server ingress.

`failurePolicy` behavior: the default is `Fail`, which blocks matching workload admission if the webhook is unreachable or returns an error. Use `--set webhook.failurePolicy=Ignore` only when availability is more important than strict enforcement.

Accidentally blocking system namespaces: keep critical namespaces in `policy.exemptNamespaces` and in `webhook.namespaceSelector`. Validate changes in a non-production cluster before widening enforcement.

## Interactive Walkthrough

The GitHub Pages walkthrough is preserved in `docs/index.html` and published at:

https://arnav1511.github.io/Kubernetes-admission-webhook/
