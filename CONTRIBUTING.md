# Contributing

Thanks for improving `k8s-policy-webhook`.

## Development Setup

1. Install Go 1.22 or newer.
2. Install optional local tools for full verification: Docker, Helm, Bash, and OpenSSL.
3. Run the local checks before opening a pull request:

```bash
go mod tidy
gofmt -w .
go vet ./...
go test -race ./...
./hack/verify.sh
```

## Pull Requests

- Keep changes focused.
- Add or update table-driven tests for policy behavior changes.
- Do not commit generated certificates, private keys, coverage files, or local build outputs.
- Update Helm values and README examples when user-visible deployment behavior changes.

## Certificate Handling

Use `hack/gen-certs.sh` only for local development or test clusters. Production clusters should normally use cert-manager or a certificate issued by your platform PKI.
