# Changelog

## Unreleased

- Added GitHub Actions CI with Go, Helm, Docker build, and Trivy checks.
- Added Dependabot configuration, golangci-lint configuration, and local Make targets.
- Replaced fragile image tag parsing with a Docker/OCI image reference parser.
- Added `/readyz` alongside `/healthz`.
- Added explicit Helm TLS modes for cert-manager and externally provided certificates.
- Hardened the Helm Deployment with pod/container security context, probes, PDB, topology spread preference, service account, config checksum, and optional NetworkPolicy.
- Reworked local certificate generation for service DNS SANs.
- Added project documentation, examples, license, contribution, and security files.
