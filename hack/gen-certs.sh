#!/usr/bin/env bash
# Generate a local CA and webhook serving certificate for development clusters.

set -euo pipefail

SERVICE_NAME="${1:-k8s-policy-webhook}"
NAMESPACE="${2:-default}"
OUTDIR="${3:-certs}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd openssl
require_cmd base64

mkdir -p "$OUTDIR"

CA_KEY="$OUTDIR/ca.key"
CA_CERT="$OUTDIR/ca.crt"
SERVER_KEY="$OUTDIR/tls.key"
SERVER_CSR="$OUTDIR/tls.csr"
SERVER_CERT="$OUTDIR/tls.crt"
OPENSSL_CONF="$OUTDIR/openssl.cnf"
CA_SERIAL="$OUTDIR/ca.srl"

cat >"$OPENSSL_CONF" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = ${SERVICE_NAME}.${NAMESPACE}.svc

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
EOF

echo "Generating local certificate authority..."
openssl genrsa -out "$CA_KEY" 4096
openssl req -x509 -new -nodes -key "$CA_KEY" \
  -sha256 -days 3650 -subj "/CN=${SERVICE_NAME}-local-ca" -out "$CA_CERT"

echo "Generating webhook server key and CSR..."
openssl genrsa -out "$SERVER_KEY" 2048
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config "$OPENSSL_CONF"

echo "Signing webhook server certificate..."
openssl x509 -req -in "$SERVER_CSR" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -days 365 -sha256 \
  -extfile "$OPENSSL_CONF" -extensions req_ext

echo "Verifying certificate..."
openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"
openssl x509 -in "$SERVER_CERT" -noout -text | grep -A1 "Subject Alternative Name" >/dev/null

rm -f "$SERVER_CSR" "$OPENSSL_CONF" "$CA_SERIAL"

CA_BUNDLE="$(base64 <"$CA_CERT" | tr -d '\n')"

cat <<EOF

Certificates generated in: $OUTDIR
  CA certificate:     $CA_CERT
  CA private key:     $CA_KEY
  Server certificate: $SERVER_CERT
  Server private key: $SERVER_KEY

Create or update the Kubernetes TLS Secret:
  kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n ${NAMESPACE} create secret tls ${SERVICE_NAME}-tls \\
    --cert=${SERVER_CERT} \\
    --key=${SERVER_KEY} \\
    --dry-run=client -o yaml | kubectl apply -f -

Install with externally managed TLS:
  helm upgrade --install ${SERVICE_NAME} deploy/helm \\
    --namespace ${NAMESPACE} \\
    --set certManager.enabled=false \\
    --set tls.existingSecretName=${SERVICE_NAME}-tls \\
    --set webhook.caBundle=${CA_BUNDLE}

Do not commit files from $OUTDIR; they contain private key material.
EOF
