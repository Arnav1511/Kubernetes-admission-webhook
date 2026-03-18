#!/bin/bash
# Generate self-signed TLS certificates for local webhook testing.
# In production, use cert-manager.

set -euo pipefail

OUTDIR="${1:-certs}"
mkdir -p "$OUTDIR"

echo "Generating CA..."
openssl genrsa -out "$OUTDIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$OUTDIR/ca.key" \
  -subj "/CN=webhook-ca" -days 365 -out "$OUTDIR/ca.crt"

echo "Generating server certificate..."
openssl genrsa -out "$OUTDIR/tls.key" 2048

cat > "$OUTDIR/csr.conf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = k8s-policy-webhook.default.svc

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = k8s-policy-webhook
DNS.2 = k8s-policy-webhook.default
DNS.3 = k8s-policy-webhook.default.svc
DNS.4 = k8s-policy-webhook.default.svc.cluster.local
DNS.5 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -key "$OUTDIR/tls.key" \
  -config "$OUTDIR/csr.conf" -out "$OUTDIR/tls.csr"

openssl x509 -req -in "$OUTDIR/tls.csr" \
  -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
  -out "$OUTDIR/tls.crt" -days 365 \
  -extfile "$OUTDIR/csr.conf" -extensions req_ext

rm "$OUTDIR/csr.conf" "$OUTDIR/tls.csr" "$OUTDIR/ca.srl" 2>/dev/null || true

echo "Certificates generated in $OUTDIR/"
echo "  CA:   $OUTDIR/ca.crt"
echo "  Cert: $OUTDIR/tls.crt"
echo "  Key:  $OUTDIR/tls.key"
