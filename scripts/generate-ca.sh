#!/bin/bash
set -e

# KProxy CA Generation Script
# Generates a root CA and intermediate CA for TLS interception

CA_DIR="${CA_DIR:-/etc/kproxy/ca}"
VALIDITY_DAYS="${VALIDITY_DAYS:-3650}"
COUNTRY="${COUNTRY:-US}"
STATE="${STATE:-California}"
LOCALITY="${LOCALITY:-San Francisco}"
ORG="${ORG:-KProxy}"

echo "==================================="
echo "KProxy CA Generation Script"
echo "==================================="
echo ""
echo "CA Directory: $CA_DIR"
echo "Validity: $VALIDITY_DAYS days"
echo ""

# Create CA directory
mkdir -p "$CA_DIR"
cd "$CA_DIR"

# Generate Root CA private key
echo "Generating Root CA private key..."
openssl ecparam -name prime256v1 -genkey -noout -out root-ca.key
chmod 600 root-ca.key

# Generate Root CA certificate
echo "Generating Root CA certificate..."
openssl req -new -x509 -sha256 \
  -key root-ca.key \
  -out root-ca.crt \
  -days "$VALIDITY_DAYS" \
  -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG/CN=KProxy Root CA"

# Generate Intermediate CA private key
echo "Generating Intermediate CA private key..."
openssl ecparam -name prime256v1 -genkey -noout -out intermediate-ca.key
chmod 600 intermediate-ca.key

# Generate Intermediate CA certificate request
echo "Generating Intermediate CA certificate request..."
openssl req -new -sha256 \
  -key intermediate-ca.key \
  -out intermediate-ca.csr \
  -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG/CN=KProxy Intermediate CA"

# Sign Intermediate CA certificate with Root CA
echo "Signing Intermediate CA certificate..."
cat > intermediate-ca.ext << EOF
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

openssl x509 -req -sha256 \
  -in intermediate-ca.csr \
  -CA root-ca.crt \
  -CAkey root-ca.key \
  -CAcreateserial \
  -out intermediate-ca.crt \
  -days "$VALIDITY_DAYS" \
  -extfile intermediate-ca.ext

# Clean up
rm intermediate-ca.csr intermediate-ca.ext

echo ""
echo "==================================="
echo "CA Generation Complete!"
echo "==================================="
echo ""
echo "Root CA Certificate: $CA_DIR/root-ca.crt"
echo "Root CA Key: $CA_DIR/root-ca.key"
echo "Intermediate CA Certificate: $CA_DIR/intermediate-ca.crt"
echo "Intermediate CA Key: $CA_DIR/intermediate-ca.key"
echo ""
echo "Next steps:"
echo "1. Install root-ca.crt on all client devices"
echo "2. Keep the private keys secure (600 permissions)"
echo "3. Update KProxy configuration to point to these files"
echo ""
echo "To install the root CA on clients:"
echo "  - Windows: certutil -addstore -user Root $CA_DIR/root-ca.crt"
echo "  - macOS: security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain $CA_DIR/root-ca.crt"
echo "  - Linux: sudo cp $CA_DIR/root-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
echo ""
