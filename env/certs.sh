#!/usr/bin/env bash
# Generate test PKI for the magicalane env (idempotent).
#   env/certs/ca.pem           - test CA (mounted into the client as ca_path)
#   env/certs/server.pem/.key  - server cert, SAN: magicalane-server (+localhost)
#
# The client uses proxy.host as rustls SNI, so the SAN must match the
# server's network alias "magicalane-server" (src/quic/client.rs).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$DIR"

if [ -s "$DIR/ca.pem" ] && [ -s "$DIR/server.pem" ] && [ -s "$DIR/server.key" ]; then
    echo "certs already present in $DIR"
    exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$tmp/ca.key" -out "$DIR/ca.pem" \
    -days 3650 -subj "/CN=magicalane test CA" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/server.key" -out "$tmp/server.csr" \
    -subj "/CN=magicalane-server" >/dev/null 2>&1

printf 'subjectAltName=DNS:magicalane-server,DNS:localhost\n' > "$tmp/ext.cnf"

openssl x509 -req -in "$tmp/server.csr" \
    -CA "$DIR/ca.pem" -CAkey "$tmp/ca.key" -CAcreateserial \
    -out "$DIR/server.pem" -days 825 -extfile "$tmp/ext.cnf" >/dev/null 2>&1

openssl x509 -in "$DIR/server.pem" -noout -fingerprint -sha256 > "$DIR/fingerprint"
echo "certs generated in $DIR:"
sed 's/^/  /' "$DIR/fingerprint"
