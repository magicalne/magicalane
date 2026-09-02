#!/usr/bin/env bash
# Ensure env/fixtures are present (idempotent).
#   fixtures/hello.txt          - committed
#   fixtures/hostname           - written by the origin container at start
#   fixtures/generated/blob-10m.bin{,.sha256} - random integrity fixture
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fixtures"
GEN="$DIR/generated"
mkdir -p "$GEN"
BLOB="$GEN/blob-10m.bin"

if [ ! -s "$BLOB" ] || [ ! -s "$BLOB.sha256" ]; then
    dd if=/dev/urandom of="$BLOB" bs=1M count=10 status=none
    ( cd "$GEN" && sha256sum "$(basename "$BLOB")" > "$(basename "$BLOB").sha256" )
    echo "generated $BLOB"
fi
