#!/usr/bin/env bash
# Tear down the magicalane test network. Removes every container labeled
# magicalane.env=true and the test networks. Idempotent.
#
#   env/down.sh          - remove containers + networks (keep image/certs)
#   env/down.sh --purge  - also remove the image, certs and generated fixtures
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
LABEL="magicalane.env=true"

say() { echo "[down] $*"; }

ids="$($CE ps -aq --filter label="$LABEL" 2>/dev/null || true)"
if [ -n "$ids" ]; then
    $CE rm -f $ids >/dev/null
    say "removed containers: $(echo "$ids" | wc -l)"
else
    say "no labeled containers"
fi

for net in magicalane-net magicalane-lan; do
    if $CE network exists "$net" 2>/dev/null; then
        $CE network rm "$net" >/dev/null
        say "removed network $net"
    fi
done

if [ "${1:-}" = "--purge" ]; then
    $CE rmi -f magicalane:env >/dev/null 2>&1 || true
    rm -rf "$ENV_DIR/certs" "$ENV_DIR/fixtures/generated" "$ENV_DIR/.build"
    say "purged image, certs, generated fixtures"
fi

say "clean"
