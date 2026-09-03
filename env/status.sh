#!/usr/bin/env bash
# Inspect the magicalane test env: containers, networks, listeners, logs.
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
LABEL="magicalane.env=true"

echo "=== containers (label $LABEL) ==="
$CE ps -a --filter label="$LABEL" --format 'table {{.Names}}\t{{.Status}}\t{{.Networks}}'

echo
echo "=== networks ==="
$CE network ls | grep -E 'NAME|magicalane' || true

for c in magicalane-testsvc magicalane-server magicalane-client magicalane-tproxy-client; do
    if $CE ps --filter name="^$c$" --filter status=running -q | grep -q .; then
        echo
        echo "=== $c listeners ==="
        $CE exec "$c" sh -c 'ss -ltnp 2>/dev/null; ss -lunp 2>/dev/null' | grep -v '^State' || true
        echo "--- $c logs (tail 5) ---"
        $CE logs --tail 5 "$c" 2>&1 | tail -5
    fi
done

if $CE ps --filter name="^magicalane-tproxy-client$" --filter status=running -q | grep -q .; then
    echo
    echo "=== tproxy rules (inside magicalane-tproxy-client) ==="
    $CE exec magicalane-tproxy-client /usr/local/bin/tproxy-rules.sh show
    echo
    echo "=== app route ==="
    $CE exec magicalane-app ip route
fi
