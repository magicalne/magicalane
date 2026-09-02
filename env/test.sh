#!/usr/bin/env bash
# Verification suite for the magicalane test env. Run env/up.sh first;
# the tproxy section auto-detects the tproxy profile.
set -Eeuo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
SOCKS="127.0.0.1:1080"
PASS_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo "PASS: $*"; }

fail_dump() {
    echo "FAIL: $*" >&2
    echo "--- server logs (tail) ---" >&2
    $CE logs --tail 20 magicalane-server 2>/dev/null >&2 || true
    echo "--- client logs (tail) ---" >&2
    $CE logs --tail 20 magicalane-client 2>/dev/null >&2 || true
    echo "--- tproxy-client logs (tail) ---" >&2
    $CE logs --tail 20 magicalane-tproxy-client 2>/dev/null >&2 || true
    exit 1
}
trap 'fail_dump "unexpected failure at line $LINENO"' ERR

need() { $CE ps --format '{{.Names}}' | grep -qx "$1" \
    || fail_dump "$1 is not running (did you run env/up.sh?)"; }

# ------------------------------------------------------------------ preflight
need magicalane-origin
need magicalane-server
need magicalane-client
TRANSPORT="$($CE exec magicalane-client sh -c 'grep -o "protocol = \"[a-z]*\"" /etc/magicalane/client.toml 2>/dev/null | cut -d\" -f2' 2>/dev/null || true)"
[ -n "$TRANSPORT" ] || TRANSPORT="quic"
echo "transport under test: $TRANSPORT"
CURL="curl -fsS --max-time 15 --socks5-hostname $SOCKS"

# T1: happy path - SOCKS5 -> QUIC -> server -> origin, exact content
$CE exec magicalane-client sh -c "curl -fsS --max-time 15 --socks5-hostname $SOCKS http://origin/fixtures/hello.txt" \
    | diff - "$ENV_DIR/fixtures/hello.txt" >/dev/null \
    || fail_dump "T1 content mismatch"
pass "T1 happy path: proxied fetch matches fixture"

# T2: origin identity - egress must be the server container's view
fetched="$($CE exec magicalane-client sh -c "curl -fsS --max-time 15 --socks5-hostname $SOCKS http://origin/fixtures/hostname")" \
    || fail_dump "T2 fetch hostname failed"
origin_host="$($CE exec magicalane-origin cat /etc/hostname)"
[ "$fetched" = "$origin_host" ] || fail_dump "T2 egress hostname mismatch: '$fetched' != '$origin_host'"
pass "T2 egress identity: connection left from server side"

# T3: integrity - 10MB blob, sha256 must match
expected="$(cut -d' ' -f1 "$ENV_DIR/fixtures/generated/blob-10m.bin.sha256")"
got="$($CE exec magicalane-client sh -c "curl -fsS --max-time 60 --socks5-hostname $SOCKS -o /tmp/blob http://origin/fixtures/generated/blob-10m.bin && sha256sum /tmp/blob | cut -d' ' -f1")" \
    || fail_dump "T3 blob fetch failed"
[ "$got" = "$expected" ] || fail_dump "T3 blob sha mismatch: $got != $expected"
pass "T3 integrity: 10MB blob sha256 matches"

# T4: concurrency - 20 parallel fetches
$CE exec magicalane-client sh -c "seq 1 20 | xargs -P20 -I{} curl -fsS --max-time 30 --socks5-hostname $SOCKS http://origin/fixtures/hello.txt -o /dev/null" \
    || fail_dump "T4 parallel fetches failed"
pass "T4 concurrency: 20 parallel proxied fetches"

# T5: wrong password must be rejected (bounded, no hang)
$CE run -d --rm --name magicalane-client-badpw --label magicalane.env=true \
    --network magicalane-net \
    -v "$ENV_DIR/configs/client-$TRANSPORT-badpw.toml:/etc/magicalane/client.toml:ro" \
    -v "$ENV_DIR/certs:/etc/magicalane/certs:ro" \
    magicalane:env magicalane --config /etc/magicalane/client.toml >/dev/null
trap '$CE rm -f magicalane-client-badpw >/dev/null 2>&1 || true; fail_dump "unexpected failure at line $LINENO"' ERR
for _ in $(seq 1 30); do
    $CE exec magicalane-client-badpw sh -c "ss -ltn | grep -q ':1080'" 2>/dev/null && break
    sleep 0.5
done
if $CE exec magicalane-client-badpw sh -c "curl -fsS --max-time 5 --socks5-hostname $SOCKS http://origin/fixtures/hello.txt" >/dev/null 2>&1; then
    fail_dump "T5 wrong password was ACCEPTED"
fi
pass "T5 auth: wrong password rejected within 5s"
$CE rm -f magicalane-client-badpw >/dev/null
trap 'fail_dump "unexpected failure at line $LINENO"' ERR

# T6: unreachable destination -> proper SOCKS error, no hang
if $CE exec magicalane-client sh -c "curl -fsS --max-time 6 --socks5-hostname $SOCKS http://192.0.2.1:1/" >/dev/null 2>&1; then
    fail_dump "T6 unreachable destination unexpectedly succeeded"
fi
pass "T6 negative: unreachable destination fails fast"

# T7: host isolation - nothing bound on host, nothing reachable
if ss -ltn 2>/dev/null | grep -qE ':(1080|4433)\b'; then
    fail_dump "T7 host has a listener on 1080/4433"
fi
if curl -fsS --max-time 2 --socks5-hostname 127.0.0.1:1080 http://origin/ >/dev/null 2>&1; then
    fail_dump "T7 host could reach the client socks port"
fi
pass "T7 isolation: no host listeners, no host reachability"

# T8: tproxy profile (auto-detected)
if $CE ps --format '{{.Names}}' | grep -qx magicalane-app; then
    if $CE exec magicalane-app env | grep -qi proxy; then
        fail_dump "T8 app container must not have proxy env vars"
    fi
    fetched="$($CE exec magicalane-app curl -fsS --max-time 10 http://origin/fixtures/hello.txt)" \
        || fail_dump "T8 transparent fetch failed"
    [ "$fetched" = "$(cat "$ENV_DIR/fixtures/hello.txt")" ] || fail_dump "T8 content mismatch"
    pass "T8 tproxy: transparent fetch with zero proxy configuration"

    fetched="$($CE exec magicalane-app curl -fsS --max-time 10 http://origin/fixtures/hostname)" \
        || fail_dump "T8b transparent hostname fetch failed"
    [ "$fetched" = "$origin_host" ] || fail_dump "T8b egress hostname mismatch"
    pass "T8b tproxy: egress identity correct"
else
    echo "SKIP: T8 tproxy (profile not up; use env/up.sh --profile tproxy)"
fi

# T9: host firewall untouched by tproxy rules (needs passwordless sudo)
if sudo -n true 2>/dev/null; then
    if sudo -n nft list ruleset 2>/dev/null | grep -i 'tproxy'; then
        fail_dump "T9 host nft ruleset contains tproxy rules"
    fi
    pass "T9 host firewall: no tproxy rules on host"
else
    echo "SKIP: T9 host firewall check (no passwordless sudo)"
fi

echo "OK: $PASS_COUNT checks passed"
