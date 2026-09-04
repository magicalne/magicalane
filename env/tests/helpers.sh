#!/usr/bin/env bash
# Shared helpers for testcases (sourced by each env/tests/NNN-*.sh).
# The harness exports: TEST_TRANSPORT (quic|kcp|any), TESTS_DIR.
# A testcase passes by exiting 0 and fails via `fail` / assert_* helpers.

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
SOCKS="127.0.0.1:1080"
export ENV_DIR CE SOCKS

pass() { echo "  ok: $*" >&2; }

fail() {
    echo "  FAIL: $*" >&2
    exit 1
}

assert_eq() { # actual expected msg
    [ "$1" = "$2" ] || fail "$3 (got '$1', want '$2')"
    pass "$3"
}

assert_contains() { # haystack needle msg
    grep -qF "$2" <<<"$1" || fail "$3 (missing '$2')"
    pass "$3"
}

must_fail() { # cmd... -- must exit non-zero
    local desc="${1:-command}"
    shift 2>/dev/null || true
    if "$@" >/dev/null 2>&1; then
        fail "$desc unexpectedly succeeded"
    fi
    pass "$desc fails as expected"
}

# exec helpers: _c(lient) _s(erver) _a(pp)
exec_c() { $CE exec magicalane-client "$@"; }
exec_s() { $CE exec magicalane-server "$@"; }
exec_a() { $CE exec magicalane-app "$@"; }

curl_socks() { # curl args after --socks5-hostname SOCKS
    exec_c curl -fsS --max-time 15 --socks5-hostname "$SOCKS" "$@"
}
curl_direct() { exec_c curl -sS --max-time 5 "$@"; }

fixture() { cat "$ENV_DIR/fixtures/$1"; }

testsvc_id() { curl_socks http://testsvc:8080/id; }

wait_container_port() { # container tcp-port
    for _ in $(seq 1 30); do
        if $CE exec "$1" sh -c "ss -ltn | grep -q ':$2 '" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    fail "timeout waiting for $1:$2"
}

# ------------------------------------------------------- workstation (ws) mode
# A second client instance with transparent interception enabled runs in
# the client container; lifecycle helpers manage it for testcases.

WS_CFG="/etc/magicalane/client-ws.toml"

ws_running() {
    [ "$($CE exec magicalane-client /usr/local/bin/ws-daemon.sh status 2>/dev/null)" = "running" ]
}

# Start the ws client with a specific config (e.g. fakeip profile).
ws_start_cfg() {
    local cfg="$1"
    if ws_running; then return 0; fi
    $CE exec magicalane-client /usr/local/bin/ws-daemon.sh start "$cfg"
    # Wait for listeners AND the nat rules: the listener binds before
    # the rules apply, and a racing query would leak past the interceptor.
    for _ in $(seq 1 40); do
        if $CE exec magicalane-client sh -c "ss -ltn | grep -q ':7897 ' && iptables -t nat -n -L MGL-NAT >/dev/null 2>&1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    fail "ws fakeip client did not become ready"
}

ws_start() {
    if ws_running; then return 0; fi
    $CE exec magicalane-client /usr/local/bin/ws-daemon.sh start
    for _ in $(seq 1 40); do
        if $CE exec magicalane-client sh -c "iptables -t nat -n -L MGL-NAT >/dev/null 2>&1 && ss -ltn | grep -q ':7895 '" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    fail "ws client did not become ready"
}

ws_stop() { # signal (default TERM)
    local sig="${1:-TERM}"
    if [ "$sig" = "KILL" ]; then
        PID=$($CE exec magicalane-client cat /tmp/ws-client.pid 2>/dev/null | tr -d '[:space:]')
        [ -n "$PID" ] && $CE exec magicalane-client kill -9 "$PID" 2>/dev/null
        $CE exec magicalane-client rm -f /tmp/ws-client.pid 2>/dev/null
    else
        $CE exec magicalane-client /usr/local/bin/ws-daemon.sh stop
    fi
    for _ in $(seq 1 20); do
        ws_running || return 0
        sleep 0.3
    done
    fail "ws client did not stop"
}

ws_wait_gone() {
    for _ in $(seq 1 20); do
        ws_running || return 0
        sleep 0.3
    done
    fail "ws client still running"
}

# Wait for iptables chains to be fully removed (teardown is async:
# the daemon stop returns before the process finishes cleaning up).
ws_wait_clean() {
    for _ in $(seq 1 20); do
        ws_rules_present || return 0
        sleep 0.3
    done
    fail "iptables chains still present after teardown"
}

# Network-state snapshot of the client container (mangle table + ip rule +
# table 141). Byte-comparable before/after = clean-exit contract holds.
ws_snapshot() {
    $CE exec magicalane-client sh -c '
        iptables-save 2>/dev/null | grep -v "^#" | sort
        echo "--- rules ---"
        ip rule list 2>/dev/null
        echo "--- table141 ---"
        ip route show table 141 2>/dev/null
    '
}

ws_rules_present() {
    $CE exec magicalane-client sh -c "iptables -t mangle -n -L MGL-OUT >/dev/null 2>&1"
}

# Snapshot only MGL-related iptables chains (the clean-exit contract is
# about OUR chains, not the presence of empty tables).
ws_snapshot_chains() {
    $CE exec magicalane-client sh -c '
        iptables-save 2>/dev/null | grep -E "^:.*-|^-[A-Z]" | grep -iE "MGL|mangle.*-A" || true
    '
}

ws_snapshot_rules() {
    $CE exec magicalane-client sh -c '
        ip rule list 2>/dev/null | grep -E "fwmark|141" || true
        ip route show table 141 2>/dev/null || true
    '
}
