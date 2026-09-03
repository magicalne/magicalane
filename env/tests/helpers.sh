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
