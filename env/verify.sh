#!/usr/bin/env bash
# Verification framework harness.
#
#   env/verify.sh                 # fast: smoke suite on quic
#   env/verify.sh full            # everything: all suites x transports + tproxy
#   env/verify.sh smoke           # one suite
#   env/verify.sh 008-tunnel-http-private   # one testcase (any transport it declares)
#   env/verify.sh regression      # regression suite only
#
# Testcases are env/tests/NNN-slug.sh with metadata headers:
#   # suites: smoke transport
#   # transports: quic kcp | any      (any = run once, transport-agnostic)
#   # isolated: no
# They source tests/helpers.sh and use assert_*/pass/fail. Output is TAP.
set -uo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
TESTS_DIR="$ENV_DIR/tests"
TEST_TIMEOUT="${TEST_TIMEOUT:-180}"

# ---------------------------------------------------------------- selectors
SELECTORS=("$@")
[ ${#SELECTORS[@]} -eq 0 ] && SELECTORS=(fast)

suite_alias() {
    case "$1" in
        fast) echo "smoke" ;;
        # tproxy tests imply the tproxy profile; smoke runs without it
        full) echo "smoke transport tproxy regression fakeip routing" ;;
        *) echo "$1" ;;
    esac
}

# ---------------------------------------------------------------- discovery
# testcase files sorted by number
tc_files() { ls "$TESTS_DIR"/[0-9]*-*.sh 2>/dev/null | sort; }

has_token() { # list token -> 0 if exact whitespace-separated token present
    [ -z "$2" ] && return 1
    case " $1 " in
        *" $2 "*) return 0 ;;
        *) return 1 ;;
    esac
}

tc_meta() { # file key -> space-separated values
    grep -m1 "^# $2:" "$1" 2>/dev/null | sed "s/^# $2://" | tr -d '\r'
}

tc_name() { basename "$1" .sh; }

# select testcases matching any selector (suite name or testcase name)
declare -a SELECTED=()
for f in $(tc_files); do
    name="$(tc_name "$f")"
    for sel in "${SELECTORS[@]}"; do
        for suite in $(suite_alias "$sel"); do
            if [ "$suite" = "$name" ] || has_token "$(tc_meta "$f" suites)" "$suite"; then
                SELECTED+=("$f")
                break 2
            fi
        done
        if [ "$sel" = "$name" ]; then
            SELECTED+=("$f")
            break
        fi
    done
done
# dedupe, preserving order
declare -a TESTS=()
declare -A seen=()
for f in "${SELECTED[@]}"; do
    [ -n "${seen[$f]:-}" ] && continue
    seen[$f]=1
    TESTS+=("$f")
done

if [ ${#TESTS[@]} -eq 0 ]; then
    echo "no testcases matched: ${SELECTORS[*]}" >&2
    exit 2
fi

# ---------------------------------------------------------------- env mgmt
current_transport() {
    $CE exec magicalane-client sh -c \
        'grep -o "protocol = \"[a-z-]*\"" /etc/magicalane/client.toml 2>/dev/null | cut -d\" -f2' \
        2>/dev/null || true
}
tproxy_up() { $CE ps --format '{{.Names}}' 2>/dev/null | grep -qx magicalane-app; }

ensure_env() { # transport tproxy(0|1)
    local want_t="$1" want_tp="$2" cur_tp
    cur_tp=0; tproxy_up && cur_tp=1
    if [ "$(current_transport)" = "$want_t" ] && [ "$cur_tp" = "$want_tp" ] \
        && $CE ps --format '{{.Names}}' | grep -qx magicalane-client; then
        return 0
    fi
    echo "# env: (re)deploying transport=$want_t tproxy=$want_tp" >&2
    "$ENV_DIR/down.sh" >/dev/null 2>&1
    local args=(--transport "$want_t")
    [ "$want_tp" = "1" ] && args+=(--profile tproxy)
    "$ENV_DIR/up.sh" "${args[@]}" >/dev/null 2>&1
}

fail_dump() {
    echo "  --- diagnostics ---" >&2
    for c in magicalane-client magicalane-server magicalane-tproxy-client; do
        $CE logs --tail 8 "$c" 2>/dev/null | sed "s/^/  [$c] /" >&2
    done
    echo "  --- end diagnostics ---" >&2
}

# ---------------------------------------------------------------- run phases
# Phase order minimizes env cycles:
#   1) quic, no tproxy: tests declaring quic (or any) that are NOT tproxy-suite
#   2) kcp, no tproxy: tests declaring kcp
#   3) tproxy profile (quic): tproxy-suite tests
run_test() { # file transport|any
    local f="$1" t="$2" start rc
    local label
    if [ "$t" = "any" ]; then label="$(tc_name "$f")"; else label="$(tc_name "$f") [$t]"; fi
    COUNT=$((COUNT + 1))
    start=$(date +%s%N)
    set +e
    out=$(TEST_TRANSPORT="$t" TESTS_DIR="$TESTS_DIR" timeout "$TEST_TIMEOUT" bash "$f" 2>&1)
    rc=$?
    set -e 2>/dev/null || true
    local dur=$(( ($(date +%s%N) - start) / 1000000 ))
    if [ $rc -eq 0 ]; then
        echo "ok $COUNT - $label (${dur}ms)"
    elif [ $rc -eq 124 ]; then
        echo "not ok $COUNT - $label (timeout ${TEST_TIMEOUT}s)"
        echo "$out" | sed 's/^/  # /'
        fail_dump
        FAILED=$((FAILED + 1))
    else
        echo "not ok $COUNT - $label (${dur}ms)"
        echo "$out" | sed 's/^/  # /'
        fail_dump
        FAILED=$((FAILED + 1))
    fi
}

COUNT=0
FAILED=0
START=$(date +%s)

declare -a phase1=() phase2=() phase3=()
for f in "${TESTS[@]}"; do
    suites="$(tc_meta "$f" suites)"
    transports="$(tc_meta "$f" transports)"
    [ -z "$transports" ] && transports="any"
    if has_token "$suites" tproxy; then
        phase3+=("$f")
        continue
    fi
    if has_token "$transports" quic || has_token "$transports" any; then
        phase1+=("$f")
    fi
    if has_token "$transports" kcp; then
        phase2+=("$f")
    fi
done

run_phase() { # file-array-name transport_label mode
    local -a files=("${!1}")
    [ ${#files[@]} -eq 0 ] && return 0
    local f t
    for f in "${files[@]}"; do
        transports="$(tc_meta "$f" transports)"
        [ -z "$transports" ] && transports="any"
        if [ "$3" = "tproxy" ]; then
            run_test "$f" "any"
        elif has_token "$transports" "$2"; then
            run_test "$f" "$2"
        fi
    done
}

if [ ${#phase1[@]} -gt 0 ]; then
    ensure_env quic 0
    run_phase phase1[@] quic plain
fi
if [ ${#phase2[@]} -gt 0 ]; then
    ensure_env kcp 0
    run_phase phase2[@] kcp plain
fi
if [ ${#phase3[@]} -gt 0 ]; then
    ensure_env quic 1
    run_phase phase3[@] quic tproxy
fi

# ---------------------------------------------------------------- summary
DURATION=$(( $(date +%s) - START ))
echo
echo "# tests: $COUNT  failed: $FAILED  (${DURATION}s)"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
