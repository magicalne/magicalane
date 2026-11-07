#!/usr/bin/env bash
# Memory soak harness (issue #29): drives churn-heavy stream load
# against the REAL server binary on host loopback and samples its RSS
# per batch. No containers, no tproxy — plain client -> transport ->
# server -> echo origin, matching production topology.
#
#   env/soak.sh                                # stream churn, quic+kcp+tcp
#   env/soak.sh --transports quic              # one transport
#   env/soak.sh --mode conn                    # client restarted every batch
#                                              #   (server-side connection churn)
#   env/soak.sh --mode idle                    # no load; allocator drift baseline
#   env/soak.sh --batches 20 --batch-size 500 --concurrency 4
#   env/soak.sh --abandon 0.5 --unreachable 0.2 # error-path teardown churn
#   env/soak.sh --max-mb-h 5                   # exit 1 if slope exceeds threshold
#
# Prints per-batch samples (from magabench churn) and a per-transport
# slope table; saves the run under env/soak-results/ (gitignored).
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# MGL_SOAK_PORT_BASE offsets every port AND isolates the work dir
# (parallel soaks / regression runs alongside a long soak in flight).
BASE="${MGL_SOAK_PORT_BASE:-0}"
WORK="$ENV_DIR/soak$([ "$BASE" = 0 ] || echo "-base$BASE")"
RESULTS="$ENV_DIR/soak-results"
CERTS="$ENV_DIR/certs"
ECHO_PORT=$((19807 + BASE))

TRANSPORTS="quic kcp tcp"
MODE="stream"
BATCHES=12
BATCH_SIZE=300
CONCURRENCY=1
SETTLE=2
ABANDON=0.0
UNREACHABLE=0.0
MAX_MB_H=""
PROFILE="${MGL_SOAK_PROFILE:-release}"
while [ $# -gt 0 ]; do
    case "$1" in
        --transports) TRANSPORTS="${2//,/ }"; shift ;;
        --mode) MODE="$2"; shift ;;
        --batches) BATCHES="$2"; shift ;;
        --batch-size) BATCH_SIZE="$2"; shift ;;
        --concurrency) CONCURRENCY="$2"; shift ;;
        --settle) SETTLE="$2"; shift ;;
        --abandon) ABANDON="$2"; shift ;;
        --unreachable) UNREACHABLE="$2"; shift ;;
        --max-mb-h) MAX_MB_H="$2"; shift ;;
        --debug) PROFILE="debug"; ;;
        *) echo "usage: env/soak.sh [--transports quic,kcp,tcp] [--mode stream|conn|idle] \
[--batches N] [--batch-size N] [--concurrency N] [--settle S] [--abandon 0..1] [--unreachable 0..1] \
[--max-mb-h MB] [--debug]" >&2; exit 2 ;;
    esac
    shift
done

say() { echo "[soak] $*" >&2; }

BIN="target/$PROFILE"
if [ "$PROFILE" = release ]; then
    cargo build --release --bins >/dev/null
else
    cargo build --bins >/dev/null
fi

"$ENV_DIR/certs.sh" >/dev/null   # env/certs: ca.pem + server.pem/.key (SAN localhost)

mkdir -p "$WORK" "$RESULTS"

# Kill stale processes from a previous soak (never touches other
# magicalane instances: match the soak config paths only).
for pid in $(pgrep -f "$WORK/(server|client)-.*\\.toml" 2>/dev/null || true) \
           $(pgrep -f "magabench echo --listen 127.0.0.1:$ECHO_PORT" 2>/dev/null || true); do
    kill "$pid" >/dev/null 2>&1 || true
done
sleep 0.5

# Ports per transport (distinct so a leaked process fails loudly).
port_of() {
    case "$1" in
        quic) echo $((14433 + BASE)) ;;
        kcp)  echo $((14435 + BASE)) ;;
        tcp)  echo $((14437 + BASE)) ;;
    esac
}
socks_of() {
    case "$1" in
        quic) echo $((11080 + BASE)) ;;
        kcp)  echo $((11081 + BASE)) ;;
        tcp)  echo $((11082 + BASE)) ;;
    esac
}

PIDS=()
cleanup() {
    [ -n "${MGL_SOAK_KEEP:-}" ] && return 0
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    for pid in "${PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

wait_port() { # host port -> blocks until TCP-connectable
    local host="$1" port="$2"
    for _ in $(seq 1 200); do
        if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
            exec 3>&- 3<&- || true
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Server readiness: wait for the transport's bind log line (quic is
# UDP — no TCP probe possible).
wait_server() { # log-file transport
    local log="$1" t="$2" pat=""
    case "$t" in
        quic) pat="Server bind" ;;
        kcp)  pat="KCP server bind" ;;
        tcp)  pat="tcp-transport server listening" ;;
    esac
    for _ in $(seq 1 200); do
        grep -q "$pat" "$log" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

start_server() { # transport -> echoes pid
    local t="$1" port
    port="$(port_of "$t")"
    cat >"$WORK/server-$t.toml" <<EOF
password = "soak-password"
bandwidth = 65536
verbose = false
kind = { Server = { port = $port, protocol = "$t", ca = "$CERTS/server.pem", key = "$CERTS/server.key", tls = true } }
EOF
    # Fast KCP idle reaping: sessions awaiting idle-timeout teardown
    # would otherwise pile up for the production 120s window and blur
    # the slope (test hook, src/kcp/session.rs).
    # MALLOC_ARENA_MAX / MALLOC_TOP_PAD_ pass through for allocator A/B
    # experiments (issue #29 root-causing). MGL_SOAK_SERVER_CPUS pins
    # the server with taskset to emulate small production instances
    # (worker/arena count scales with visible CPUs).
    MAGICALANE_TEST_KCP_IDLE_SECS="${MGL_SOAK_KCP_IDLE_SECS:-10}" \
    RUST_LOG=info ${MGL_SOAK_SERVER_CPUS:+taskset -c "$MGL_SOAK_SERVER_CPUS"} \
        "$BIN/magicalane" --config "$WORK/server-$t.toml" \
        >"$WORK/server-$t.log" 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    echo "$pid" >"$WORK/server-$t.pid"
    echo "$pid"
}

start_client() { # transport -> echoes pid
    local t="$1" port socks
    port="$(port_of "$t")"
    socks="$(socks_of "$t")"
    cat >"$WORK/client-$t.toml" <<EOF
password = "soak-password"
bandwidth = 65536
verbose = false
kind = { Client = { proxy = { host = "localhost", port = $port, ca_path = "$CERTS/ca.pem", protocol = "$t" }, socks5_port = $socks, tproxy = { tcp_port = 7895, udp_port = 7896 } } }
EOF
    RUST_LOG=warn "$BIN/magicalane" --config "$WORK/client-$t.toml" \
        >"$WORK/client-$t.log" 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    echo "$pid"
}

stop_pid() {
    kill "$1" >/dev/null 2>&1 || true
    wait "$1" 2>/dev/null || true
}

# slope_mb_h <pairs-file> <wall-secs>: least-squares RSS slope from
# magabench pairs output, converted to MB/h using the wall seconds over
# the sampled batches. Skips the first 2 samples (warmup). Prints
# "<MB/h> <MB/batch> <first MB> <last MB>".
slope_mb_h() {
    awk -v wall="$2" '
        /^batch=/ {
            b = ""; rkb = ""
            for (i = 1; i <= NF; i++) {
                split($i, kv, "=")
                if (kv[1] == "batch") b = kv[2] + 0
                if (kv[1] == "rss_kb") rkb = kv[2] + 0
            }
            if (b != "" && rkb != "") { n++; batch[n] = b; rvec[n] = rkb }
        }
        END {
            start = (n > 3 ? 3 : 1)   # skip 2 warmup samples when possible
            m = 0
            for (i = start; i <= n; i++) { m++; x[m] = batch[i]; y[m] = rvec[i] }
            if (m < 2 || wall <= 0) { print "0.000 0.000 0 0"; exit }
            sx = 0; sy = 0
            for (i = 1; i <= m; i++) { sx += x[i]; sy += y[i] }
            mx = sx / m; my = sy / m
            num = 0; den = 0
            for (i = 1; i <= m; i++) { num += (x[i]-mx)*(y[i]-my); den += (x[i]-mx)^2 }
            if (den == 0) { print "0.000 0.000 0 0"; exit }
            sl = num / den                       # kb per batch-index step
            span = x[m] - x[1]
            batches_per_sec = (span > 0) ? span / wall : 0
            printf "%.3f %.3f %d %d\n", sl / 1024 * batches_per_sec * 3600, sl / 1024, y[1] / 1024, y[m] / 1024
        }' "$1"
}

run_stream() { # transport -> pairs-file
    local t="$1" socks="$2" spid="$3" out="$4"
    local target="${MGL_SOAK_TARGET:-127.0.0.1:$ECHO_PORT}"
    local magic=()
    case "${MGL_SOAK_MAGIC:-}" in
        udp) magic=(--udp-magic) ;;
        dns) magic=(--dns-magic) ;;
    esac
    "$BIN/magabench" churn --socks "127.0.0.1:$socks" --target "$target" \
        --batches "$BATCHES" --batch-size "$BATCH_SIZE" --concurrency "$CONCURRENCY" \
        --settle "$SETTLE" --sample-pid "$spid" --abandon "$ABANDON" --unreachable "$UNREACHABLE" \
        "${magic[@]}" --pairs | tee "$out" | grep '^batch=' >&2
}

run_conn() { # transport -> pairs-file (client restarted between batches)
    local t="$1" socks="$2" spid="$3" out="$4" cpid=""
    local target="${MGL_SOAK_TARGET:-127.0.0.1:$ECHO_PORT}"
    local magic=()
    case "${MGL_SOAK_MAGIC:-}" in
        udp) magic=(--udp-magic) ;;
        dns) magic=(--dns-magic) ;;
    esac
    : >"$out"
    for b in $(seq 0 $((BATCHES - 1))); do
        # fresh client == fresh tunnel connection server-side
        [ -n "$cpid" ] && stop_pid "$cpid"
        cpid="$(start_client "$t")"
        wait_port 127.0.0.1 "$socks" || { say "client failed to listen"; return 1; }
        "$BIN/magabench" churn --socks "127.0.0.1:$socks" --target "$target" \
            --batches 1 --batch-size "$BATCH_SIZE" --concurrency "$CONCURRENCY" \
            --settle "$SETTLE" --sample-pid "$spid" --abandon "$ABANDON" --unreachable "$UNREACHABLE" \
            "${magic[@]}" --pairs | grep '^batch=' | sed "s/^batch=0/batch=$b/" | tee -a "$out" >&2
    done
    [ -n "$cpid" ] && stop_pid "$cpid"
}

run_idle() { # transport -> pairs-file (no load; drift baseline)
    local t="$1" spid="$2" out="$3"
    : >"$out"
    for b in $(seq 0 $((BATCHES - 1))); do
        sleep "$SETTLE"
        awk -v b="$b" -v pid="$spid" 'BEGIN {
            rss = 0; fd = 0; thr = 0
            while ((getline line < ("/proc/" pid "/status")) > 0) {
                if (line ~ /^VmRSS:/) { split(line, f, " "); rss = f[2] }
                if (line ~ /^Threads:/) { split(line, f, " "); thr = f[2] }
            }
            close("/proc/" pid "/status")
            cmd = "ls /proc/" pid "/fd 2>/dev/null | wc -l"
            cmd | getline fd; close(cmd)
            printf "batch=%d rss_kb=%d fd=%d thr=%d ok=0 err=0 wall_ms=0\n", b, rss, fd, thr
        }' | tee -a "$out" >&2
    done
}

# ---------------------------------------------------------------- echo origin
"$BIN/magabench" echo --listen "127.0.0.1:$ECHO_PORT" >"$WORK/echo.log" 2>&1 &
ECHO_PID=$!
PIDS+=("$ECHO_PID")
wait_port 127.0.0.1 "$ECHO_PORT"

declare -a SUMMARY_T=() SUMMARY_SLOPE=() SUMMARY_MB=() SUMMARY_FD=() SUMMARY_THR=()
declare -i FAIL=0

for t in $TRANSPORTS; do
    say "=== transport $t (mode=$MODE batches=$BATCHES size=$BATCH_SIZE conc=$CONCURRENCY settle=${SETTLE}s)"
    spid="$(start_server "$t")"
    wait_server "$WORK/server-$t.log" "$t" || { say "server $t failed to listen"; tail "$WORK/server-$t.log" >&2; exit 1; }

    out="$WORK/pairs-$t.txt"
    wall0=$SECONDS
    case "$MODE" in
        stream)
            cpid="$(start_client "$t")"
            wait_port 127.0.0.1 "$(socks_of "$t")" || { say "client $t failed"; exit 1; }
            run_stream "$t" "$(socks_of "$t")" "$spid" "$out"
            stop_pid "$cpid"
            ;;
        conn)   run_conn "$t" "$(socks_of "$t")" "$spid" "$out" ;;
        idle)   run_idle "$t" "$spid" "$out" ;;
    esac
    wall=$((SECONDS - wall0))

    read -r mb_h mb_batch first_mb last_mb <<<"$(slope_mb_h "$out" "$wall")"
    fd_first=$(grep -oE 'fd=[0-9]+' "$out" | head -1 | cut -d= -f2)
    fd_last=$(grep -oE 'fd=[0-9]+' "$out" | tail -1 | cut -d= -f2)
    thr_first=$(grep -oE 'thr=[0-9]+' "$out" | head -1 | cut -d= -f2)
    thr_last=$(grep -oE 'thr=[0-9]+' "$out" | tail -1 | cut -d= -f2)

    SUMMARY_T+=("$t"); SUMMARY_SLOPE+=("$mb_h"); SUMMARY_MB+=("$first_mb -> $last_mb")
    SUMMARY_FD+=("$fd_first -> $fd_last"); SUMMARY_THR+=("$thr_first -> $thr_last")

    if [ -n "$MAX_MB_H" ]; then
        over=$(awk -v a="$mb_h" -v b="$MAX_MB_H" 'BEGIN { print (a > b) ? 1 : 0 }')
        if [ "$over" = 1 ]; then
            say "FAIL: $t slope ${mb_h} MB/h exceeds threshold ${MAX_MB_H} MB/h"
            FAIL=1
        else
            say "ok: $t slope ${mb_h} MB/h <= ${MAX_MB_H} MB/h"
        fi
    fi

    [ -z "${MGL_SOAK_KEEP:-}" ] && stop_pid "$spid"
done

say "================ soak summary ($MODE, ${BATCHES}x${BATCH_SIZE} @ conc $CONCURRENCY)"
printf '%-8s %14s %18s %12s %12s\n' transport 'slope(MB/h)' 'rss(MB)' 'fd' 'threads' >&2
for i in "${!SUMMARY_T[@]}"; do
    printf '%-8s %14s %18s %12s %12s\n' \
        "${SUMMARY_T[$i]}" "${SUMMARY_SLOPE[$i]}" "${SUMMARY_MB[$i]}" \
        "${SUMMARY_FD[$i]}" "${SUMMARY_THR[$i]}" >&2
done

ts=$(date +%Y%m%d-%H%M%S)
summary_file="$RESULTS/soak-$MODE-$ts.txt"
{
    echo "# mode=$MODE batches=$BATCHES batch_size=$BATCH_SIZE conc=$CONCURRENCY settle=$SETTLE abandon=$ABANDON unreachable=$UNREACHABLE profile=$PROFILE"
    echo "# commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    for i in "${!SUMMARY_T[@]}"; do
        printf '%s slope_mb_h=%s rss_mb="%s" fd="%s" thr="%s"\n' \
            "${SUMMARY_T[$i]}" "${SUMMARY_SLOPE[$i]}" "${SUMMARY_MB[$i]}" \
            "${SUMMARY_FD[$i]}" "${SUMMARY_THR[$i]}"
    done
} | tee "$summary_file" >&2
say "saved: $summary_file"

exit $FAIL
