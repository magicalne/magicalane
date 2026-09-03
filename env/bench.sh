#!/usr/bin/env bash
# Benchmark the transports end-to-end through the test env:
#   bench client (exec'd in magicalane-client) -> socks5 -> transport -> server -> echo origin
#
#   env/bench.sh                          # quic vs kcp, no network emulation
#   env/bench.sh --transports quic,kcp,kcp-plain
#   env/bench.sh --delay 40 --loss 2      # add netem (40ms, 2% loss) on the server
#   env/bench.sh --pings 200              # pass-through knobs (see magabench run --help)
#
# Results print to stdout and are saved under env/bench-results/ (gitignored).
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
LABEL="magicalane.env=true"
ECHO_NAME="magicalane-bench-echo"
ECHO_PORT="9807"

TRANSPORTS="quic kcp"
MATRIX=""
DELAY=""
LOSS=""
BADNET=""
BADNET_AQM="fifo"
declare -a EXTRA=()
while [ $# -gt 0 ]; do
    case "$1" in
        --transports) TRANSPORTS="${2//,/ }"; shift ;;
        --matrix) MATRIX="1" ;;
        --delay) DELAY="$2"; shift ;;
        --loss) LOSS="$2"; shift ;;
        --badnet) BADNET="$2"; shift ;;
        --badnet-aqm) BADNET_AQM="$2"; shift ;;
        --pings|--connects|--conc-conns|--conc-pings|--dl-bytes|--ul-bytes|--dl-par|--load-chunk)
            EXTRA+=("$1" "$2"); shift ;;
        --under-load) EXTRA+=("$1"); ;;
        *) echo "usage: env/bench.sh [--matrix] [--transports ...] [--badnet PROFILE [--badnet-aqm fifo|cake]] [--delay ms] [--loss pct] [magabench knobs]" >&2; exit 2 ;;
    esac
    shift
done

say() { echo "[bench] $*" >&2; }

current_transport() {
    $CE exec magicalane-client sh -c 'grep -o "protocol = \"[a-z-]*\"" /etc/magicalane/client.toml 2>/dev/null | cut -d\" -f2' 2>/dev/null || true
}

ensure_echo() {
    if $CE ps --format '{{.Names}}' | grep -qx "$ECHO_NAME"; then
        return
    fi
    $CE rm -f "$ECHO_NAME" >/dev/null 2>&1 || true
    $CE run -d --name "$ECHO_NAME" --label "$LABEL" \
        --network magicalane-net --network-alias bench \
        magicalane:env magabench echo --listen "0.0.0.0:$ECHO_PORT" >/dev/null
    sleep 0.5
    say "echo origin started ($ECHO_NAME:$ECHO_PORT)"
}

apply_netem() {
    [ -z "$DELAY" ] && [ -z "$LOSS" ] && return 0
    local args=""
    [ -n "$DELAY" ] && args="delay ${DELAY}ms"
    [ -n "$LOSS" ] && args="$args loss ${LOSS}%"
    $CE exec magicalane-server tc qdisc replace dev eth0 root netem $args 2>/dev/null \
        && say "netem on server: $args" \
        || say "WARN: netem not applied (missing sch_netem?)"
}

clear_netem() {
    $CE exec magicalane-server tc qdisc del dev eth0 root 2>/dev/null || true
}

run_one() { # transport -> prints "key=value" lines
    local t="$1"
    local cur
    cur="$(current_transport)"
    if [ "$cur" != "$t" ] || [ -z "$cur" ]; then
        say "switching env to transport: $t (was: ${cur:-none})"
        "$ENV_DIR/down.sh" >/dev/null 2>&1
        "$ENV_DIR/up.sh" --transport "$t" >/dev/null
    else
        say "env already on transport: $t"
    fi
    ensure_echo
    [ -n "$BADNET" ] && "$ENV_DIR/badnet.sh" apply "$BADNET" --aqm "$BADNET_AQM" >/dev/null
    apply_netem
    $CE exec magicalane-client magabench run \
        --socks 127.0.0.1:1080 --target "bench:$ECHO_PORT" --pairs "${EXTRA[@]}"
    clear_netem
    [ -n "$BADNET" ] && "$ENV_DIR/badnet.sh" clear >/dev/null
}

# ------------------------------------------------------------- matrix presets
# variant_toml <tag>: emits the tuning TOML fragment for a variant tag.
variant_toml() {
    case "$1" in
        quic)            : ;;
        quic-bbr)        printf '[tuning.quic]\ncongestion = "bbr"\n' ;;
        quic-newreno)    printf '[tuning.quic]\ncongestion = "new-reno"\n' ;;
        quic-win32m)     printf '[tuning.quic]\nsend_window = 33554432\nreceive_window = 33554432\nstream_receive_window = 16777216\n' ;;
        kcp)             : ;;
        kcp-wnd2048)     printf '[tuning.kcp]\nsndwnd = 2048\nrcvwnd = 2048\n' ;;
        kcp-nc0)         printf '[tuning.kcp]\nnc = false\n' ;;
        kcp-i40)         printf '[tuning.kcp]\ninterval = 40\n' ;;
        kcp-mtu1400)     printf '[tuning.kcp]\nmtu = 1400\n' ;;
        kcp-wnd2048-i40) printf '[tuning.kcp]\nsndwnd = 2048\nrcvwnd = 2048\ninterval = 40\n' ;;
        kcp-w2048-nc0)  printf '[tuning.kcp]\nsndwnd = 2048\nrcvwnd = 2048\nnc = false\n' ;;
        *) return 1 ;;
    esac
}

variant_transport() { echo "${1%%-*}"; }

gen_variant_configs() { # tag -> writes variants/<tag>-{server,client}.toml, echoes dir
    local tag="$1" t
    t="$(variant_transport "$tag")"
    local dir="$ENV_DIR/configs/variants"
    mkdir -p "$dir"
    for side in server client; do
        cp "$ENV_DIR/configs/$side-$t.toml" "$dir/$tag-$side.toml"
        variant_toml "$tag" >> "$dir/$tag-$side.toml"
    done
    echo "$dir"
}

run_matrix_one() { # tag -> prints key=value lines
    local tag="$1" dir
    dir="$(gen_variant_configs "$tag")"
    say "deploying variant $tag"
    "$ENV_DIR/down.sh" >/dev/null 2>&1
    "$ENV_DIR/up.sh" --transport "$(variant_transport "$tag")" \
        --server-config "$dir/$tag-server.toml" \
        --client-config "$dir/$tag-client.toml" >/dev/null
    ensure_echo
    [ -n "$BADNET" ] && "$ENV_DIR/badnet.sh" apply "$BADNET" --aqm "$BADNET_AQM" >/dev/null
    apply_netem
    $CE exec magicalane-client magabench run \
        --socks 127.0.0.1:1080 --target "bench:$ECHO_PORT" --pairs "${EXTRA[@]}"
    clear_netem
}

# ------------------------------------------------------------------ run
if [ -n "$MATRIX" ]; then
    # throughput-focused defaults unless overridden
    if [ ${#EXTRA[@]} -eq 0 ]; then
        EXTRA=(--pings 20 --dl-bytes 134217728 --ul-bytes 67108864 --dl-par 4)
    fi
fi
RESULTS_DIR="$ENV_DIR/bench-results"
mkdir -p "$RESULTS_DIR"
TAG="$(date +%Y%m%d-%H%M%S)"
[ -n "$DELAY" ] && TAG="$TAG-d${DELAY}ms"
[ -n "$LOSS" ] && TAG="$TAG-l${LOSS}pct"
[ -n "$BADNET" ] && TAG="$TAG-${BADNET}-${BADNET_AQM}"
OUT="$RESULTS_DIR/$TAG.txt"

declare -A PER_TRANSPORT
if [ -n "$MATRIX" ]; then
    for tag in $TRANSPORTS; do
        say "benchmarking variant $tag ..."
        if ! out="$(run_matrix_one "$tag")"; then
            say "benchmark for $tag FAILED"
            continue
        fi
        echo "=== $tag ===" >> "$OUT"
        echo "$out" >> "$OUT"
        PER_TRANSPORT["$tag"]="$out"
    done
else
    for t in $TRANSPORTS; do
        say "benchmarking $t ..."
        if ! out="$(run_one "$t")"; then
            say "benchmark for $t FAILED"
            continue
        fi
        echo "=== $t ===" >> "$OUT"
        echo "$out" >> "$OUT"
        PER_TRANSPORT["$t"]="$out"
    done
fi

# ------------------------------------------------------------------ comparison table
COLS="connect_p50_ms rtt64_p50_ms dl_mbps dl4par_mbps ul_mbps conc_rps loaded_rtt64_p95_ms load_dl_mbps"

{
printf "%-14s" "transport"
for c in $COLS; do printf "%16s" "$c"; done
printf "\n"
for t in $TRANSPORTS; do
    [ -z "${PER_TRANSPORT[$t]:-}" ] && continue
    printf "%-14s" "$t"
    for c in $COLS; do
        v="$(echo "${PER_TRANSPORT[$t]}" | grep -oP "(?<=^$c=).*" || true)"
        printf "%16s" "${v:--}"
    done
    printf "\n"
done
} | tee -a "$OUT"

say "results saved to $OUT"
