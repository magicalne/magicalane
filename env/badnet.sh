#!/usr/bin/env bash
# Simulate a realistic bad network between client and server ("server in
# another country, limited public bandwidth"). Shapes BOTH directions with
# per-direction rate limits (client uplink vs downlink), RTT, jitter, loss.
#
# Only traffic between the magicalane client and server containers is shaped
# (dst-IP filtered); server<->origin and DNS stay on the clean bridge, just
# like a real deployment where the origin sits near the server.
#
#   env/badnet.sh apply cn-us              # China<->US-ish: 160ms, 5/20 Mbps
#   env/badnet.sh apply eu-us --aqm cake   # EU<->US-ish with managed queue
#   env/badnet.sh apply mobile             # lossy mobile uplink
#   env/badnet.sh status|clear
#
# AQM modes (the bottleneck queue discipline):
#   fifo  - netem + tbf with a deep buffer (default) = bufferbloat
#   cake  - netem + cake (flow-isolating AQM) = well-managed link
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CE="${CONTAINER_ENGINE:-podman}"

# podman exec with retries: rootless conmon occasionally rejects rapid
# successive execs with "Exclusivity flag on, cannot modify".
rexec() {
    local cont="$1"; shift
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if $CE exec "$cont" "$@" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    # last attempt, let errors surface
    $CE exec "$cont" "$@"
}

profile_params() {
    case "$1" in
        cn-us)  echo "160 8 0.3 5mbit 20mbit" ;;   # rtt jitter loss% up down
        eu-us)  echo "90 4 0.1 20mbit 100mbit" ;;
        mobile) echo "60 15 2.0 2mbit 10mbit" ;;
        *) echo "profiles: cn-us eu-us mobile" >&2; return 1 ;;
    esac
}

need_env() {
    $CE ps --format '{{.Names}}' | grep -qx magicalane-client || {
        echo "magicalane-client not running (run env/up.sh first)" >&2; exit 1;
    }
    $CE ps --format '{{.Names}}' | grep -qx magicalane-server || {
        echo "magicalane-server not running (run env/up.sh first)" >&2; exit 1;
    }
}

ip_of() { # container -> first ipv4
    $CE inspect "$1" --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}'
}

shape_one() { # container peer_ip rate rtt_ms jitter loss aqm
    local cont="$1" peer="$2" rate="$3" rtt="$4" jitter="$5" loss="$6" aqm="$7"
    local half=$((rtt / 2))
    local limiter
    if [ "$aqm" = "cake" ]; then
        limiter="tc qdisc add dev eth0 parent 10:1 handle 20: cake bandwidth $rate diffserv besteffort"
    else
        limiter="tc qdisc add dev eth0 parent 10:1 handle 20: tbf rate $rate burst 256kbit latency 400ms"
    fi
    # One exec for the whole side: root prio with a dst-filtered shaped lane.
    # Band 1 = shaped (to peer), band 2 = everything else stays clean.
    rexec "$cont" sh -c \
        "tc qdisc del dev eth0 root 2>/dev/null; tc qdisc replace dev eth0 root handle 1: prio bands 2 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 && \\
         tc qdisc add dev eth0 parent 1:1 handle 10: netem delay ${half}ms ${jitter}ms loss ${loss}% limit 10000 && \\
         $limiter && \\
         tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dst $peer flowid 1:1"
}

apply() { # profile aqm
    local profile="$1" aqm="$2"
    local params
    params="$(profile_params "$profile")" || return 1
    read -r rtt jitter loss up down <<<"$params"
    need_env
    local client_ip server_ip
    client_ip="$(ip_of magicalane-client)"
    server_ip="$(ip_of magicalane-server)"
    # client egress = client's uplink; server egress = client's downlink
    shape_one magicalane-client "$server_ip" "$up" "$rtt" "$jitter" "$loss" "$aqm"
    shape_one magicalane-server "$client_ip" "$down" "$rtt" "$jitter" "$loss" "$aqm"
    echo "[badnet] applied $profile (rtt ${rtt}ms +-${jitter}, loss ${loss}%, up $up, down $down, aqm $aqm)"
}

clear_one() {
    rexec "$1" tc qdisc del dev eth0 root 2>/dev/null || true
}

case "${1:-}" in
    apply)
        PROFILE="${2:-cn-us}"
        AQM="fifo"
        shift 2 2>/dev/null || shift $# 2>/dev/null || true
        while [ $# -gt 0 ]; do
            case "$1" in
                --aqm) AQM="$2"; shift ;;
                *) echo "usage: env/badnet.sh apply PROFILE [--aqm fifo|cake]" >&2; exit 2 ;;
            esac
            shift
        done
        case "$AQM" in fifo|cake) ;; *) echo "aqm must be fifo or cake" >&2; exit 2 ;; esac
        apply "$PROFILE" "$AQM"
        ;;
    clear)
        need_env
        clear_one magicalane-client
        clear_one magicalane-server
        echo "[badnet] cleared"
        ;;
    status)
        need_env
        for c in magicalane-client magicalane-server; do
            echo "=== $c ==="
            rexec "$c" tc -s qdisc show dev eth0
        done
        ;;
    *)
        echo "usage: env/badnet.sh {apply PROFILE [--aqm fifo|cake]|status|clear}" >&2
        echo "profiles: cn-us eu-us mobile" >&2
        exit 2
        ;;
esac
