#!/usr/bin/env bash
# tproxy rules - runs INSIDE the tproxy-client container (via podman exec).
# All state (mangle rules, policy routing) lives in that container's netns;
# the host firewall is never touched.
#
#   tproxy-rules.sh apply   - install interception rules
#   tproxy-rules.sh clean   - remove interception rules
#   tproxy-rules.sh show    - dump current rules
#
# Exclusions prevent the two classic interception loops:
#   1. daddr <server-ip>   - the client's own QUIC tunnel to magicalane-server
#   2. daddr <lan-gateway> - aardvark DNS used by the app container
set -euo pipefail

TCP_PORT="${TP_TCP_PORT:-7895}"
UDP_PORT="${TP_UDP_PORT:-7896}"
MARK="${TP_MARK:-1}"
TABLE="${TP_TABLE:-100}"
LAN_IF="${LAN_IF:-eth1}"   # eth0 = magicalane-net (wan), eth1 = magicalane-lan
CHAIN=mgl_tproxy

server_ip() { getent ahostsv4 magicalane-server | awk '{print $1; exit}'; }
lan_gw() { ip -4 route show default dev "$LAN_IF" | awk '{print $3; exit}'; }

apply() {
    local srv gw
    srv="$(server_ip)"
    gw="$(lan_gw)"

    # asymmetric transparent paths prefer loose reverse-path filtering;
    # tolerate failure (rootless may deny some sysctls - rp_filter is not
    # actually blocking in this topology since paths stay symmetric)
    sysctl -qw "net.ipv4.conf.all.rp_filter=0" "net.ipv4.conf.${LAN_IF}.rp_filter=0" 2>/dev/null \
        || echo "warn: could not set rp_filter (continuing)"

    iptables -t mangle -N "$CHAIN" 2>/dev/null || iptables -t mangle -F "$CHAIN"
    iptables -t mangle -C PREROUTING -i "$LAN_IF" -j "$CHAIN" 2>/dev/null \
        || iptables -t mangle -A PREROUTING -i "$LAN_IF" -j "$CHAIN"

    iptables -t mangle -A "$CHAIN" -d "$srv" -j RETURN
    [ -n "$gw" ] && iptables -t mangle -A "$CHAIN" -d "$gw" -j RETURN
    iptables -t mangle -A "$CHAIN" -p tcp -j TPROXY --on-port "$TCP_PORT" --tproxy-mark "$MARK"
    iptables -t mangle -A "$CHAIN" -p udp -j TPROXY --on-port "$UDP_PORT" --tproxy-mark "$MARK"

    # deliver marked packets locally so the transparent listener can pick them up
    ip rule list | grep -q "fwmark ${MARK} lookup ${TABLE}" \
        || ip rule add fwmark "$MARK" lookup "$TABLE"
    ip route replace local default dev lo table "$TABLE"

    echo "tproxy applied: lan_if=$LAN_IF exclude={server:$srv gw:$gw} tcp:$TCP_PORT udp:$UDP_PORT"
}

clean() {
    iptables -t mangle -D PREROUTING -i "$LAN_IF" -j "$CHAIN" 2>/dev/null || true
    iptables -t mangle -F "$CHAIN" 2>/dev/null || true
    iptables -t mangle -X "$CHAIN" 2>/dev/null || true
    while ip rule del fwmark "$MARK" lookup "$TABLE" 2>/dev/null; do :; done
    ip route flush table "$TABLE" 2>/dev/null || true
    echo "tproxy rules cleaned"
}

show() {
    echo "--- mangle ---"
    iptables -t mangle -S
    echo "--- rules ---"
    ip rule list
    echo "--- table $TABLE ---"
    ip route show table "$TABLE"
}

case "${1:-}" in
    apply) apply ;;
    clean) clean ;;
    show) show ;;
    *) echo "usage: $0 {apply|clean|show}" >&2; exit 2 ;;
esac
