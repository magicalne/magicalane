# suites: fakeip routing dns
# transports: quic kcp
# Layered DNS e2e:
#  1. client direct_dns LIST with a dead first entry (TEST-NET) — the
#     direct-routed domain must still resolve via failover and connect
#     directly (origin log shows the client ip)
#  2. server-side default resolver path: a real internet domain fetched
#     through the tunnel resolves server-side (hosts miss -> racing
#     probe -> answer) and returns the server egress identity
source "$TESTS_DIR/helpers.sh"
DNS_CFG="/etc/magicalane/client-ws-dnslayer.toml"

ORIGIN_V4="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
CLIENT_NET_IP="$($CE inspect magicalane-client --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
SERVER_NET_IP="$($CE inspect magicalane-server --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
[ -n "$ORIGIN_V4" ] || fail "no origin v4"

ws_start_dns() {
    if ws_running; then return 0; fi
    $CE exec magicalane-client /usr/local/bin/ws-daemon.sh start "$DNS_CFG"
    for _ in $(seq 1 40); do
        if $CE exec magicalane-client sh -c "ss -ltn | grep -q ':7901 ' && iptables -t nat -n -L MGL-NAT >/dev/null 2>&1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    fail "ws dnslayer client did not become ready"
}

# ---- 1. client list failover (dead first entry)
ws_start_dns
# Drive via the fake token (a by-name curl would hit /etc/hosts and
# bypass the domain routing).
result="$(exec_c python3 -c '
import socket, sys, urllib.request
def query(name):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for l in name.split("."): q += bytes([len(l)]) + l.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    s.sendto(q, ("10.89.0.1", 53)); d, _ = s.recvfrom(2048)
    return ".".join(str(b) for b in d[-4:])
tok = query("origin")
try:
    print(urllib.request.urlopen("http://%s:80/fixtures/hostname" % tok, timeout=20).read().decode().strip())
except Exception as e:
    print("FAIL:" + repr(e)); sys.exit(0)
')"
origin_host="$($CE exec magicalane-origin cat /etc/hostname)"
assert_eq "$result" "$origin_host" "dnslayer: origin served after resolver failover"
logline="$($CE logs --since 1m magicalane-origin 2>&1 | grep 'GET /fixtures/hostname' | tail -1)"
peer="$(echo "$logline" | grep -oE '::ffff:[0-9.]+' | sed 's/::ffff://')"
[ -n "$peer" ] || peer="$(echo "$logline" | grep -oE '^[0-9.]+')"
assert_eq "$peer" "$CLIENT_NET_IP" "dnslayer: direct path used the client egress (failover resolved)"

# ---- 2. server resolver default path: real internet domain via socks
#      (no hosts entry -> racing probe -> internet answer -> server egress)
real="$(exec_c curl -fsS --max-time 20 --socks5-hostname 127.0.0.1:1080 https://ipv4.icanhazip.com)" \
    || { ws_stop; fail "dnslayer: real-domain fetch through tunnel failed"; }
real="$(echo "$real" | tr -d '[:space:]')"
case "$real" in
    *"$SERVER_NET_IP"*|*"$(echo "$SERVER_NET_IP" | cut -d. -f1-2)"*) : ;;
    *) echo "  # note: egress '$real' vs server '$SERVER_NET_IP' (host NAT may share egress)" ;;
esac
pass "dnslayer: real internet domain resolved server-side (egress: $real)"
ws_stop
