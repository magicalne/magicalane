# suites: fakeip routing geoip
# transports: quic
# GEOIP with REAL China data: downloads the live chnroute list
# (gaoyifan/china-operator-ip), installs it as cn.txt, then opens TCP
# connections to two REAL internet IPs by literal address:
#   223.5.5.5 (AliDNS, China)  -> must route DIRECT (client egress)
#   8.8.8.8   (Google, non-CN) -> must route through the TUNNEL
# Classification is asserted from the client's relay log; the full live
# list exercises the interval engine at real scale (~9.6k CIDRs).
# Falls back to the committed real-data snapshot if the download fails.
source "$TESTS_DIR/helpers.sh"
GEOIP_CFG="/etc/magicalane/client-ws-geoip.toml"
CHINA_URL="https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"

exec_c sh -c 'mkdir -p /tmp/geoip'
ok=""
for _ in 1 2 3; do
    if exec_c sh -c "curl -fsSL --max-time 25 '$CHINA_URL' -o /tmp/geoip/cn.txt" \
        && [ "$(exec_c sh -c 'wc -l < /tmp/geoip/cn.txt 2>/dev/null')" -ge 5000 ]; then
        ok=live
        break
    fi
    sleep 2
done
if [ -z "$ok" ]; then
    $CE cp "$ENV_DIR/fixtures/china-snapshot.txt" magicalane-client:/tmp/geoip/cn.txt
    echo "  # live download failed; using committed real-data snapshot"
fi
nlines="$(exec_c sh -c 'wc -l < /tmp/geoip/cn.txt')"
[ "${nlines:-0}" -ge 9 ] || fail "cn.txt too small ($nlines lines)"
echo "  # cn.txt installed: $nlines CIDR lines ($ok)"

ws_start_geoip() {
    if ws_running; then return 0; fi
    $CE exec magicalane-client /usr/local/bin/ws-daemon.sh start "$GEOIP_CFG"
    for _ in $(seq 1 40); do
        if $CE exec magicalane-client sh -c "ss -ltn | grep -q ':7899 ' && iptables -t nat -n -L MGL-NAT >/dev/null 2>&1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    fail "ws geoip client did not become ready"
}
ws_start_geoip

# Two literal-IP TCP connections (no DNS -> geoip classification).
result="$(exec_c python3 -c '
import socket
out = []
for ip in ["223.5.5.5", "8.8.8.8"]:
    try:
        s = socket.create_connection((ip, 53), timeout=8)
        s.close()
        out.append(ip + ":connected")
    except Exception as e:
        out.append(ip + ":connfail:" + type(e).__name__)
print(" ".join(out))
')"

ws_stop

cn_route="$(exec_c sh -c 'grep -a "tproxy relay 223.5.5.5:53: " /tmp/ws.log | grep -a "via" | tail -1')"
case "$cn_route" in
    *"direct via"*) pass "geoip CN: 223.5.5.5 (AliDNS) routed DIRECT by real china list" ;;
    *"tunnel via"*) fail "geoip CN: 223.5.5.5 was tunneled, not direct" ;;
    *) fail "geoip CN: no relay log for 223.5.5.5 ($result)" ;;
esac
gl_route="$(exec_c sh -c 'grep -a "tproxy relay 8.8.8.8:53: " /tmp/ws.log | grep -a "via" | tail -1')"
case "$gl_route" in
    *"tunnel via"*) pass "geoip non-CN: 8.8.8.8 routed through tunnel" ;;
    *"direct via"*) fail "geoip non-CN: 8.8.8.8 was routed direct" ;;
    *) fail "geoip non-CN: no relay log for 8.8.8.8 ($result)" ;;
esac
echo "  # connections: $result"
