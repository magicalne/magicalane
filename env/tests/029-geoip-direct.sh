# suites: fakeip routing v6
# transports: quic
# GEOIP routing (A+B combined): real-IP connections classified by a
# country CIDR list (<geoip_dir>/cn.txt, chnroutes2 format) instead of
# hand-written ip_cidr arrays. A literal-IP fetch of the origin (in the
# list) must go DIRECT (origin sees the CLIENT v4 or v6); a literal-IP
# fetch of testsvc (NOT in the list) must tunnel (success via server).
source "$TESTS_DIR/helpers.sh"
GEOIP_CFG="/etc/magicalane/client-ws-geoip.toml"

ORIGIN_V4="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
CLIENT_NET_IP="$($CE inspect magicalane-client --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
[ -n "$ORIGIN_V4" ] || fail "no origin v4"

# Install the country list: origin's /24 (v4) + link /64 (v6) are "cn".
exec_c sh -c 'mkdir -p /tmp/geoip && printf "%s\n%s\n" "'"$ORIGIN_V4"'/24" "$(ip -6 addr show dev eth0 2>/dev/null | grep -oE "fd[0-9a-f:]+:[0-9a-f]+" | head -1)/64" > /tmp/geoip/cn.txt; cat /tmp/geoip/cn.txt'

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

# 1. Literal-IP fetch of origin (real IP, no DNS -> geoip rule) => DIRECT.
#    Origin's log must show the client's own source address. (No restart:
#    aardvark reassigns IPs on container restart, invalidating ORIGIN_V4.)
for _ in $(seq 1 20); do
    exec_c curl -fsS --max-time 2 --socks5-hostname 127.0.0.1:1080 "http://origin/fixtures/hostname" >/dev/null 2>&1 && break
    sleep 0.5
done
body="$(exec_c curl -fsS --max-time 10 "http://$ORIGIN_V4/fixtures/hostname")" \
    || { ws_stop; fail "geoip: literal v4 fetch failed"; }
origin_host="$($CE exec magicalane-origin cat /etc/hostname)"
assert_eq "$body" "$origin_host" "geoip: literal fetch served by origin"
logline="$($CE logs --since 1m magicalane-origin 2>&1 | grep 'GET /fixtures/hostname' | tail -1)"
case "$logline" in
    "$CLIENT_NET_IP"*|::ffff:"$CLIENT_NET_IP"*) : ;;
    *) ws_stop; fail "geoip: origin did NOT see client ip (direct): $logline" ;;
esac
pass "geoip: literal-IP fetch routed direct by country list (client egress)"

# 2. Literal v6 fetch (dual-stack env) => direct over native v6.
CLIENT_V6="$($CE inspect magicalane-client --format '{{(index .NetworkSettings.Networks "magicalane-net").GlobalIPv6Address}}')"
if [ -n "$CLIENT_V6" ]; then
    ORIGIN_V6="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "magicalane-net").GlobalIPv6Address}}')"
    body="$(exec_c curl -fsS --max-time 10 "http://[$ORIGIN_V6]/fixtures/hostname")" \
        || { ws_stop; fail "geoip: literal v6 fetch failed"; }
    assert_eq "$body" "$origin_host" "geoip: literal v6 fetch served by origin"
    logline6="$($CE logs --since 1m magicalane-origin 2>&1 | grep 'GET /fixtures/hostname' | tail -1)"
    case "$logline6" in
        "$CLIENT_V6"*) pass "geoip: literal v6 routed direct (native client v6)" ;;
        *) ws_stop; fail "geoip: v6 fetch not direct from client: $logline6" ;;
    esac
fi

# 3. Non-listed literal IP (testsvc on the private backend) => tunneled
#    by IP (client cannot reach it directly; only the server can).
TESTSVC_IP="$($CE inspect magicalane-testsvc --format '{{(index .NetworkSettings.Networks "magicalane-backend").IPAddress}}')"
[ -n "$TESTSVC_IP" ] || { ws_stop; fail "no testsvc ip"; }
body="$(exec_c curl -fsS --max-time 10 "http://$TESTSVC_IP:8080/hello")" \
    || { ws_stop; fail "geoip: non-cn literal fetch failed"; }
assert_eq "$body" "magicalane-test-service" "geoip: non-cn literal fetch tunneled by IP"

ws_stop
