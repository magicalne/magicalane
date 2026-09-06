# suites: fakeip routing dns
# transports: quic kcp
# Rule providers + hot reload:
#  1. provider list served over local HTTP; refresh interval 5s; the
#     routing decision for `origin` flips proxy->direct when the list
#     gains "origin" — no restart
#  2. SIGHUP reload: adding a suffix rule to the (copied) config flips
#     the decision instantly — no restart
source "$TESTS_DIR/helpers.sh"
PROV_CFG="/etc/magicalane/client-ws-provider.toml"

# Hygiene: leftover instances from failed runs hold ports + stale rules.
cleanup_034() {
    $CE exec magicalane-client /usr/local/bin/ws-daemon.sh stop >/dev/null 2>&1 || true
    $CE exec magicalane-client sh -c 'pkill -9 -f client-ws 2>/dev/null; true'
}
trap cleanup_034 EXIT
cleanup_034
sleep 0.5

ORIGIN_V4="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
CLIENT_NET_IP="$($CE inspect magicalane-client --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
SERVER_NET_IP="$($CE inspect magicalane-server --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"

fetch_origin_egress() {   # $1 = fixture path (disambiguates log lines)
    local fixture="${1:-/fixtures/hello.txt}"
    exec_c python3 -c '
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
    urllib.request.urlopen("http://%s:80%s" % (tok, sys.argv[1]), timeout=10).read()
except Exception as e:
    print("FETCHERR:" + type(e).__name__, file=sys.stderr)
' "$fixture" 2>/dev/null
    line="$($CE logs --since 40s magicalane-origin 2>&1 | grep "GET $fixture" | tail -1)"
    p="$(echo "$line" | grep -oE '::ffff:[0-9.]+' | sed 's/::ffff://')"
    [ -n "$p" ] || p="$(echo "$line" | grep -oE '^[0-9.]+')"
    echo "$p"
}

# local provider server (mutable content)
exec_c sh -c 'mkdir -p /tmp/prov && printf "nothing.example\n" > /tmp/prov/list.txt'
exec_c sh -c 'pkill -f "http.server 8082" 2>/dev/null; true'
$CE exec -d magicalane-client sh -c 'cd /tmp/prov && exec python3 -m http.server 8082'
sleep 1

# ---- part 1: provider refresh
$CE exec magicalane-client /usr/local/bin/ws-daemon.sh start "$PROV_CFG"
for _ in $(seq 1 40); do
    $CE exec magicalane-client sh -c "ss -ltn | grep -q ':7905 ' && iptables -t nat -n -L MGL-NAT >/dev/null 2>&1" >/dev/null 2>&1 && break
    sleep 0.5
done

peer1="$(fetch_origin_egress)"
assert_eq "$peer1" "$SERVER_NET_IP" "provider v1 (origin NOT listed): tunneled (server egress)"

exec_c sh -c 'printf "origin\n" > /tmp/prov/list.txt'    # v2: direct rule for origin
# Poll the per-instance relay log for the decision flip (the provider
# refresh lands within its 5s interval).
v2=""
for _ in $(seq 1 24); do
    fetch_origin_egress >/dev/null 2>&1
    r="$(exec_c sh -c 'grep -a "relay.*origin" /tmp/ws.log 2>/dev/null | grep -a "via" | tail -1')"
    case "$r" in
        *"direct via"*) v2=direct; break ;;
    esac
    sleep 1
done
[ "$v2" = "direct" ] || fail "provider v2: not direct after refresh window (last: $r)"
pass "provider v2 (origin listed): DIRECT after auto-refresh"

$CE exec magicalane-client /usr/local/bin/ws-daemon.sh stop >/dev/null 2>&1 || true

# ---- part 2: SIGHUP reload (copied config, rule added after start)
exec_c sh -c 'cp '"$PROV_CFG"' /tmp/hot.toml'
exec_c sh -c 'rm -f /tmp/prov/list.txt && printf "nothing.example\n" > /tmp/prov/list.txt'
$CE exec magicalane-client /usr/local/bin/ws-daemon.sh start /tmp/hot.toml
for _ in $(seq 1 40); do
    $CE exec magicalane-client sh -c "ss -ltn | grep -q ':7905 ' && iptables -t nat -n -L MGL-NAT >/dev/null 2>&1" >/dev/null 2>&1 && break
    sleep 0.5
done
fetch_origin_egress /fixtures/hostname >/dev/null
route3="$(exec_c sh -c 'grep -a "fake.*-> origin\|relay.*origin" /tmp/ws.log | tail -1')"
case "$route3" in
    *"tunnel via"*) pass "hot-reload base: origin tunneled" ;;
    *"direct via"*) fail "hot-reload base: origin already direct: $route3" ;;
    *) fail "hot-reload base: no relay log for origin" ;;
esac

exec_c sed -i 's|aaaa = "auto", provider|aaaa = "auto", rule = [ { domain_suffix = [ "origin" ], action = "direct" } ], provider|' /tmp/hot.toml
PID="$($CE exec magicalane-client cat /tmp/ws-client.pid)"
$CE exec magicalane-client kill -HUP "$PID"
sleep 2
fetch_origin_egress /fixtures/hostname >/dev/null
route4="$(exec_c sh -c 'grep -a "relay.*origin" /tmp/ws.log | grep -a "via" | tail -1')"
case "$route4" in
    *"direct via"*) pass "SIGHUP: suffix rule applied without restart (direct)" ;;
    *"tunnel via"*) fail "SIGHUP: still tunneled after reload: $route4" ;;
    *) fail "SIGHUP: no relay log for origin" ;;
esac

$CE exec magicalane-client /usr/local/bin/ws-daemon.sh stop >/dev/null 2>&1 || true
exec_c sh -c 'pkill -f "http.server 8082" 2>/dev/null; true'
exit 0
