# suites: fakeip routing tproxy-ws
# transports: quic kcp
# Split routing (CP2): `origin` matches the direct rule, so a fetch via
# its fake token must bypass the tunnel — origin's access log must show
# the CLIENT ip. The tunneled counterpart (plain ws config, all-proxy)
# must show the SERVER ip. Proves domain-based split + no re-interception
# loop on the direct path.
source "$TESTS_DIR/helpers.sh"
FAKEIP_CFG="/etc/magicalane/client-ws-fakeip.toml"

CLIENT_NET_IP="$($CE inspect magicalane-client --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
SERVER_NET_IP="$($CE inspect magicalane-server --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
[ -n "$CLIENT_NET_IP" ] || fail "no client net ip"
[ -n "$SERVER_NET_IP" ] || fail "no server net ip"

# --- direct path: fake token -> routing rule suffix origin -> DIRECT
ws_start_cfg "$FAKEIP_CFG"
result="$(exec_c python3 -c '
import socket, sys, urllib.request

def query(name):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, ("10.89.0.1", 53))
    data, _ = s.recvfrom(2048)
    if len(data) < 28:
        raise RuntimeError("short response")
    return ".".join(str(b) for b in data[-4:])

try:
    token = query("origin")
except Exception as e:
    print("FAIL:dns-query:" + repr(e)); sys.exit(0)
if not (token.startswith("198.18.") or token.startswith("198.19.")):
    print("FAIL:token:" + token); sys.exit(0)
try:
    body = urllib.request.urlopen("http://%s:80/fixtures/hostname" % token, timeout=15).read().decode().strip()
except Exception as e:
    print("FAIL:fetch:" + repr(e)); sys.exit(0)
print("OK:" + token + ":" + body)
')"
ws_stop

origin_host="$($CE exec magicalane-origin cat /etc/hostname)"
case "$result" in
    OK:198.1[89].*:"$origin_host") : ;;
    *) fail "split: direct fetch via token failed: $result" ;;
esac

# Peer may log as plain v4 or v4-mapped v6 (::ffff:10.x) — origin binds ::
logline="$($CE logs --since 2m magicalane-origin 2>&1 | grep 'GET /fixtures/hostname' | tail -1)"
peer="$(echo "$logline" | grep -oE '::ffff:([0-9]+\.){3}[0-9]+' | sed 's/::ffff://' )"
[ -n "$peer" ] || peer="$(echo "$logline" | grep -oE '^([0-9]+\.){3}[0-9]+')"
[ -n "$peer" ] || fail "split: no access-log entry for the direct fetch"
assert_eq "$peer" "$CLIENT_NET_IP" "split: origin saw CLIENT ip (direct, not tunneled)"

# --- tunneled counterpart: plain ws config (no routing) fetches
# hello.txt (different path => unambiguous log line) via /etc/hosts ip;
# everything tunnels => origin sees SERVER ip.
ws_start
exec_c curl -fsS --max-time 10 http://origin/fixtures/hello.txt >/dev/null 2>&1
ws_stop
logline2="$($CE logs --since 2m magicalane-origin 2>&1 | grep 'GET /fixtures/hello.txt' | tail -1)"
peer2="$(echo "$logline2" | grep -oE '::ffff:([0-9]+\.){3}[0-9]+' | sed 's/::ffff://')"
[ -n "$peer2" ] || peer2="$(echo "$logline2" | grep -oE '^([0-9]+\.){3}[0-9]+')"
[ -n "$peer2" ] || fail "split: no access-log entry for the tunneled fetch"
assert_eq "$peer2" "$SERVER_NET_IP" "split: plain config tunnels (origin saw SERVER ip)"
