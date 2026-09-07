# suites: multi
# transports: quic kcp
# Multi-server pool: per-domain server selection. testsvc is pinned to
# the "alt" server (server2 over the OTHER transport — a mixed-protocol
# pool), origin uses the default (primary). The /peer endpoint on
# testsvc reports the RELAYING server's address: an unambiguous oracle
# for which server carried the connection.
source "$TESTS_DIR/helpers.sh"
MULTI_CFG="/etc/magicalane/client-ws-multi.toml"

ws_stop >/dev/null 2>&1 || true
ws_start_cfg "$MULTI_CFG" 7903

# testsvc-via-alt must report SERVER2's backend ip; the rules pin it.
result="$(exec_c python3 -c '
import socket, sys, urllib.request
def query(name):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for l in name.split("."):
        q += bytes([len(l)]) + l.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    s.sendto(q, ("10.89.0.1", 53)); d, _ = s.recvfrom(2048)
    return ".".join(str(b) for b in d[-4:])
try:
    tok = query("testsvc")
    peer = urllib.request.urlopen("http://%s:8080/peer" % tok, timeout=12).read().decode().strip()
    body = urllib.request.urlopen("http://%s:8080/hello" % tok, timeout=12).read().decode().strip()
    tok2 = query("origin")
    origin_body = urllib.request.urlopen("http://%s/fixtures/hello.txt" % tok2, timeout=12).read().decode().strip()
except Exception as e:
    print("FAIL:" + repr(e)); sys.exit(0)
print("OK:%s|%s|%s" % (peer, body, origin_body))
')"
case "$result" in
    FAIL:*) fail "multi fetch: $result" ;;
    OK:*) result="${result#OK:}" ;;
esac
ALT_PEER="$($CE exec magicalane-server2 sh -c 'curl -s --max-time 3 http://testsvc:8080/peer')"
DEF_PEER="$($CE exec magicalane-server sh -c 'curl -s --max-time 3 http://testsvc:8080/peer')"
[ -n "$ALT_PEER" ] || fail "server2 cannot reach testsvc (env problem)"
[ -n "$DEF_PEER" ] || fail "server1 cannot reach testsvc (env problem)"

tsvc_peer="$(echo "$result" | cut -d'|' -f1)"
tsvc_body="$(echo "$result" | cut -d'|' -f2)"
org_body="$(echo "$result" | cut -d'|' -f3)"

[ "$tsvc_peer" = "$ALT_PEER" ] \
    || fail "testsvc relayed by $tsvc_peer, expected server2 ($ALT_PEER) - rule did not pin 'alt'"
pass "multi: testsvc -> server2 ($ALT_PEER) by domain rule (mixed transports)"
[ "$tsvc_body" = "magicalane-test-service" ] || fail "testsvc body wrong: $tsvc_body"
pass "multi: testsvc content intact through alt"
# origin via the DEFAULT target (content check: the fixture is only on
# the origin; /peer is a magabench endpoint the origin lacks).
[ "$org_body" = "magicalane-test-fixture-hello" ] \
    || fail "origin body wrong: $org_body"
pass "multi: origin reachable via default target"
ws_stop
