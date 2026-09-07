# suites: multi
# transports: quic kcp
# load-balance (round-robin) alternates servers across connections;
# url-test converges to the sole alive member after a death.
source "$TESTS_DIR/helpers.sh"
MULTI_CFG="/etc/magicalane/client-ws-multi.toml"


# Pin the group-alias domains (fb.testsvc etc.) on both servers so the
# server side can resolve them to the test service.
pin_group_domains() {
    local tip
    tip="$(timeout 10 $CE inspect magicalane-testsvc --format '{{(index .NetworkSettings.Networks "magicalane-backend").IPAddress}}')"
    [ -n "$tip" ] || fail "cannot resolve testsvc ip for group-domain pins"
    for s in magicalane-server magicalane-server2; do
        timeout 10 $CE exec "$s" sh -c "echo '$tip fb.testsvc ut.testsvc lb.testsvc' >> /etc/hosts" 2>/dev/null || true
    done
}

ws_stop >/dev/null 2>&1 || true
pin_group_domains
ws_start_cfg "$MULTI_CFG" 7903

lb_fetch() {
    exec_c python3 -c '
import socket, sys, urllib.request
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
for l in "lb.testsvc".split("."):
    q += bytes([len(l)]) + l.encode()
q += b"\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, ("10.89.0.1", 53)); d, _ = s.recvfrom(2048)
tok = ".".join(str(b) for b in d[-4:])
try:
    print(urllib.request.urlopen("http://%s:8080/peer" % tok, timeout=12).read().decode().strip())
except Exception as e:
    print("FAIL:" + repr(e))
'
}
ut_fetch() {
    exec_c python3 -c '
import socket, sys, urllib.request
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
for l in "ut.testsvc".split("."):
    q += bytes([len(l)]) + l.encode()
q += b"\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, ("10.89.0.1", 53)); d, _ = s.recvfrom(2048)
tok = ".".join(str(b) for b in d[-4:])
try:
    print(urllib.request.urlopen("http://%s:8080/peer" % tok, timeout=12).read().decode().strip())
except Exception as e:
    print("FAIL:" + repr(e))
'
}

ALT_PEER="$($CE exec magicalane-server2 sh -c 'curl -s --max-time 3 http://testsvc:8080/peer')"
DEF_PEER="$($CE exec magicalane-server sh -c 'curl -s --max-time 3 http://testsvc:8080/peer')"
[ "$ALT_PEER" != "$DEF_PEER" ] || fail "servers share egress; lb test needs distinct peers"

# Round-robin: 4 sequential connections must touch BOTH servers.
seen_a=0; seen_b=0
for _ in 1 2 3 4; do
    p="$(lb_fetch)"
    case "$p" in FAIL:*) fail "lb fetch: $p" ;; esac
    if [ "$p" = "$ALT_PEER" ]; then seen_a=$((seen_a+1)); fi
    if [ "$p" = "$DEF_PEER" ]; then seen_b=$((seen_b+1)); fi
done
[ "$seen_a" -gt 0 ] && [ "$seen_b" -gt 0 ] \
    || fail "round-robin did not spread: alt=$seen_a default=$seen_b"
pass "load-balance: rr spread across both servers (alt=$seen_a default=$seen_b)"

# url-test: kill alt; group ut must converge to default.
$CE exec magicalane-server2 sh -c 'pkill -9 -x magicalane || true'
p=""
for _ in $(seq 1 20); do
    p="$(ut_fetch)"
    case "$p" in FAIL:*) sleep 1; continue ;; esac
    [ "$p" = "$DEF_PEER" ] && break
    sleep 1
done
[ "$p" = "$DEF_PEER" ] || fail "url-test did not converge to default (last: $p)"
pass "url-test: converged to sole alive server after alt death"

# restore server2 for other tests in the suite
$CE exec -d magicalane-server2 sh -c 'exec magicalane --config /etc/magicalane/server2-quic.toml' >/dev/null 2>&1
$CE exec -d magicalane-server2 sh -c 'exec magicalane --config /etc/magicalane/server2-kcp.toml' >/dev/null 2>&1
ws_stop
