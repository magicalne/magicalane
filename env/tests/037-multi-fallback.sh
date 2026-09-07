# suites: multi
# transports: quic kcp
# Group resilience: the "fb" group (fallback: alt first, then default)
# must keep serving when the alt server dies, and return to alt after
# it recovers. Server PROCESSES are killed (container stays: IP kept,
# so the client's resolved address stays valid).
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

fb_fetch() {
    exec_c python3 -c '
import socket, sys, urllib.request
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
for l in "fb.testsvc".split("."):
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

# The fb.testsvc suffix rule targets group fb; suffix "testsvc" also
# matches, so use the GROUP alias domain to force fb.
ALT_PEER="$($CE exec magicalane-server2 sh -c 'curl -s --max-time 3 http://testsvc:8080/peer')"
DEF_PEER="$($CE exec magicalane-server sh -c 'curl -s --max-time 3 http://testsvc:8080/peer')"

p1="$(fb_fetch)"
case "$p1" in FAIL:*) fail "fb fetch before kill: $p1" ;; esac
[ "$p1" = "$ALT_PEER" ] || fail "fb initially used $p1, expected alt ($ALT_PEER)"
pass "fallback: healthy alt serves fb ($p1)"

# Take server2 down: the marker pauses the supervisor, the pkill stops
# the tunnels; the container (and its IPs) stays.
$CE exec magicalane-server2 sh -c 'touch /tmp/mgl-server2-down; pkill -9 -x magicalane || true'
sleep 0.5
# Wait for the probe to mark it dead (interval 2s, threshold 3 -> <8s).
p2=""
for _ in $(seq 1 20); do
    p2="$(fb_fetch)"
    [ "$p2" = "$DEF_PEER" ] && break
    sleep 1
done
[ "$p2" = "$DEF_PEER" ] \
    || fail "fb did not fall back to default after alt death (last: $p2)"
pass "fallback: alt death -> default serves fb within probe window ($p2)"

# Recover: clear the marker; the supervisor respawns both processes.
$CE exec magicalane-server2 sh -c 'rm -f /tmp/mgl-server2-down' 
p3=""
for _ in $(seq 1 20); do
    p3="$(fb_fetch)"
    [ "$p3" = "$ALT_PEER" ] && break
    sleep 1
done
[ "$p3" = "$ALT_PEER" ] \
    || fail "fb did not return to alt after recovery (last: $p3)"
pass "fallback: alt recovery restores priority ($p3)"
ws_stop
