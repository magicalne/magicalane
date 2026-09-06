# suites: tun
# transports: quic
# TUN mode (no iptables): mgl0 + userspace TCP/IP stack. DNS to an
# EXTERNAL resolver IP (routed via mgl0) gets a fake token; TCP through
# the token completes the smoltcp handshake and is relayed through the
# tunnel. Clean exit restores the container's default route.
source "$TESTS_DIR/helpers.sh"
TUN_CFG="/etc/magicalane/client-ws-tun.toml"

cleanup_tun() {
    $CE exec magicalane-client sh -c '
        [ -f /tmp/tun.pid ] && kill "$(cat /tmp/tun.pid)" 2>/dev/null
        rm -f /tmp/tun.pid
        pkill -9 -f magicalane-tun 2>/dev/null
        true'
}
trap cleanup_tun EXIT
cleanup_tun
sleep 0.5

# Start the feature binary directly (smoltcp userspace stack).
$CE exec -d magicalane-client sh -c 'exec magicalane-tun --config /etc/magicalane/client-ws-tun.toml > /tmp/tun.log 2>&1'
for _ in $(seq 1 40); do
    $CE exec magicalane-client sh -c 'ip link show mgl0 >/dev/null 2>&1 && ip route show default | grep -q mgl0' >/dev/null 2>&1 && break
    sleep 0.5
done
$CE exec magicalane-client sh -c 'ip link show mgl0 >/dev/null 2>&1' || { cat /tmp/tun.log 2>/dev/null; fail "tun device did not come up"; }
pass "tun: mgl0 up with default route (no iptables involved)"

# 1. DNS via an external resolver IP -> fake token.
result="$(exec_c python3 -c '
import socket, sys, urllib.request
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07testsvc\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
s.sendto(q, ("8.8.8.8", 53)); d, _ = s.recvfrom(2048)
tok = ".".join(str(b) for b in d[-4:])
if not tok.startswith("198.18.") and not tok.startswith("198.19."):
    print("FAIL:token:" + tok); sys.exit(0)
try:
    body = urllib.request.urlopen("http://%s:8080/hello" % tok, timeout=10).read().decode().strip()
except Exception as e:
    print("FAIL:fetch:" + repr(e)); sys.exit(0)
print("OK:" + body)
')"
case "$result" in
    OK:magicalane-test-service) pass "tun: DNS via external IP faked; TCP via token tunneled end-to-end" ;;
    *) fail "tun flow: $result" ;;
esac

# 2. Clean exit: TERM restores the default route and takes mgl0 down.
PID="$($CE exec magicalane-client sh -c 'pgrep -f magicalane-tun | head -1')"
$CE exec magicalane-client kill -TERM "$PID"
for _ in $(seq 1 20); do
    $CE exec magicalane-client sh -c '! ip link show mgl0 >/dev/null 2>&1' >/dev/null 2>&1 && break
    sleep 0.5
done
if $CE exec magicalane-client sh -c 'ip link show mgl0 >/dev/null 2>&1'; then
    fail "tun: mgl0 still present after TERM"
else
    pass "tun: clean exit (mgl0 gone)"
fi
$CE exec magicalane-client sh -c 'ip route show default | grep -q "via 10.89.0.1 dev eth0"' \
    || fail "tun: container default route not restored"
pass "tun: default route restored"
