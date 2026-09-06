# suites: fakeip dns
# transports: quic kcp
# fakeip-filter + persistence:
#  1. filtered domain (testsvc) gets a REAL answer (its backend IP),
#     unfiltered (origin) still gets a 198.18/15 token
#  2. a token assigned before shutdown survives the restart (same token)
source "$TESTS_DIR/helpers.sh"
FILTER_CFG="/etc/magicalane/client-ws-fakefilter.toml"

TESTSVC_IP="$($CE inspect magicalane-testsvc --format '{{(index .NetworkSettings.Networks "magicalane-backend").IPAddress}}')"
[ -n "$TESTSVC_IP" ] || fail "no testsvc ip"

query() {
    exec_c python3 -c '
import socket, sys
name, qtype = sys.argv[1], int(sys.argv[2])
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
for l in name.split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, ("10.89.0.1", 53)); d, _ = s.recvfrom(2048)
print(".".join(str(b) for b in d[-4:]) if qtype == 1 else ":".join("%02x" % b for b in d[-16:]))
' "$1" "$2"
}

$CE exec magicalane-client sh -c 'rm -f /tmp/fakeip.cache'
$CE exec magicalane-client /usr/local/bin/ws-daemon.sh start "$FILTER_CFG"
for _ in $(seq 1 40); do
    $CE exec magicalane-client sh -c "ss -ltn | grep -q ':7903 ' && iptables -t nat -n -L MGL-NAT >/dev/null 2>&1" >/dev/null 2>&1 && break
    sleep 0.5
done

# ---- 1. filter: real vs token
real="$(query testsvc 1)"
assert_eq "$real" "$TESTSVC_IP" "filter: testsvc answered with its REAL address"
token="$(query origin 1)"
case "$token" in
    198.18.*|198.19.*) pass "filter: origin still gets a fake token ($token)" ;;
    *) fail "filter: origin got a non-token answer: $token" ;;
esac

# ---- 2. persistence: token survives restart
$CE exec magicalane-client /usr/local/bin/ws-daemon.sh stop >/dev/null 2>&1 || true
[ -s /proc/$(true) ] 2>/dev/null
$CE exec magicalane-client sh -c 'test -s /tmp/fakeip.cache' || fail "fakeip cache not written on shutdown"
$CE exec magicalane-client /usr/local/bin/ws-daemon.sh start "$FILTER_CFG"
for _ in $(seq 1 40); do
    $CE exec magicalane-client sh -c "ss -ltn | grep -q ':7903 ' && iptables -t nat -n -L MGL-NAT >/dev/null 2>&1" >/dev/null 2>&1 && break
    sleep 0.5
done
token2="$(query origin 1)"
assert_eq "$token2" "$token" "persist: origin token identical after restart"
$CE exec magicalane-client /usr/local/bin/ws-daemon.sh stop >/dev/null 2>&1 || true
