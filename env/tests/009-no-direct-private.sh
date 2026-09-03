# suites: smoke transport
# transports: quic kcp
# Negative twin of 008: without the tunnel the private service must be
# unreachable (http + tcp + udp). Pair with 008 for a trustworthy signal.
source "$TESTS_DIR/helpers.sh"
TESTSVC_IP="$($CE inspect magicalane-testsvc --format '{{(index .NetworkSettings.Networks "magicalane-backend").IPAddress}}')"

if curl_direct http://testsvc:8080/id >/dev/null 2>&1; then
    fail "direct HTTP to private service succeeded (leak!)"
fi
pass "direct HTTP to private service unreachable"

if exec_c timeout 3 bash -c "exec 3<>/dev/tcp/$TESTSVC_IP/9001" 2>/dev/null; then
    fail "direct TCP to private service connected (leak!)"
fi
pass "direct TCP to private service unreachable"

leak="$(exec_c python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
try:
    s.sendto(b'probe', ('testsvc', 9002)); s.recvfrom(2048); print('leak')
except OSError:
    print('silent')
")"
assert_eq "$leak" "silent" "direct UDP to private service unreachable"
