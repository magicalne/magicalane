# suites: tproxy-ws udp
# transports: quic kcp
# UDP relay (phase 2): a datagram to the private UDP echo service from the
# workstation must be answered through the tunnel.
source "$TESTS_DIR/helpers.sh"
ws_start
reply="$(exec_c python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(8)
payload = b'mgl-udp-probe-7f3a'
try:
    s.sendto(payload, ('testsvc', 9002))
    data, _ = s.recvfrom(2048)
    print('echo' if data == payload else 'wrong:' + repr(data))
except OSError as e:
    print('error:', e)
")"
ws_stop
assert_eq "$reply" "echo" "ws: UDP datagram relayed to private service and echoed"
