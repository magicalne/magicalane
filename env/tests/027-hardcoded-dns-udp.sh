# suites: fakeip udp
# transports: quic kcp
# Fake-IP + UDP (CP5): hardcoded resolvers (8.8.8.8) get intercepted
# (udp/53 REDIRECT is destination-agnostic) and UDP datagrams sent to a
# fake token are TPROXY'd, mapped back to the domain, and tunneled by
# name (the server resolves the UDP destination server-side).
source "$TESTS_DIR/helpers.sh"
FAKEIP_CFG="/etc/magicalane/client-ws-fakeip.toml"

ws_start_cfg "$FAKEIP_CFG"
result="$(exec_c python3 -c '
import socket, sys

# 1. A hardcoded resolver (8.8.8.8) still gets the fake layer: the
#    udp/53 REDIRECT matches ANY destination.
def query(ns, name):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, (ns, 53))
    data, _ = s.recvfrom(2048)
    if len(data) < 28:
        raise RuntimeError("short response")
    return ".".join(str(b) for b in data[-4:])

try:
    token = query("8.8.8.8", "testsvc")
except Exception as e:
    print("FAIL:hardcoded-dns:" + repr(e)); sys.exit(0)
if not (token.startswith("198.18.") or token.startswith("198.19.")):
    print("FAIL:token:" + token); sys.exit(0)

# 2. UDP datagram flow THROUGH the fake token: TPROXY -> domain mapping
#    -> tunneled by domain -> server resolves testsvc -> echo.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    payload = b"mgl-udp-fake-9c2f"
    s.sendto(payload, (token, 9002))
    data, peer = s.recvfrom(2048)
    ok = "echo" if data == payload else "wrong:" + repr(data)
except Exception as e:
    ok = "FAIL:udp:" + repr(e)
print("OK:" + token + ":" + ok)
')"
ws_stop

case "$result" in
    OK:198.1[89].*:echo) echo "    hardcoded dns + udp fake flow: ${result%%:*}" ;;
    *) fail "hardcoded-dns/udp flow failed: $result" ;;
esac
