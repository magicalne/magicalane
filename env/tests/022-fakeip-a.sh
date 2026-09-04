# suites: fakeip tproxy-ws
# transports: quic kcp
# Fake-IP DNS (CP1): A queries answered LOCALLY from 198.18.0.0/15 and
# connections to the token still reach the destination (mapped back to
# the domain at connect time, tunneled by name). Podman writes aliases
# into /etc/hosts, so the flow is driven with raw sockets in python.
source "$TESTS_DIR/helpers.sh"
FAKEIP_CFG="/etc/magicalane/client-ws-fakeip.toml"

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
    token = query("testsvc")
except Exception as e:
    print("FAIL:dns-query:" + repr(e)); sys.exit(0)
if not (token.startswith("198.18.") or token.startswith("198.19.")):
    print("FAIL:token:" + token); sys.exit(0)
if query("testsvc") != token:
    print("FAIL:unstable"); sys.exit(0)
try:
    body = urllib.request.urlopen("http://%s:8080/hello" % token, timeout=15).read().decode().strip()
except Exception as e:
    print("FAIL:fetch:" + repr(e)); sys.exit(0)
if body == "magicalane-test-service":
    print("OK:" + token)
else:
    print("FAIL:body:" + repr(body))
')"
ws_stop

case "$result" in
    OK:198.1[89].*) echo "    fake token: ${result#OK:}" ;;
    *) fail "fakeip flow failed: $result" ;;
esac
