# suites: fakeip v6
# transports: quic
# Fake-IP AAAA (CP4): AAAA queries (v4- AND v6-carried) return fc00::/18
# tokens; fetching through the v6 token is intercepted by the MGL6
# mirror, mapped back to the domain, and tunneled by name.
source "$TESTS_DIR/helpers.sh"
FAKEIP_CFG="/etc/magicalane/client-ws-fakeip.toml"

ws_start_cfg "$FAKEIP_CFG"
result="$(exec_c python3 -c '
import socket, sys, urllib.request

def query(name, qtype, use_v6_dns=False):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    if use_v6_dns:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        ns = ("fd00:89::1", 53)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ns = ("10.89.0.1", 53)
    s.settimeout(5)
    s.sendto(q, ns)
    data, _ = s.recvfrom(2048)
    return data

# 1. AAAA via v4-carried query -> fc00 token
try:
    r = query("testsvc", 28)
    tok6 = r[-16:]
    text = "".join("%02x" % b for b in tok6)
except Exception as e:
    print("FAIL:aaaa-query:" + repr(e)); sys.exit(0)
if not text.startswith("fc00"):
    print("FAIL:not-fc00:" + text); sys.exit(0)

# 2. stable
if query("testsvc", 28)[-16:] != tok6:
    print("FAIL:unstable"); sys.exit(0)

# 3. fetch via the v6 token: intercepted (MGL6), mapped, tunneled by name
import ipaddress
v6 = str(ipaddress.IPv6Address(tok6))
try:
    body = urllib.request.urlopen("http://[%s]:8080/hello" % v6, timeout=15).read().decode().strip()
except Exception as e:
    print("FAIL:fetch:" + repr(e)); sys.exit(0)
if body != "magicalane-test-service":
    print("FAIL:body:" + repr(body)); sys.exit(0)

# 4. AAAA via a V6-carried query (resolver fd00:89::1) also faked
try:
    r = query("origin", 28, use_v6_dns=True)
    if not "".join("%02x" % b for b in r[-16:]).startswith("fc00"):
        print("FAIL:v6-dns-not-faked"); sys.exit(0)
except Exception as e:
    print("FAIL:v6-dns-query:" + repr(e)); sys.exit(0)

print("OK:" + v6)
')"
ws_stop

case "$result" in
    OK:fc00*) echo "    fake v6 token: ${result#OK:}" ;;
    *) fail "fakeip v6 flow failed: $result" ;;
esac
