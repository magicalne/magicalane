# suites: fakeip v6 routing
# transports: quic
# China-direct over IPv6 (the RFC 6724 case): a direct-rule domain
# fetched via its fake AAAA token must connect DIRECTLY over the
# client's NATIVE IPv6 — origin's access log must show the client's
# global v6 address (fd00:...), not the server, not v4-mapped.
source "$TESTS_DIR/helpers.sh"
FAKEIP_CFG="/etc/magicalane/client-ws-fakeip.toml"

CLIENT_V6="$($CE inspect magicalane-client --format '{{(index .NetworkSettings.Networks "magicalane-net").GlobalIPv6Address}}')"
[ -n "$CLIENT_V6" ] || fail "client has no global v6 (env not dual-stack?)"

ws_start_cfg "$FAKEIP_CFG"
result="$(exec_c python3 -c '
import socket, sys, urllib.request

def query(name, qtype):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, ("10.89.0.1", 53))
    d, _ = s.recvfrom(2048)
    return d

# 1. AAAA for the direct-rule domain -> fake v6 token
try:
    d = query("origin", 28)
    tok = ":".join("%x" % int.from_bytes(d[i:i+2], "big") for i in range(len(d)-16, len(d), 2))
except Exception as e:
    print("FAIL:aaaa:" + repr(e)); sys.exit(0)
if not tok.startswith("fc00"):
    print("FAIL:token:" + tok); sys.exit(0)

# 2. Fetch THROUGH the v6 token: intercepted -> domain -> DIRECT rule
#    -> local AAAA resolution -> native v6 connect.
try:
    body = urllib.request.urlopen(
        "http://[%s]:80/fixtures/hostname" % tok, timeout=10
    ).read().decode().strip()
except Exception as e:
    print("FAIL:fetch:" + repr(e)); sys.exit(0)
print("OK:" + tok + ":" + body)
')"
ws_stop

origin_host="$($CE exec magicalane-origin cat /etc/hostname)"
case "$result" in
    OK:fc00*:"$origin_host") : ;;
    *) fail "v6 direct: fetch via AAAA token failed: $result" ;;
esac

# Egress proof: the access-log peer is the client's GLOBAL v6.
logline="$($CE logs --since 2m magicalane-origin 2>&1 | grep 'GET /fixtures/hostname' | tail -1)"
case "$logline" in
    "$CLIENT_V6"*) echo "    v6 direct egress: $CLIENT_V6" ;;
    ::ffff:*|127.0.0.1*) fail "v6 direct: peer is v4-mapped/loopback, not native v6: $logline" ;;
    *) fail "v6 direct: unexpected peer in origin log: $logline" ;;
esac
