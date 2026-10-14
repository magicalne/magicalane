# suites: regression tproxy-ws
# transports: quic kcp
# regression: issue #23 — UDP self-relay storm
#
# One datagram addressed to the client's OWN udp interceptor port used to
# be relayed "direct" back to the same port: the interceptor's wildcard
# listener received its own forwarded packet (new ephemeral source = new
# flow key) and relayed it again — a self-sustaining chain that minted a
# flow task + fd + 64KiB buffer per hop. Production (2026-10-13) hit fd
# exhaustion within ~5s (~28k flows, ~2GB transient heap per storm,
# retained by glibc arenas as the reported GB/day RSS "leak").
#
# Post-fix: the interceptor drops self-destined datagrams (and any
# multicast/broadcast dst) before flow creation; iptables also exempts
# the interception ports as destinations. This test seeds the loop and
# asserts it cannot start.
source "$TESTS_DIR/helpers.sh"

LOOP_CFG="/etc/magicalane/client-$TEST_TRANSPORT-ws-loop.toml"
exec_c test -f "$LOOP_CFG" || skip "no loop config for transport $TEST_TRANSPORT"

ws_start_cfg "$LOOP_CFG" 7897
trap 'ws_stop 2>/dev/null' EXIT

WS_PID="$(exec_c cat /tmp/ws-client.pid 2>/dev/null)"
[ -n "$WS_PID" ] || fail "no ws pid"
exec_c grep -q 'State:.*Z' "/proc/$WS_PID/status" 2>/dev/null && fail "ws instance is a zombie"

# own lab address + interceptor port (7898 per the loop config)
OWN_IP="$(exec_c sh -c "hostname -I | tr ' ' '\n' | grep -m1 '^10\\.'")"
[ -n "$OWN_IP" ] || OWN_IP="$(exec_c sh -c "hostname -i")"
case "$OWN_IP" in
    10.89.*) ;;
    *) fail "unexpected client address '$OWN_IP'" ;;
esac
UDP_PORT=7898

fd_count() { exec_c sh -c "ls /proc/$WS_PID/fd 2>/dev/null | wc -l"; }
base_fds="$(fd_count)"
[ "${base_fds:-0}" -gt 5 ] || fail "ws instance fd baseline looks wrong ($base_fds)"

# seed: ONE datagram to our own interceptor port (how the production
# storm started: a LAN client's connected-UDP reply to gw:7896)
exec_c python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'seed', ('$OWN_IP', $UDP_PORT))
print('seeded')"

# pre-fix: fds grow by thousands per second here; give the chain room to
# run, then demand it never started
sleep 8
now_fds="$(fd_count)"
rss="$(exec_c sh -c "grep VmRSS /proc/$WS_PID/status" | awk '{print $2}')"
echo "  info: fds $base_fds -> $now_fds, rss ${rss:-?} kB"

[ "${now_fds:-0}" -le $((base_fds + 64)) ] \
    || fail "self-relay storm: fds went $base_fds -> $now_fds (expected <=$((base_fds+64)))"

# the drop must be visible in the ws log (warn level)
exec_c sh -c "grep -q 'dropped self-destined' /tmp/ws.log" \
    || fail "no self-destined drop logged in /tmp/ws.log"

# the iptables exemptions must be LOCAL-scoped (review: a dst-port-only
# RETURN would bypass interception for REMOTE services that happen to
# use the same port number)
scoped="$(exec_c sh -c 'iptables-save 2>/dev/null | grep -c "dport 7897.*addrtype.*dst-type LOCAL"')"
[ "${scoped:-0}" -ge 1 ] || fail "MGL-NAT tcp_port exemption not LOCAL-scoped (addrtype)"
scoped_u="$(exec_c sh -c 'iptables-save -t mangle 2>/dev/null | grep -c "dport 7898.*addrtype.*dst-type LOCAL"')"
[ "${scoped_u:-0}" -ge 1 ] || fail "MGL-OUT udp_port exemption not LOCAL-scoped (addrtype)"
pass "interception-port exemptions are LOCAL-scoped"

# TCP twin (review round 5): a connection to our OWN transparent TCP
# port must be explicitly refused by the user-space self-destination
# guard (tproxy::serve/serve6), not just silently closed by the dst-
# resolution fallback.
TCP_PORT=7897
exec_c python3 -c "
import socket
s = socket.create_connection(('$OWN_IP', $TCP_PORT), timeout=5)
s.settimeout(4)
s.sendall(b'GET / HTTP/1.1\r\n\r\n')
try:
    d = s.recv(64)
    closed = (d == b'')
except OSError:
    closed = True  # reset by peer
if not closed:
    raise SystemExit('self-destined TCP conn was not refused: got data')
print('self-destined TCP conn refused')"
sleep 1
exec_c sh -c "grep -q 'dropped self-destined conn' /tmp/ws.log" \
    || fail "no explicit self-destined TCP drop logged in /tmp/ws.log"
pass "TCP self-destined conn explicitly refused + logged"

# NOTE: the broadcast/multicast drop (LAN mDNS -> EPERM retry loop in
# production, gateway-mode PREROUTING interception) is not exercisable
# here: rootless podman cannot TPROXY forwarded traffic (kernel >=
# 6.12.107 userns regression, see 011) and self-sent broadcast/multicast
# never loops back via lo. That path is pinned by the unit tests
# (broadcast_and_multicast_are_dropped) and the production gateway.
exec_c python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.sendto(b'bcast', ('10.89.0.255', 5353))"
sleep 2
now_fds2="$(fd_count)"
[ "${now_fds2:-0}" -le $((base_fds + 64)) ] \
    || fail "broadcast minted flows (fds $base_fds -> $now_fds2)"

pass "self-destined datagrams dropped; no storm"
