# Bypass-router mode: a LAN device that ONLY sets default route + DNS to
# the gateway (the "one-box bypass router" client story).
# Covers what gateway=true alone does NOT provide:
#   - ICMP transit (ping through the gateway: ip_forward + FORWARD
#     accept + POSTROUTING MASQUERADE from bypass_router)
#   - DNS over TCP on udp-style port 53 (both to the gw directly and
#     transit tcp/53 — RFC 7766 fallback resolvers use it)
#   - clean teardown of the bypass extras (MGL-FWD/MGL-MASQ removed,
#     no duplicated builtin jumps after a restart re-apply)
# The TCP/UDP interception assertions need working xt_TPROXY; on hosts
# where that is broken in rootless userns we still run the
# interception-independent parts (ICMP + DNS) instead of skipping.
# suites: tproxy
# transports: any
source "$TESTS_DIR/helpers.sh"

GW="magicalane-tproxy-client"
LAN_IP="$($CE inspect "$GW" --format '{{(index .NetworkSettings.Networks "magicalane-lan").IPAddress}}')"
ORIGIN_IP="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
[ -n "$LAN_IP" ] && [ -n "$ORIGIN_IP" ] || fail "could not derive lab IPs (LAN=$LAN_IP ORIGIN=$ORIGIN_IP)"

exec_gw() { $CE exec "$GW" "$@"; }

# Self-heal the app's route pin: container restarts can move the gw's
# lan IP (aardvark reassigns), and up.sh only re-pins at deploy time.
exec_a ip route replace default via "$LAN_IP" dev eth0

# Kernel regression guard (see 011/012): xt_TPROXY silently drops in
# ROOTLESS podman user-namespaces since 6.12.107. Only the TPROXY-
# dependent assertion is gated; ICMP/DNS parts above are nat-REDIRECT /
# FORWARD based and unaffected.
probe_tproxy_forward() {
    local hits
    hits="$(exec_gw iptables -t mangle -L MGL-PRE -n -v 2>/dev/null | awk '/TPROXY redirect 0.0.0.0:7895/ {print $1; exit}')"
    [ -n "$hits" ] && [ "$hits" -gt 0 ]
}
rootless_tproxy_broken() {
    ! exec_a curl -fsS --max-time 4 http://10.89.0.2/ >/dev/null 2>&1 && probe_tproxy_forward
}

# --- the app is a pure bypass client: default route via the gw -------
echo "-- app default route via gateway ($LAN_IP)"
route="$(exec_a ip route show default)"
assert_contains "$route" "via $LAN_IP" "app default route points at the gateway"

# --- bypass state installed by the client itself --------------------
echo "-- bypass chains + forwarding present in gateway"
exec_gw iptables -t filter -n -L MGL-FWD >/dev/null 2>&1 || fail "MGL-FWD (FORWARD accept) missing"
pass "MGL-FWD present"
exec_gw iptables -t nat -n -L MGL-MASQ >/dev/null 2>&1 || fail "MGL-MASQ (POSTROUTING masquerade) missing"
pass "MGL-MASQ present"
fw="$(exec_gw cat /proc/sys/net/ipv4/ip_forward 2>/dev/null | tr -d '[:space:]')"
assert_eq "$fw" "1" "ip_forward enabled (in-process, or container sysctl where /proc/sys is RO)"
# single jump per builtin chain: re-apply must not stack duplicates
dups="$(exec_gw sh -c 'iptables-save | grep -c -- "-A POSTROUTING -j MGL-MASQ"')"
assert_eq "$dups" "1" "exactly one POSTROUTING->MGL-MASQ jump"

# --- ICMP through the gateway (the core bypass capability) ----------
echo "-- ICMP transit (ping origin through the gw, NAT'd both ways)"
fwd_before="$(exec_gw iptables -t filter -L MGL-FWD -n -v | awk '/ACCEPT/ {print $1; exit}')"
[ -n "$fwd_before" ] || fwd_before=0
exec_a ping -c 2 -W 3 "$ORIGIN_IP" >/dev/null 2>&1 || fail "ping through gateway failed (forwarding/MASQ)"
pass "ICMP forwarded through the gateway"
fwd_after="$(exec_gw iptables -t filter -L MGL-FWD -n -v | awk '/ACCEPT/ {print $1; exit}')"
[ -n "$fwd_after" ] || fwd_after=0
[ "$fwd_after" -gt "$fwd_before" ] \
    || fail "ping did not traverse MGL-FWD (took a parallel path; counters $fwd_before -> $fwd_after)"
pass "ICMP provably traversed the gateway's FORWARD chain"
exec_a ping -c 1 -W 3 "$LAN_IP" >/dev/null 2>&1 || fail "ping to gateway itself failed"
pass "ICMP to the gateway itself"

# --- DNS: the gw is the resolver (udp AND tcp) ----------------------
echo "-- DNS via gateway as resolver"
# UDP to the gw's :53 (PREROUTING REDIRECT -> fakeip)
a="$(exec_a dig +time=3 +tries=1 +short "@$LAN_IP" origin A 2>/dev/null | head -1)"
case "$a" in 198.18.*) pass "udp DNS to gw answers fakeip ($a)";; *) fail "udp DNS to gw: expected fakeip, got '$a'";; esac
# TCP to the gw's :53 (new tcp/53 REDIRECT + DNS TCP listener)
a="$(exec_a dig +time=3 +tries=1 +tcp +short "@$LAN_IP" origin A 2>/dev/null | head -1)"
case "$a" in 198.18.*) pass "tcp DNS to gw answers fakeip ($a)";; *) fail "tcp DNS to gw: expected fakeip, got '$a'";; esac
# transit tcp/53 aimed elsewhere still lands in the interceptor
a="$(exec_a dig +time=3 +tries=1 +tcp +short @8.8.8.8 origin A 2>/dev/null | head -1)"
case "$a" in 198.18.*) pass "transit tcp/53 intercepted -> fakeip ($a)";; *) fail "transit tcp/53: expected fakeip, got '$a'";; esac

# --- resolv.conf = gateway only (the exact user scenario) -----------
echo "-- app with DNS= only the gateway"
exec_a sh -c "printf 'nameserver $LAN_IP\n' > /etc/resolv.conf"
# note: `origin` is pinned in /etc/hosts (files precede dns in nsswitch),
# so use an unpinned name to force the resolver path.
got="$(exec_a getent ahostsv4 example.com 2>/dev/null | awk '{print $1; exit}')"
case "$got" in 198.18.*) pass "getent via gw-DNS returns fakeip ($got)";; *) fail "getent via gw-DNS: expected fakeip, got '$got'";; esac
# restore the lab default (other tests assume routed DNS transit)
exec_a sh -c "printf 'nameserver 8.8.8.8\n' > /etc/resolv.conf"

# --- transparent fetch (needs working xt_TPROXY) --------------------
if rootless_tproxy_broken; then
    echo "  SKIP: transparent TCP fetch (xt_TPROXY broken in rootless userns; ICMP/DNS parts above still ran)"
else
    out="$(exec_a curl -fsS --max-time 10 http://origin/fixtures/hello.txt)" \
        || fail "transparent fetch failed"
    assert_eq "$out" "$(fixture hello.txt)" "transparent fetch matches fixture (zero proxy config)"
fi

# --- teardown contract for the bypass extras ------------------------
echo "-- stop/start: clean exit, adopt re-applies without stacking"
$CE stop -t 15 "$GW" >/dev/null 2>&1 || fail "gateway container stop failed"
rc="$($CE inspect "$GW" --format '{{.State.ExitCode}}')"
assert_eq "$rc" "0" "gateway exited cleanly on SIGTERM (teardown ran)"
# the container netns (and its rules) is gone with the stop; the restart
# is the oracle: adoption (apply -> teardown first) must not stack
# duplicate jumps on the builtin chains.
$CE start "$GW" >/dev/null 2>&1 || fail "gateway container start failed"
# aardvark may hand the restarted container a DIFFERENT lan IP: re-derive
# it and re-pin the app's default route (same as up.sh does at deploy).
LAN_IP="$($CE inspect "$GW" --format '{{(index .NetworkSettings.Networks "magicalane-lan").IPAddress}}')"
[ -n "$LAN_IP" ] || fail "no lan IP after restart"
exec_a ip route replace default via "$LAN_IP" dev eth0
for _ in $(seq 1 40); do
    if exec_gw sh -c 'iptables -t nat -n -L MGL-MASQ >/dev/null 2>&1 && iptables -t filter -n -L MGL-FWD >/dev/null 2>&1' 2>/dev/null; then
        break
    fi
    sleep 0.5
done
exec_gw iptables -t nat -n -L MGL-MASQ >/dev/null 2>&1 || fail "MGL-MASQ not re-applied after restart"
pass "bypass chains re-applied after restart"
for chain in "POSTROUTING -j MGL-MASQ" "FORWARD -j MGL-FWD" "PREROUTING -j MGL-PRENAT" "OUTPUT -j MGL-NAT"; do
    n="$(exec_gw sh -c "iptables-save | grep -c -- '-A $chain'")"
    assert_eq "$n" "1" "single jump after restart: $chain"
done
# and the bypass behavior itself still works post-restart
exec_a ping -c 2 -W 3 "$ORIGIN_IP" >/dev/null 2>&1 || fail "ICMP through gateway broken after restart (lan ip $LAN_IP)"
pass "ICMP still forwarded after restart"

echo "PASS: 040-gw-bypass"
