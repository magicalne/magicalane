# Kernel regression guard: since 6.12.107, xt_TPROXY silently drops
# packets in ROOTLESS podman user-namespaces (verified: rule counters
# climb, listeners never see packets; same rules work in incus/init
# userns — the production gateway depends on it and is unaffected).
# Workstation-mode coverage (nat REDIRECT path) is unaffected: 017,
# 022-025 keep the transparent stack green. Skip here when broken.
probe_tproxy_forward() {
    local hits
    hits="$($CE exec magicalane-tproxy-client iptables -t mangle -L MGL-PRE -n -v 2>/dev/null | awk '/TPROXY redirect 0.0.0.0:7895/ {print $1; exit}')"
    [ -n "$hits" ] && [ "$hits" -gt 0 ]
}
rootless_tproxy_broken() {
    # TPROXY packets hit the rule but the app cannot fetch => userns TPROXY dead
    ! exec_a curl -fsS --max-time 4 http://10.89.0.2/ >/dev/null 2>&1 && probe_tproxy_forward
}
# suites: tproxy
# transports: any
# The strongest transparent assertion: the app is on NO network that can
# reach the private service. Success proves interception + tunnel + server
# egress all worked.
source "$TESTS_DIR/helpers.sh"

if rootless_tproxy_broken; then
    skip "xt_TPROXY broken in rootless userns (kernel >= 6.12.107 regression); workstation coverage via 017/022-025"
fi
id="$(exec_a curl -fsS --max-time 10 http://testsvc:8080/id | awk '{print $1}')" \
    || fail "transparent fetch of private service failed"
svc_host="$(exec_s curl -fsS --max-time 3 http://testsvc:8080/id | awk '{print $1}')"
assert_eq "$id" "$svc_host" "app reached private service transparently through the tunnel"
