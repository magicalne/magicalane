# suites: dns tproxy-ws
# transports: quic kcp
# DNS module: queries from the workstation must resolve through the tunnel
# (server-side upstream), not leak.
source "$TESTS_DIR/helpers.sh"
ws_start
got="$(exec_c getent hosts origin | awk '{print $1}')" || true
ws_stop
[ -n "$got" ] || fail "origin did not resolve through tunnel dns"
origin_ip="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
assert_eq "$got" "$origin_ip" "dns: origin resolved via tunnel to its real address"
