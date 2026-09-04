# suites: fakeip v6 residue
# transports: quic
# v6 clean-exit contract (CP3): kill -9 leaves the MGL6 mirror behind
# (no cleanup ran); the NEXT start adopts the stale state; after a
# graceful stop both families are clean. Mirrors 021 for the v6 plane.
source "$TESTS_DIR/helpers.sh"
FAKEIP_CFG="/etc/magicalane/client-ws-fakeip.toml"

ws_start_cfg "$FAKEIP_CFG"
# v6 plane must be live while running
chains="$($CE exec magicalane-client ip6tables -t nat -S 2>/dev/null | grep -c '^-N MGL6-NAT')"
assert_eq "$chains" "1" "v6: MGL6-NAT chain exists while running"
rule="$($CE exec magicalane-client ip -6 rule 2>/dev/null | grep -c 'lookup 141')"
[ "$rule" -ge 1 ] || fail "v6: policy rule missing while running"

ws_stop KILL
ws_wait_gone
stale="$($CE exec magicalane-client ip6tables -t nat -S 2>/dev/null | grep -c '^-N MGL6-NAT')"
[ "$stale" = "1" ] || fail "v6: expected stale MGL6 chains after kill -9 (test premise)"
pass "v6: stale rules present after kill -9 (as designed)"

# restart adopts the stale v6 state (startup teardown), then graceful stop
ws_start_cfg "$FAKEIP_CFG"
ws_stop
ws_wait_gone
ws_wait_clean

left_chains="$($CE exec magicalane-client ip6tables -S 2>/dev/null | grep -c 'MGL6')"
assert_eq "$left_chains" "0" "v6: adoption cleans stale chains (kill -9 residue gone)"
left_rule="$($CE exec magicalane-client ip -6 rule 2>/dev/null | grep -c 'lookup 141')"
assert_eq "$left_rule" "0" "v6: no policy rule remains after adoption+stop"
