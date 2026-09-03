# suites: residue
# transports: quic kcp
# Clean-exit contract, graceful path: after SIGTERM the client container's
# network state must have no MGL chains, no policy routing entries, and
# no listeners on our ports.
source "$TESTS_DIR/helpers.sh"
before_chains="$(ws_snapshot_chains)"
before_rules="$(ws_snapshot_rules)"
ws_start
ws_rules_present || { ws_stop; fail "rules not installed while running"; }
ws_stop
ws_wait_gone
ws_wait_clean
after_chains="$(ws_snapshot_chains)"
after_rules="$(ws_snapshot_rules)"
assert_eq "$after_chains" "$before_chains" "residue: no MGL chains after graceful stop"
assert_eq "$after_rules" "$before_rules" "residue: no policy routes after graceful stop"
if ws_rules_present; then
    fail "MGL chains still present after graceful stop"
fi
pass "residue: chains removed after graceful stop"
