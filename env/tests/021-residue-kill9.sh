# suites: residue
# transports: quic kcp
# Clean-exit contract, kill -9 path: rules survive the kill (no cleanup ran),
# and the NEXT start adopts and replaces the stale state; after its graceful
# stop the system is clean again.
source "$TESTS_DIR/helpers.sh"
before_chains="$(ws_snapshot_chains)"
before_rules="$(ws_snapshot_rules)"
ws_start
ws_stop KILL
ws_wait_gone
ws_rules_present || fail "expected stale rules after kill -9 (test premise)"
pass "residue: stale rules present after kill -9 (as designed)"
# restart adopts stale state
ws_start
ws_stop
ws_wait_gone
ws_wait_clean
after_chains="$(ws_snapshot_chains)"
after_rules="$(ws_snapshot_rules)"
assert_eq "$after_chains" "$before_chains" "residue: adoption cleans stale state"
assert_eq "$after_rules" "$before_rules" "residue: no policy routes after adoption+stop"
