# suites: residue
# transports: quic kcp
# Clean-exit contract, graceful path: after SIGTERM the client container's
# network state must be byte-identical to before startup.
source "$TESTS_DIR/helpers.sh"
before="$(ws_snapshot)"
ws_start
ws_rules_present || { ws_stop; fail "rules not installed while running"; }
ws_stop
ws_wait_gone
after="$(ws_snapshot)"
assert_eq "$after" "$before" "residue: graceful exit leaves network state byte-identical"
if ws_rules_present; then
    fail "MGL chains still present after graceful stop"
fi
pass "residue: chains removed after graceful stop"
