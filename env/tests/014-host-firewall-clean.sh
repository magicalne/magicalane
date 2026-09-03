# suites: smoke tproxy
# transports: any
source "$TESTS_DIR/helpers.sh"
if ! sudo -n true 2>/dev/null; then
    echo "  skip: no passwordless sudo" >&2
    exit 0
fi
if sudo -n nft list ruleset 2>/dev/null | grep -i tproxy; then
    fail "host nft ruleset contains tproxy rules"
fi
pass "host firewall free of tproxy rules"
