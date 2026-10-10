# suites: regression
# transports: quic
# regression: tproxy reply-eat - the MGL-PRE interception catch-all
# captured conntrack REPLY-direction packets: answers to connections
# the gateway itself initiated (resolver probes, direct connects) were
# TPROXY-swallowed, so direct-path DNS and ALL direct connections
# timed out (production gateway, 2026-10: china sites died while
# tunneled sites worked — only the exempted server IP survived).
# The guard (-m conntrack --ctdir REPLY -j RETURN) must sit at the
# head of the chain, before any MARK/TPROXY rule. (Behaviorally
# verified on the production gateway; rootless-podman labs cannot
# read legacy tables — skip-guarded, see docs.)
source "$TESTS_DIR/helpers.sh"

# rootless podman: even -u 0 lacks CAP_NET_ADMIN over the initial
# netns for legacy tables -> skip like the other rule-reading tests.
pre="$($CE exec -u 0 magicalane-client iptables-legacy -t mangle -S MGL-PRE 2>/dev/null)"
if [ -z "$pre" ]; then
    echo "  skip: cannot read iptables (rootless lab; see 040 header)" >&2
    exit 0
fi
guard_line="$(printf '%s\n' "$pre" | grep -n -- '--ctdir REPLY' | head -1 | cut -d: -f1)"
[ -n "$guard_line" ] || fail "MGL-PRE has no conntrack REPLY guard (reply-eat regression)"
assert_eq "$guard_line" "1" "reply guard is the first MGL-PRE rule"

pre6="$($CE exec -u 0 magicalane-client ip6tables-legacy -t mangle -S MGL6-PRE 2>/dev/null || true)"
if [ -n "$pre6" ]; then
    g6="$(printf '%s\n' "$pre6" | grep -n -- '--ctdir REPLY' | head -1 | cut -d: -f1)"
    [ -n "$g6" ] || fail "MGL6-PRE installed but missing the REPLY guard"
    pass "v6 plane guarded too"
fi
pass "reply-direction guard present and first"
