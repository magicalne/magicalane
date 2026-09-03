# suites: smoke transport
# transports: quic kcp
source "$TESTS_DIR/helpers.sh"
if exec_c curl -fsS --max-time 6 --socks5-hostname "$SOCKS" http://192.0.2.1:1/ >/dev/null 2>&1; then
    fail "unreachable destination unexpectedly succeeded"
fi
pass "unreachable destination fails fast"
