# suites: regression
# transports: quic kcp
# regression: ad8b360 - quinn<=0.8 decoded source addresses via layout-
# incompatible ptr::read (10.89.0.6:40726 became 2.0.159.22:22794), so
# the server replied to a garbage address and handshakes never completed.
# N fresh proxied connections all succeeding pins that fix.
source "$TESTS_DIR/helpers.sh"
for i in $(seq 1 10); do
    curl_socks http://testsvc:8080/id >/dev/null || fail "fresh connection #$i failed"
done
pass "10 sequential fresh proxied connections complete"
