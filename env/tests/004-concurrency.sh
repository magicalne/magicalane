# suites: transport
# transports: quic kcp
source "$TESTS_DIR/helpers.sh"
exec_c sh -c "seq 1 20 | xargs -P20 -I{} curl -fsS --max-time 30 --socks5-hostname $SOCKS http://origin/fixtures/hello.txt -o /dev/null" \
    || fail "parallel fetches failed"
pass "20 parallel proxied fetches succeed"
