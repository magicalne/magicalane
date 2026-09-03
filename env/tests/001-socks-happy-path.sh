# suites: smoke transport
# transports: quic kcp
source "$TESTS_DIR/helpers.sh"
out="$(curl_socks http://origin/fixtures/hello.txt)" || fail "proxied fetch failed"
assert_eq "$out" "$(fixture hello.txt)" "socks5 happy path: content matches fixture"
