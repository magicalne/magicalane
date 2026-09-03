# suites: smoke transport
# transports: quic kcp
source "$TESTS_DIR/helpers.sh"
fetched="$(curl_socks http://origin/fixtures/hostname)" || fail "hostname fetch failed"
origin_host="$($CE exec magicalane-origin cat /etc/hostname)"
assert_eq "$fetched" "$origin_host" "proxied fetch really served by origin"
