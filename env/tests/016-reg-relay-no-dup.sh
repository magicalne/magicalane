# suites: regression
# transports: quic kcp
# regression: 8f687a7 - the relay state machine re-wrote its 1-byte flag
# on every Pending re-poll (harmless over QUIC, corrupting over TLS-on-KCP:
# a stream of 0x00 bytes preceded the payload). POST /echo through the
# tunnel must return the body byte-exact.
source "$TESTS_DIR/helpers.sh"
body="$(head -c 3000 /dev/urandom | base64 | tr -d '\n')"
out="$(exec_c curl -fsS --max-time 20 --socks5-hostname "$SOCKS" \
    -X POST --data-binary "$body" http://testsvc:8080/echo)" \
    || fail "echo request failed"
assert_eq "$out" "$body" "relayed body is byte-exact (no injected flag bytes)"
