# suites: transport
# transports: quic kcp
source "$TESTS_DIR/helpers.sh"
expected="$(cut -d' ' -f1 "$ENV_DIR/fixtures/generated/blob-10m.bin.sha256")"
got="$(exec_c sh -c "curl -fsS --max-time 60 --socks5-hostname $SOCKS -o /tmp/blob http://origin/fixtures/generated/blob-10m.bin && sha256sum /tmp/blob | cut -d' ' -f1")" \
    || fail "blob fetch failed"
assert_eq "$got" "$expected" "10MB blob sha256 matches"
