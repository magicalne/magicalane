# suites: smoke transport
# transports: quic kcp
source "$TESTS_DIR/helpers.sh"
# spin up a client with a wrong password on the same network
$CE rm -f magicalane-client-badpw >/dev/null 2>&1 || true
$CE run -d --rm --name magicalane-client-badpw --label magicalane.env=true \
    --network magicalane-net \
    -v "$ENV_DIR/configs/client-$TEST_TRANSPORT-badpw.toml:/etc/magicalane/client.toml:ro" \
    -v "$ENV_DIR/certs:/etc/magicalane/certs:ro" \
    magicalane:env magicalane --config /etc/magicalane/client.toml >/dev/null
trap '$CE rm -f magicalane-client-badpw >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 30); do
    $CE exec magicalane-client-badpw sh -c "ss -ltn | grep -q ':1080 '" 2>/dev/null && break
    sleep 0.5
done
if $CE exec magicalane-client-badpw sh -c "curl -fsS --max-time 5 --socks5-hostname 127.0.0.1:1080 http://origin/fixtures/hello.txt" >/dev/null 2>&1; then
    fail "wrong password was accepted"
fi
pass "wrong password rejected"
