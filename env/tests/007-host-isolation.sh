# suites: smoke
# transports: any
source "$TESTS_DIR/helpers.sh"
if ss -ltn 2>/dev/null | grep -qE ':(1080|4433) '; then
    fail "host has a listener on 1080/4433"
fi
pass "no host listeners on proxy ports"
if curl -fsS --max-time 2 --socks5-hostname 127.0.0.1:1080 http://origin/ >/dev/null 2>&1; then
    fail "host could reach the client socks port"
fi
pass "host cannot reach client socks port"
