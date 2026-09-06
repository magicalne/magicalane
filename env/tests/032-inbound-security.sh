# suites: security inbound
# transports: quic kcp
# Inbound security bundle:
#  1. default bind is 127.0.0.1 — a LAN peer (the server container) is refused
#  2. allow_lan + socks5_users: wrong password refused; right creds work
#     from BOTH loopback and the LAN
#  3. mixed-port HTTP proxy: absolute-form GET through the proxy works;
#     CONNECT works; HTTP path enforces Basic auth too
source "$TESTS_DIR/helpers.sh"
AUTH_CFG="/etc/magicalane/client-ws-auth.toml"

CLIENT_NET_IP="$($CE inspect magicalane-client --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
[ -n "$CLIENT_NET_IP" ] || fail "no client ip"

# ---- 1. default (main client, no allow_lan) refuses LAN peers
exec_s curl -fsS --max-time 4 --socks5-hostname "$CLIENT_NET_IP:1080" http://testsvc:8080/hello \
    && fail "main socks port is reachable from the LAN (must default to 127.0.0.1)"
pass "inbound: default bind is loopback-only (LAN peer refused)"

# ---- start the auth+allow_lan instance
$CE exec magicalane-client /usr/local/bin/ws-daemon.sh start "$AUTH_CFG"
for _ in $(seq 1 40); do
    $CE exec magicalane-client sh -c "ss -ltn | grep -q ':1085 '" >/dev/null 2>&1 && break
    sleep 0.5
done
$CE exec magicalane-client sh -c "ss -ltn | grep -q ':1085 '" || fail "auth instance not listening"

# ---- 2a. wrong password refused (loopback)
exec_c curl -fsS --max-time 6 --socks5-hostname "bob:wrong@127.0.0.1:1085" http://testsvc:8080/hello \
    && fail "wrong password accepted"
pass "inbound: wrong SOCKS5 credentials refused"

# ---- 2b. right creds via SOCKS5 from loopback
body="$(exec_c curl -fsS --max-time 10 --socks5-hostname "alice:secret@127.0.0.1:1085" http://testsvc:8080/hello)" \
    || fail "socks5 auth loopback fetch failed"
assert_eq "$body" "magicalane-test-service" "inbound: socks5+auth (loopback) reaches testsvc"

# ---- 2c. right creds from the LAN (server container)
body="$(exec_s curl -fsS --max-time 10 --socks5-hostname "alice:secret@$CLIENT_NET_IP:1085" http://testsvc:8080/hello)" \
    || fail "socks5 auth LAN fetch failed"
assert_eq "$body" "magicalane-test-service" "inbound: socks5+auth reachable from LAN (allow_lan)"

# ---- 3a. HTTP proxy (absolute-form) with auth, via the same mixed port
body="$(exec_c curl -fsS --max-time 10 -x "http://alice:secret@127.0.0.1:1085" http://testsvc:8080/hello)" \
    || fail "http proxy (absolute-form) fetch failed"
assert_eq "$body" "magicalane-test-service" "inbound: HTTP absolute-form through mixed port"

# ---- 3b. HTTP without auth is refused (407)
exec_c curl -fsS --max-time 6 -x "http://127.0.0.1:1085" http://testsvc:8080/hello \
    && fail "HTTP proxy accepted unauthenticated request"
pass "inbound: HTTP path enforces Basic auth"

# ---- 3c. HTTP CONNECT method (raw, then a GET through the tunnel)
body="$(exec_c python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 1085), timeout=8)
s.sendall(b"CONNECT testsvc:8080 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n")
resp = s.recv(4096)
assert b"200" in resp.split(b"\r\n")[0], resp
s.sendall(b"GET /hello HTTP/1.1\r\nHost: testsvc:8080\r\nConnection: close\r\n\r\n")
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk: break
    data += chunk
body = data.split(b"\r\n\r\n", 1)[1]
print(body.decode().strip().splitlines()[-1])
')" || fail "CONNECT failed"
assert_eq "$body" "magicalane-test-service" "inbound: HTTP CONNECT tunnels"

$CE exec magicalane-client /usr/local/bin/ws-daemon.sh stop >/dev/null 2>&1 || true
