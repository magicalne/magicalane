# suites: tcptransport
# transports: quic
# TCP+TLS transport end-to-end: a second server instance (protocol
# "tcp", port 4535) inside the server container, and a workstation
# client whose tunnel rides TLS-over-TCP. Proves the full chain
# (TLS + password auth + Addr + relay) through the real binary pair,
# plus the egress-identity oracle (/peer reports the relaying server).
source "$TESTS_DIR/helpers.sh"

cleanup() {
    ws_stop >/dev/null 2>&1 || true
    exec_s pkill -f "server-tcp.toml" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# 1. second server instance: TCP+TLS on :4535
if ! exec_s sh -c 'ss -Hltn | grep -q ":4535 "' >/dev/null 2>&1; then
    $CE exec -d magicalane-server /usr/local/bin/magicalane --config /etc/magicalane/server-tcp.toml
fi
for _ in $(seq 1 30); do
    exec_s sh -c 'ss -Hltn | grep -q ":4535 "' >/dev/null 2>&1 && break
    sleep 0.5
done
exec_s sh -c 'ss -Hltn | grep -q ":4535 "' >/dev/null 2>&1 \
    || fail "tcp-transport server never listened on 4535"
pass "tcp-transport: server listening on :4535 (TLS)"

# 2. workstation client with tunnel = tcp transport
ws_start_cfg /etc/magicalane/client-ws-tcptransport.toml 7903

# 3. through the TCP tunnel: origin fixture + testsvc /peer oracle
result="$(exec_c python3 -c '
import urllib.request
try:
    body = urllib.request.urlopen("http://origin/fixtures/hello.txt", timeout=15).read().decode().strip()
    peer = urllib.request.urlopen("http://testsvc:8080/peer", timeout=15).read().decode().strip()
except Exception as e:
    print("FAIL:" + repr(e)); raise SystemExit
print("OK:%s|%s" % (body, peer))
' 2>/dev/null || true)"
case "$result" in
    FAIL:*) fail "tcp-transport fetch: $result" ;;
    OK:*) result="${result#OK:}" ;;
    *) fail "tcp-transport fetch: unexpected output '$result'" ;;
esac
body="$(echo "$result" | cut -d'|' -f1)"
peer="$(echo "$result" | cut -d'|' -f2)"
[ "$body" = "magicalane-test-fixture-hello" ] || fail "tcp-transport: origin body wrong: $body"
pass "tcp-transport: origin fixture via TLS-over-TCP tunnel"

# 4. egress identity: /peer must report server1 (the only tunnel egress)
S1_PEER="$(exec_s sh -c 'curl -s --max-time 3 http://testsvc:8080/peer')"
[ -n "$S1_PEER" ] || fail "server1 cannot reach testsvc (env problem)"
[ "$peer" = "$S1_PEER" ] \
    || fail "tcp-transport: egress $peer != server1 $S1_PEER"
pass "tcp-transport: relayed by server1 ($peer) — egress identity confirmed"

# 5. a second request on the same client (fresh TLS connection each
# time — one connection per proxy connection, by design)
exec_c curl -fsS --max-time 12 --socks5-hostname 127.0.0.1:1085 \
    http://testsvc:8080/hello >/dev/null 2>&1 \
    && pass "tcp-transport: second request OK (fresh TLS conn per request)"

cleanup
pass "tcp-transport: cleanup done"
