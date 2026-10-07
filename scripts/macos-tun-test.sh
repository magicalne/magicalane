#!/bin/bash
# macOS utun end-to-end test (run with sudo; needs root for utun+routes).
#
# Proves on real Apple-silicon macOS:
#   1. the utun device opens and capture routes (0/1+128/1+2000::/3) install
#   2. traffic routed into the TUN plane flows through the embedded
#      TCP/IP stack -> routing engine -> tunnel -> server -> origin
#   3. the local SOCKS5 listener also works (explicit proxy path)
#   4. the clean-exit contract: SIGTERM removes the capture routes
#
# Everything is local to the runner (loopback server, origin on the
# host's own en0 address) so no external network is needed. The origin
# binds the LAN IP on purpose: traffic TO it must route via utun.
#
# Usage: sudo ./scripts/macos-tun-test.sh <path-to-magicalane>

set -euo pipefail

BIN=${1:?usage: macos-tun-test.sh <magicalane-binary>}
[ "$(id -u)" = 0 ] || { echo "must run as root (utun + routes)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v openssl >/dev/null || { echo "openssl required"; exit 1; }

WORK=$(mktemp -d /tmp/mgl-tun-test.XXXXXX)
ORIGIN_PORT=18080
SERVER_PORT=14433
SOCKS_PORT=11080

SRV_PID="" ORIGIN_PID="" CLIENT_PID=""
cleanup() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    sleep 0.5
    # Belt-and-braces route removal (clean-exit should have done it).
    route -n delete -inet 0.0.0.0/1 2>/dev/null || true
    route -n delete -inet 128.0.0.0/1 2>/dev/null || true
    route -n delete -inet6 2000::/3 2>/dev/null || true
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "$ORIGIN_PID" ] && kill "$ORIGIN_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- 1. self-signed cert (client trusts it directly)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/server.key" -out "$WORK/server.pem" -days 2 \
    -subj "/CN=localhost" >/dev/null 2>&1
echo ok > "$WORK/origin-file.txt"

# --- 2. origin on the host's primary IP (dst routes via utun once captured)
ORIGIN_IP=$(ipconfig getifaddr en0)
[ -n "$ORIGIN_IP" ] || { echo "cannot determine en0 address"; exit 1; }
echo "origin: http://$ORIGIN_IP:$ORIGIN_PORT (python3)"
python3 -m http.server "$ORIGIN_PORT" --bind "$ORIGIN_IP" --directory "$WORK" \
    >"$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!

# --- 3. local tunnel server (loopback: unaffected by route capture)
cat > "$WORK/server.toml" <<EOF
password = "pw"
bandwidth = 65536
verbose = true
kind = { Server = { port = $SERVER_PORT, ca = "$WORK/server.pem", key = "$WORK/server.key" } }
EOF
"$BIN" --config "$WORK/server.toml" >"$WORK/server.log" 2>&1 &
SRV_PID=$!

# --- 4. client in tun mode
cat > "$WORK/client.toml" <<EOF
password = "pw"
bandwidth = 65536
verbose = true
kind = { Client = { proxy = { host = "127.0.0.1", port = $SERVER_PORT, ca_path = "$WORK/server.pem" }, socks5_port = $SOCKS_PORT, tproxy = { mode = "tun", tcp_port = 0, udp_port = 0, dns_port = 0, dns_mode = "fakeip" }, routing = { default = "proxy" } } }
EOF
RUST_LOG=info "$BIN" --config "$WORK/client.toml" >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!

# --- 5. wait for capture routes (max 15s)
captured=""
for _ in $(seq 1 30); do
    if route -n get 8.8.8.8 2>/dev/null | grep -q "interface: utun"; then
        captured=yes; break
    fi
    sleep 0.5
done
[ -n "$captured" ] || {
    echo "FAIL: capture routes never appeared"; cat "$WORK/client.log"; exit 1;
}
echo "capture routes up: $(route -n get 8.8.8.8 | grep interface)"
ifconfig | grep -A4 "^utun" | grep -E "^utun|inet |mtu" || true

# --- 6. through the TUN plane (transparent; dst = en0 IP -> utun)
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
    --noproxy '*' "http://$ORIGIN_IP:$ORIGIN_PORT/origin-file.txt")
[ "$code" = 200 ] || {
    echo "FAIL: tun-plane curl got $code"; tail -30 "$WORK/client.log"; exit 1;
}
echo "tun-plane: HTTP $code (traffic went utun -> stack -> tunnel -> origin)"

# --- 7. through the SOCKS5 listener (explicit proxy)
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
    -x "socks5h://127.0.0.1:$SOCKS_PORT" "http://$ORIGIN_IP:$ORIGIN_PORT/origin-file.txt")
[ "$code" = 200 ] || {
    echo "FAIL: socks5 curl got $code"; tail -30 "$WORK/client.log"; exit 1;
}
echo "socks5:   HTTP $code (explicit proxy through the same tunnel)"

# --- 8. clean-exit: SIGTERM must remove the capture routes
kill -TERM "$CLIENT_PID"
for _ in $(seq 1 20); do
    if ! route -n get 8.8.8.8 2>/dev/null | grep -q "interface: utun"; then
        echo "clean-exit: capture routes removed on SIGTERM"
        exit 0
    fi
    sleep 0.5
done
echo "FAIL: capture routes survived SIGTERM (clean-exit broken)"
exit 1
