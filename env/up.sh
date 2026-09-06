#!/usr/bin/env bash
# Bring up the isolated magicalane test network (rootless podman).
#
#   env/up.sh                  - socks5/QUIC lab: origin + server + client
#   env/up.sh --profile tproxy - additionally: dual-homed tproxy-client + app
#
# Nothing is published to the host: all interaction is via podman exec.
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$ENV_DIR/.." && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
LABEL="magicalane.env=true"
NET="magicalane-net"
LAN="magicalane-lan"
IMAGE="magicalane:env"

IPV6="${IPV6:-0}"
PROFILE=""
TRANSPORT="quic"
SERVER_CONFIG=""
CLIENT_CONFIG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --ipv6) IPV6=1 ;;
        --profile) : ;;
        tproxy) PROFILE="tproxy" ;;
        --transport) TRANSPORT="$2"; shift ;;
        quic|kcp|kcp-plain) TRANSPORT="$1" ;;
        --server-config) SERVER_CONFIG="$2"; shift ;;
        --client-config) CLIENT_CONFIG="$2"; shift ;;
        *) echo "usage: env/up.sh [--transport quic|kcp|kcp-plain] [--ipv6] [--profile tproxy] [--server-config PATH] [--client-config PATH]" >&2; exit 2 ;;
    esac
    shift
done
SERVER_CFG_PATH="${SERVER_CONFIG:-$ENV_DIR/configs/server-$TRANSPORT.toml}"
CLIENT_CFG_PATH="${CLIENT_CONFIG:-$ENV_DIR/configs/client-$TRANSPORT.toml}"
case "$TRANSPORT" in quic|kcp|kcp-plain) ;; *) echo "invalid transport: $TRANSPORT" >&2; exit 2 ;; esac

say() { echo "[up] $*"; }
say "transport: $TRANSPORT"

have_net() { $CE network exists "$1" 2>/dev/null; }
running() { $CE ps --format '{{.Names}}' | grep -qx "$1"; }
created() { $CE ps -a --format '{{.Names}}' | grep -qx "$1"; }

ensure_run() { # name args...
    local name="$1"; shift
    if running "$name"; then
        say "$name already running"
    else
        created "$name" && $CE rm -f "$name" >/dev/null
        "$@"
        say "started $name"
    fi
}

wait_exec() { # name cmd... (retry until cmd succeeds inside container, 30s)
    local name="$1"; shift
    for _ in $(seq 1 60); do
        if $CE exec "$name" "$@" >/dev/null 2>&1; then return 0; fi
        sleep 0.5
    done
    echo "[up] timeout waiting for $name readiness" >&2
    $CE logs --tail 20 "$name" >&2 || true
    return 1
}

# ---------------------------------------------------------------- prerequisites
cd "$ROOT"
say "building release binary"
cargo build --release

say "staging build context"
mkdir -p "$ENV_DIR/.build"
cp -f target/release/magicalane "$ENV_DIR/.build/magicalane"
cp -f target/release/magabench "$ENV_DIR/.build/magabench"
cp -f "$ENV_DIR/tproxy-rules.sh" "$ENV_DIR/.build/tproxy-rules.sh"
cp -f "$ENV_DIR/ws-daemon.sh" "$ENV_DIR/.build/ws-daemon.sh"
chmod +x "$ENV_DIR/.build/"*

say "generating certs"
"$ENV_DIR/certs.sh"

say "generating fixtures"
"$ENV_DIR/fixtures.sh"

say "building image"
$CE build -q -t "$IMAGE" -f "$ENV_DIR/Containerfile" "$ENV_DIR/.build" >/dev/null

# ---------------------------------------------------------------- network
if have_net "$NET"; then
    say "network $NET exists"
else
    if [ "$IPV6" = "1" ]; then
        $CE network create --ipv6 --subnet "10.89.0.0/16" --subnet "fd00:89::/64" "$NET" >/dev/null
        say "created network $NET (dual-stack)"
    else
        $CE network create "$NET" >/dev/null
        say "created network $NET"
    fi
fi
BACKEND="magicalane-backend"
# --internal: no gateway in the shared netns, so the backend subnet is
# unreachable from other container networks - only containers attached to
# this network (server, testsvc) can talk, at L2. This is what makes the
# test service PROVABLY private.
if have_net "$BACKEND"; then say "network $BACKEND exists"; else $CE network create --internal "$BACKEND" >/dev/null; say "created network $BACKEND (internal)"; fi

# ---------------------------------------------------------------- core roles
ensure_run magicalane-origin \
    $CE run -d --name magicalane-origin --label "$LABEL" \
    --network "$NET" --network-alias origin \
    --cap-add NET_ADMIN \
    -v "$ENV_DIR/fixtures:/fixtures:ro" \
    "$IMAGE" sh -c 'mkdir -p /srv/www/fixtures && cp -r /fixtures/. /srv/www/fixtures/ && cat /etc/hostname > /srv/www/fixtures/hostname && exec python3 -m http.server 80 --bind :: --directory /srv/www'

ensure_run magicalane-testsvc \
    $CE run -d --name magicalane-testsvc --label "$LABEL" \
    --network "$BACKEND" --network-alias testsvc \
    "$IMAGE" magabench serve --http 8080 --tcp 9001 --udp 9002

ensure_run magicalane-server \
    $CE run -d --name magicalane-server --label "$LABEL" \
    --network "$NET" --network-alias magicalane-server \
    --cap-add NET_ADMIN \
    -e RUST_LOG=info \
    -v "$SERVER_CFG_PATH:/etc/magicalane/server.toml:ro" \
    -v "$ENV_DIR/certs:/etc/magicalane/certs:ro" \
    "$IMAGE" magicalane --config /etc/magicalane/server.toml

ensure_run magicalane-client \
    $CE run -d --name magicalane-client --label "$LABEL" \
    --network "$NET" \
    --cap-add NET_ADMIN \
    -e RUST_LOG=info \
    -v "$CLIENT_CFG_PATH:/etc/magicalane/client.toml:ro" \
    -v "$ENV_DIR/configs/client-$TRANSPORT-ws.toml:/etc/magicalane/client-ws.toml:ro" \
    -v "$ENV_DIR/configs/client-$TRANSPORT-ws-fakeip.toml:/etc/magicalane/client-ws-fakeip.toml:ro" \
    -v "$ENV_DIR/configs/client-$TRANSPORT-ws-geoip.toml:/etc/magicalane/client-ws-geoip.toml:ro" \
    -v "$ENV_DIR/configs/client-$TRANSPORT-ws-dnslayer.toml:/etc/magicalane/client-ws-dnslayer.toml:ro" \
    -v "$ENV_DIR/configs/client-$TRANSPORT-ws-auth.toml:/etc/magicalane/client-ws-auth.toml:ro" \
    -v "$ENV_DIR/configs/client-$TRANSPORT-ws-fakefilter.toml:/etc/magicalane/client-ws-fakefilter.toml:ro" \
    -v "$ENV_DIR/configs/client-$TRANSPORT-ws-provider.toml:/etc/magicalane/client-ws-provider.toml:ro" \
    -v "$ENV_DIR/certs:/etc/magicalane/certs:ro" \
    "$IMAGE" magicalane --config /etc/magicalane/client.toml

say "waiting for readiness"
wait_exec magicalane-server sh -c "ss -lun | grep -q ':4433'"
wait_exec magicalane-client sh -c "ss -ltn | grep -q ':1080'"

# pin the test service name on the client container as well (its resolver
# cannot resolve internal-network names; the tproxy-ws tests fetch it by name)
WS_TESTSVC_IP="$($CE inspect magicalane-testsvc --format '{{(index .NetworkSettings.Networks "magicalane-backend").IPAddress}}')"
$CE exec magicalane-client sh -c "grep -q testsvc /etc/hosts 2>/dev/null || echo '$WS_TESTSVC_IP testsvc' >> /etc/hosts" || true

# server joins the backend network (idempotent) so it - and only it - can
# reach the private test service
if ! $CE inspect magicalane-server --format '{{range $k, $_ := .NetworkSettings.Networks}}{{$k}} {{end}}' | grep -q " $BACKEND "; then
    $CE network connect "$BACKEND" magicalane-server
    say "connected magicalane-server to $BACKEND"
fi
# aardvark DNS does not serve internal networks - pin the name on the server
TESTSVC_IP_NOW="$($CE inspect magicalane-testsvc --format '{{(index .NetworkSettings.Networks "magicalane-backend").IPAddress}}')"
$CE exec magicalane-server sh -c "grep -q testsvc /etc/hosts 2>/dev/null || echo '$TESTSVC_IP_NOW testsvc' >> /etc/hosts"
wait_exec magicalane-server sh -c "curl -fsS --max-time 2 http://testsvc:8080/id >/dev/null"

say "core lab up: client socks5 -> $TRANSPORT -> server -> origin (+ private testsvc on $BACKEND)"

# ---------------------------------------------------------------- tproxy profile
if [ "$PROFILE" = "tproxy" ]; then
    if have_net "$LAN"; then say "network $LAN exists"; else $CE network create "$LAN" >/dev/null; fi

    # dual-homed client: magicalane-net (eth0, wan) + magicalane-lan (eth1, lan).
    # bridge.py stands in for the future magicalane tproxy listener on tcp
    # 7895: it accepts transparently-intercepted connections and relays them
    # through the local socks5 server (i.e. through the chosen transport).
    ensure_run magicalane-tproxy-client \
        $CE run -d --name magicalane-tproxy-client --label "$LABEL" \
        --network "$NET" \
        --cap-add NET_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        -e RUST_LOG=info \
        -v "$CLIENT_CFG_PATH:/etc/magicalane/client.toml:ro" \
        -v "$ENV_DIR/certs:/etc/magicalane/certs:ro" \
        -v "$ENV_DIR/bridge.py:/usr/local/bin/bridge.py:ro" \
        "$IMAGE" sh -c 'python3 /usr/local/bin/bridge.py & exec magicalane --config /etc/magicalane/client.toml'

    $CE network connect "$LAN" magicalane-tproxy-client

    LAN_IP="$($CE inspect magicalane-tproxy-client --format '{{(index .NetworkSettings.Networks "'"$LAN"'").IPAddress}}')"
    ORIGIN_IP="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "'"$NET"'").IPAddress}}')"
    TESTSVC_IP="$($CE inspect magicalane-testsvc --format '{{(index .NetworkSettings.Networks "magicalane-backend").IPAddress}}')"
    say "tproxy-client lan ip: $LAN_IP, origin ip: $ORIGIN_IP, testsvc ip: $TESTSVC_IP"

    # the app: no proxy configuration whatsoever - its default route goes
    # through the tproxy client, which intercepts transparently.
    ensure_run magicalane-app \
        $CE run -d --name magicalane-app --label "$LABEL" \
        --network "$LAN" \
        --cap-add NET_ADMIN \
        --add-host "origin:$ORIGIN_IP" \
        --add-host "testsvc:$TESTSVC_IP" \
        "$IMAGE" sleep infinity

    $CE exec magicalane-app ip route replace default via "$LAN_IP" dev eth0
    $CE exec magicalane-app ip route del default via 10.89.1.1 dev eth0 2>/dev/null || true

    # Return path for routed (non-intercepted) traffic from the wan side:
    # the shared rootless netns does not forward between subnets, so pin a
    # route back through the tproxy client on the origin.
    WAN_IP="$($CE inspect magicalane-tproxy-client --format '{{(index .NetworkSettings.Networks "'"$NET"'").IPAddress}}')"
    LAN_SUBNET="$($CE exec magicalane-tproxy-client ip -4 route show dev eth1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1)"
    $CE exec magicalane-origin ip route replace "$LAN_SUBNET" via "$WAN_IP"

    say "applying tproxy rules inside magicalane-tproxy-client"
    $CE exec magicalane-tproxy-client /usr/local/bin/tproxy-rules.sh apply

    say "tproxy lab up: app -> [transparent] tproxy-client -> server -> origin"
fi

say "done. verify with: env/test.sh"
