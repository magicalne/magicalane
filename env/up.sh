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

PROFILE=""
TRANSPORT="quic"
while [ $# -gt 0 ]; do
    case "$1" in
        --profile) : ;;
        tproxy) PROFILE="tproxy" ;;
        --transport) TRANSPORT="$2"; shift ;;
        quic|kcp) TRANSPORT="$1" ;;
        *) echo "usage: env/up.sh [--transport quic|kcp] [--profile tproxy]" >&2; exit 2 ;;
    esac
    shift
done
case "$TRANSPORT" in quic|kcp) ;; *) echo "invalid transport: $TRANSPORT" >&2; exit 2 ;; esac

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
cp -f "$ENV_DIR/tproxy-rules.sh" "$ENV_DIR/.build/tproxy-rules.sh"
chmod +x "$ENV_DIR/.build/"*

say "generating certs"
"$ENV_DIR/certs.sh"

say "generating fixtures"
"$ENV_DIR/fixtures.sh"

say "building image"
$CE build -q -t "$IMAGE" -f "$ENV_DIR/Containerfile" "$ENV_DIR/.build" >/dev/null

# ---------------------------------------------------------------- network
if have_net "$NET"; then say "network $NET exists"; else $CE network create "$NET" >/dev/null; say "created network $NET"; fi

# ---------------------------------------------------------------- core roles
ensure_run magicalane-origin \
    $CE run -d --name magicalane-origin --label "$LABEL" \
    --network "$NET" --network-alias origin \
    --cap-add NET_ADMIN \
    -v "$ENV_DIR/fixtures:/fixtures:ro" \
    "$IMAGE" sh -c 'mkdir -p /srv/www/fixtures && cp -r /fixtures/. /srv/www/fixtures/ && cat /etc/hostname > /srv/www/fixtures/hostname && exec python3 -m http.server 80 --directory /srv/www'

ensure_run magicalane-server \
    $CE run -d --name magicalane-server --label "$LABEL" \
    --network "$NET" --network-alias magicalane-server \
    -e RUST_LOG=info \
    -v "$ENV_DIR/configs/server-$TRANSPORT.toml:/etc/magicalane/server.toml:ro" \
    -v "$ENV_DIR/certs:/etc/magicalane/certs:ro" \
    "$IMAGE" magicalane --config /etc/magicalane/server.toml

ensure_run magicalane-client \
    $CE run -d --name magicalane-client --label "$LABEL" \
    --network "$NET" \
    -e RUST_LOG=info \
    -v "$ENV_DIR/configs/client-$TRANSPORT.toml:/etc/magicalane/client.toml:ro" \
    -v "$ENV_DIR/certs:/etc/magicalane/certs:ro" \
    "$IMAGE" magicalane --config /etc/magicalane/client.toml

say "waiting for readiness"
wait_exec magicalane-server sh -c "ss -lun | grep -q ':4433'"
wait_exec magicalane-client sh -c "ss -ltn | grep -q ':1080'"
say "core lab up: client socks5 -> $TRANSPORT -> server -> origin"

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
        -v "$ENV_DIR/configs/client-$TRANSPORT.toml:/etc/magicalane/client.toml:ro" \
        -v "$ENV_DIR/certs:/etc/magicalane/certs:ro" \
        "$IMAGE" sh -c 'socat TCP-LISTEN:7895,bind=0.0.0.0,reuseaddr,fork,ip-transparent TCP:origin:80 & exec magicalane --config /etc/magicalane/client.toml'

    $CE network connect "$LAN" magicalane-tproxy-client

    LAN_IP="$($CE inspect magicalane-tproxy-client --format '{{(index .NetworkSettings.Networks "'"$LAN"'").IPAddress}}')"
    ORIGIN_IP="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "'"$NET"'").IPAddress}}')"
    say "tproxy-client lan ip: $LAN_IP, origin ip: $ORIGIN_IP"

    # the app: no proxy configuration whatsoever - its default route goes
    # through the tproxy client, which intercepts transparently.
    ensure_run magicalane-app \
        $CE run -d --name magicalane-app --label "$LABEL" \
        --network "$LAN" \
        --cap-add NET_ADMIN \
        --add-host "origin:$ORIGIN_IP" \
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
