#!/usr/bin/env bash
# gateway.sh — deploy and manage a magicalane transparent-gateway client
# inside an LXC container (incus) on the LAN.
#
# The container gets its own LAN IP via macvlan; LAN devices point
# their default gateway + DNS at it (or just use SOCKS5/HTTP on 1080).
# Everything firewall-related lives INSIDE the container — the host is
# untouched except for a macvlan "shim" route so the host itself can
# reach the container (macvlan limitation).
#
# Usage: scripts/gateway.sh <command>
#   create    build + launch container + deploy binary/config/unit (idempotent)
#   verify    spin up a temp tunnel server on the LAN, wire the gateway to it,
#             and prove the whole chain end-to-end (fake-IP DNS, SOCKS via the
#             tunnel to the internet, clean-exit rule teardown), then clean up
#   start | stop | restart   systemctl inside the container
#   status    container, service, listeners, firewall rules
#   logs [N]  journalctl inside the container
#   shell     bash inside the container
#   config    show the live config (path: /etc/magicalane/client.toml)
#   remove    tear down container(s), shim and routes
#
# Environment overrides:
#   GW_INSTANCE (magicalane-gw)   container name
#   GW_PARENT  (enp9s0)           LAN interface for macvlan
#   GW_IP      (192.168.2.90)     static LAN IP for the gateway
#   GW_ROUTER  (192.168.2.1)      LAN default gateway/DNS
#   SRV_INSTANCE (magicalane-gwtest) / SRV_IP (192.168.2.91)  verify helpers
set -euo pipefail

GW_INSTANCE="${GW_INSTANCE:-magicalane-gw}"
GW_PARENT="${GW_PARENT:-enp9s0}"
GW_IP="${GW_IP:-192.168.2.90}"
GW_ROUTER="${GW_ROUTER:-192.168.2.1}"
SRV_INSTANCE="${SRV_INSTANCE:-magicalane-gwtest}"
SRV_IP="${SRV_IP:-192.168.2.91}"
SHIM="mgl-gw-shim"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CERTS_DIR="/var/tmp/magicalane-gateway-certs"
PASS_FILE="/var/tmp/magicalane-gateway-certs/verify-creds"

ic() { sudo incus "$@"; }                     # incus wrapper
gw() { ic exec "$GW_INSTANCE" -- "$@"; }       # run inside gateway
say() { printf '\033[1;34mgateway.sh\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mgateway.sh ERROR\033[0m %s\n' "$*" >&2; exit 1; }
rand() { openssl rand -hex 10; }               # 20 hex chars, no pipefail traps

container_exists() { ic list -c n --format csv | grep -qx "$1"; }
service_active()  { [ "$(gw systemctl is-active magicalane 2>/dev/null || true)" = "active" ]; }

shim_up() {
  sudo ip link show "$SHIM" >/dev/null 2>&1 || sudo ip link add "$SHIM" link "$GW_PARENT" type macvlan mode bridge
  sudo ip link set "$SHIM" up
  sudo ip route replace "${GW_IP}/32" dev "$SHIM"
}

build_binary() {
  say "building magicalane (release)..."
  (cd "$REPO" && cargo build --release --quiet)
  [ -x "$REPO/target/release/magicalane" ] || die "build produced no binary"
}

push_binary_and_unit() {  # $1 = instance
  ic exec "$1" -- sh -c 'systemctl stop magicalane magicalane-server 2>/dev/null; exit 0'; sleep 1   # text-file-busy guard
  ic file push --mode 0755 "$REPO/target/release/magicalane" "$1/usr/local/bin/magicalane"
  ic file push "$REPO/configs/magicalane-gateway.service" "$1/etc/systemd/system/magicalane.service"
  ic exec "$1" -- systemctl daemon-reload
}

wait_listening() {  # $1=instance $2=port $3=flag(t or u)
  local i
  for i in $(seq 1 30); do
    if ic exec "$1" -- ss -Hln"$3" 2>/dev/null | grep -q ":$2 "; then return 0; fi
    sleep 1
  done
  return 1
}

cmd_create() {
  build_binary
  if ! container_exists "$GW_INSTANCE"; then
    say "launching container $GW_INSTANCE (debian/13, macvlan on $GW_PARENT)..."
    # root disk on the default profile (one-time, idempotent)
    ic profile device add default root disk path=/ pool=default >/dev/null 2>&1 || true
    ic launch images:debian/13 "$GW_INSTANCE"
    ic config device add "$GW_INSTANCE" eth0 nic nictype=macvlan parent="$GW_PARENT" name=eth0 >/dev/null
    sleep 5
    say "pinning static $GW_IP via systemd-networkd..."
    ic exec "$GW_INSTANCE" -- sh -c "printf '[Match]\nName=eth0\n\n[Network]\nAddress=$GW_IP/24\nGateway=$GW_ROUTER\nDNS=$GW_ROUTER\nIPv6AcceptRA=no\n' > /etc/systemd/network/10-magicalane.network && rm -f /etc/systemd/network/eth0.network && systemctl restart systemd-networkd"
    say "installing iptables (firewall backend)..."
    ic exec "$GW_INSTANCE" -- sh -c 'apt-get update -qq && apt-get install -y -qq iptables >/dev/null'
    sleep 2
    ip -br addr show 2>/dev/null | grep -q "$GW_IP " || ic exec "$GW_INSTANCE" -- ip -br addr show eth0
  else
    say "container $GW_INSTANCE already exists — redeploying binary/unit..."
  fi
  gw sh -c 'command -v iptables >/dev/null || { apt-get update -qq && apt-get install -y -qq iptables >/dev/null; }'
  gw mkdir -p /etc/magicalane/certs /var/lib/magicalane
  push_binary_and_unit "$GW_INSTANCE"
  if ! gw test -f /etc/magicalane/client.toml; then
    ic file push "$REPO/configs/client-gateway.toml" "$GW_INSTANCE/etc/magicalane/client.toml"
    say "template config installed (service NOT started yet)"
  else
    say "existing config kept untouched"
  fi
  gw systemctl enable magicalane >/dev/null 2>&1
  shim_up
  say "host shim up: this host reaches the gateway at $GW_IP"
  cat <<EOF

Next:
  1. edit the config:  scripts/gateway.sh config   (host: $GW_IP path /etc/magicalane/client.toml)
     — set proxy.host / port / password, and copy your CA to /etc/magicalane/certs/ca.pem:
       ic file push ca.pem $GW_INSTANCE/etc/magicalane/certs/ca.pem
  2. start:            scripts/gateway.sh start
  3. point devices:    default gateway = $GW_IP   DNS = $GW_IP (port 53 is fine*)
     (* dns_port answers on 15353; you can also publish it as 53 later)
  Or try a full self-test first:  scripts/gateway.sh verify
EOF
}

gen_certs() {  # CA + server cert with IP SAN into $CERTS_DIR
  mkdir -p "$CERTS_DIR"
  [ -f "$CERTS_DIR/ca.pem" ] && return 0
  say "generating CA + server cert (SAN: DNS:gwtest, IP:$SRV_IP)..."
  ( cd "$CERTS_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout ca.key -out ca.pem -subj "/CN=magicalane gateway verify CA" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=gwtest" >/dev/null 2>&1
    printf 'subjectAltName=DNS:gwtest,IP:%s\n' "$SRV_IP" > ext.cnf
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 825 -extfile ext.cnf >/dev/null 2>&1 )
}

write_gw_client_config() {  # $1=server ip $2=passwd $3=socks user:pass
  cat > "$CERTS_DIR/client-verify.toml" <<EOF
password = "$2"
bandwidth = 65536
verbose = true
kind = { Client = { proxy = { host = "$1", port = 4433, ca_path = "/etc/magicalane/certs/ca.pem" }, socks5_port = 1080, socks5_users = ["$3"], allow_lan = true, tproxy = { mode = "tproxy", gateway = true, tcp_port = 7895, udp_port = 7896, dns_port = 15353, dns_mode = "fakeip" }, routing = { default = "proxy", direct_dns = ["$GW_ROUTER:53"], fakeip_cache = "/var/lib/magicalane/fakeip.map", rule = [ { domain_suffix = ["lan", "local"], action = "direct" }, { ip_cidr = ["192.168.0.0/16", "10.0.0.0/8"], action = "direct" } ] } } }
EOF
  ic file push "$CERTS_DIR/client-verify.toml" "$GW_INSTANCE/etc/magicalane/client.toml"
}

cmd_verify() {
  build_binary
  gw sh -c 'command -v iptables >/dev/null || { apt-get update -qq && apt-get install -y -qq iptables >/dev/null; }'
  gw mkdir -p /etc/magicalane/certs /var/lib/magicalane
  push_binary_and_unit "$GW_INSTANCE"     # verify is self-sufficient
  gen_certs
  local TUNNEL_PASS SOCKS_CREDS
  TUNNEL_PASS="$(rand 20)"
  SOCKS_CREDS="verify:$(rand 16)"
  echo "$TUNNEL_PASS $SOCKS_CREDS" > "$PASS_FILE"; chmod 600 "$PASS_FILE"

  # --- temp tunnel server on the LAN ---
  if ! container_exists "$SRV_INSTANCE"; then
    say "launching temp server container $SRV_INSTANCE ($SRV_IP)..."
    ic launch images:debian/13 "$SRV_INSTANCE"
    ic config device add "$SRV_INSTANCE" eth0 nic nictype=macvlan parent="$GW_PARENT" name=eth0 >/dev/null
    sleep 5
    ic exec "$SRV_INSTANCE" -- sh -c "printf '[Match]\nName=eth0\n\n[Network]\nAddress=$SRV_IP/24\nGateway=$GW_ROUTER\nDNS=$GW_ROUTER\nIPv6AcceptRA=no\n' > /etc/systemd/network/10-magicalane.network && rm -f /etc/systemd/network/eth0.network && systemctl restart systemd-networkd"
  fi
  ic exec "$SRV_INSTANCE" -- sh -c 'systemctl stop magicalane-server 2>/dev/null; exit 0'
  sleep 1
  ic exec "$SRV_INSTANCE" -- mkdir -p /etc/magicalane
  ic file push --mode 0755 "$REPO/target/release/magicalane" "$SRV_INSTANCE/usr/local/bin/magicalane"
  ic file push "$CERTS_DIR/ca.pem" "$CERTS_DIR/server.pem" "$CERTS_DIR/server.key" "$SRV_INSTANCE/etc/magicalane/"
  cat > "$CERTS_DIR/server-verify.toml" <<EOF
password = "$TUNNEL_PASS"
bandwidth = 65536
verbose = true
kind = { Server = { port = 4433, ca = "/etc/magicalane/server.pem", key = "/etc/magicalane/server.key" } }

[dns]
upstream = ["$GW_ROUTER:53"]
EOF
  ic file push "$CERTS_DIR/server-verify.toml" "$SRV_INSTANCE/etc/magicalane/server.toml"
  ic exec "$SRV_INSTANCE" -- sh -c 'printf "[Unit]\nDescription=temp magicalane server\n[Service]\nExecStart=/usr/local/bin/magicalane --config /etc/magicalane/server.toml\nRestart=always\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/magicalane-server.service && systemctl daemon-reload && systemctl reset-failed magicalane-server 2>/dev/null; systemctl restart magicalane-server'
  say "waiting for tunnel server on $SRV_IP:4433..."
  wait_listening "$SRV_INSTANCE" 4433 u || die "temp server never listened on 4433/udp"

  # --- gateway wiring ---
  shim_up
  ic file push "$CERTS_DIR/ca.pem" "$GW_INSTANCE/etc/magicalane/certs/ca.pem"
  write_gw_client_config "$SRV_IP" "$TUNNEL_PASS" "$SOCKS_CREDS"
  gw sh -c 'systemctl reset-failed magicalane 2>/dev/null; systemctl restart magicalane'
  say "waiting for gateway listeners (socks 1080, dns 15353, tproxy 7895/7896)..."
  wait_listening "$GW_INSTANCE" 1080 t || die "gateway socks never came up (logs: scripts/gateway.sh logs)"
  wait_listening "$GW_INSTANCE" 15353 u || die "gateway dns never came up"
  wait_listening "$GW_INSTANCE" 7903 u || true   # udp interceptor binds port+1 for v6
  if ! gw ss -Hlun | grep -q ':7896 '; then die "gateway udp interceptor never came up"; fi

  local fail=0
  say "CHECK 1/4 fake-IP DNS from a routed client: dig @9.9.9.9 (routed via $GW_IP, intercepted)"
  local tok
  sudo ip route replace 9.9.9.9/32 via "$GW_IP" dev "$SHIM"
  tok="$(dig +short +time=3 +tries=1 @9.9.9.9 example.com A | head -1 || true)"
  sudo ip route del 9.9.9.9/32 2>/dev/null || true
  if [[ "$tok" == 198.18.* ]]; then say "  ok: token $tok — hardcoded resolver intercepted, answered locally"; else say "  FAIL: got '$tok'"; fail=1; fi

  say "CHECK 2/4 SOCKS5 through the tunnel to the internet (egress = $SRV_IP)"
  local code
  code="$(curl -m 20 -s -o /dev/null -w '%{http_code}' --socks5-hostname "$SOCKS_CREDS@$GW_IP:1080" https://www.example.com || true)"
  if [ "$code" = 200 ]; then say "  ok: HTTP $code via $GW_IP -> $SRV_IP -> internet"; else say "  FAIL: curl code=$code"; fail=1; fi

  say "CHECK 3/4 gateway firewall rules installed (PREROUTING = forwarded traffic intercepted)"
  if gw iptables -t mangle -S MGL-PRE 2>/dev/null | grep -q TPROXY; then say "  ok: MGL-PRE TPROXY rules present"; else say "  FAIL: no MGL-PRE TPROXY rules"; fail=1; fi

  say "CHECK 4/4 clean-exit contract: stop -> rules gone, start -> back"
  gw systemctl stop magicalane
  sleep 1
  if gw iptables -t mangle -S MGL-PRE 2>/dev/null | grep -q TPROXY; then say "  FAIL: rules survived stop"; fail=1;
  else say "  ok: rules reverted on stop"; fi
  gw systemctl start magicalane
  wait_listening "$GW_INSTANCE" 1080 t || die "service did not come back"
  if gw iptables -t mangle -S MGL-PRE 2>/dev/null | grep -q TPROXY; then say "  ok: rules re-installed on start"; else say "  FAIL: rules missing after start"; fail=1; fi

  # --- cleanup: remove temp server, restore template config (stopped) ---
  say "cleaning up verify artifacts..."
  ic delete -f "$SRV_INSTANCE" >/dev/null 2>&1 || true
  gw systemctl stop magicalane
  ic file push "$REPO/configs/client-gateway.toml" "$GW_INSTANCE/etc/magicalane/client.toml"
  rm -f "$CERTS_DIR/client-verify.toml" "$CERTS_DIR/server-verify.toml"
  say "temp server removed; gateway config restored to template (service stopped)"
  echo
  if [ "$fail" = 0 ]; then
    cat <<EOF
ALL CHECKS PASSED — the gateway deployment works end-to-end.
The working verify config was: host=$SRV_IP (temp server, now gone).
Wire your real server now: scripts/gateway.sh config
EOF
  else
    die "verify FAILED ($fail) — inspect: scripts/gateway.sh logs"
  fi
}

cmd_status() {
  shim_up 2>/dev/null || true
  ic list -c ns4 | grep -E "NAME|$GW_INSTANCE|$SRV_INSTANCE" || true
  echo
  if container_exists "$GW_INSTANCE"; then
    echo "service:   $(gw systemctl is-active magicalane 2>/dev/null || true)"
    if service_active; then
      echo "listeners: $(gw ss -Hlntu | awk '{print $5}' | paste -sd' ' -)"
      echo "rules:     $(gw iptables -t mangle -S 2>/dev/null | grep -c '^-' || true) mangle rules"
      echo "health:    $(curl -m 5 -s -o /dev/null -w '%{http_code}' --socks5-hostname "$(cat "$PASS_FILE" 2>/dev/null | cut -d' ' -f2)@$GW_IP:1080" https://www.example.com 2>/dev/null || echo n/a)"
    fi
  fi
}

cmd_logs() { gw journalctl -u magicalane -n "${1:-30}" --no-pager; }
cmd_shell() { ic exec "$GW_INSTANCE" -- bash || ic exec "$GW_INSTANCE" -- sh; }
cmd_config() { ic exec "$GW_INSTANCE" -- cat /etc/magicalane/client.toml; }
cmd_remove() {
  say "removing..."
  ic delete -f "$GW_INSTANCE" >/dev/null 2>&1 || true
  ic delete -f "$SRV_INSTANCE" >/dev/null 2>&1 || true
  sudo ip route del "${GW_IP}/32" dev "$SHIM" 2>/dev/null || true
  sudo ip link del "$SHIM" 2>/dev/null || true
  say "containers + shim removed (incus storage pool and profile stay)"
}

case "${1:-}" in
  create)  cmd_create ;;
  verify)  cmd_verify ;;
  start)   gw systemctl start magicalane ;;
  stop)    gw systemctl stop magicalane ;;
  restart) gw systemctl restart magicalane ;;
  status)  cmd_status ;;
  logs)    shift; cmd_logs "${1:-30}" ;;
  shell)   cmd_shell ;;
  config)  cmd_config ;;
  remove)  cmd_remove ;;
  *) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -22; exit 1 ;;
esac
