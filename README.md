# Magicalane — a QUIC/KCP proxy with transparent interception and split routing

A local proxy client forwards traffic through an encrypted tunnel
(QUIC by default, KCP+TLS as an alternative transport) to a relay
server. Beyond a plain SOCKS5/HTTP inbound, the client can intercept
**all** traffic transparently — TCP, UDP and DNS, IPv4 and IPv6 —
answer DNS locally with fake IPs so no real query ever leaks, and
route every connection by domain/IP rules: China direct, the rest
through the tunnel, per-domain server selection, load balancing and
automatic failover across multiple tunnel servers.

Feature highlights:

- **Transports**: QUIC (built-in TLS via rustls/quinn), KCP+TLS
  (reliable UDP; often faster on lossy links) and **TCP+TLS** (one TLS
  connection per proxy connection — for paths where UDP is filtered;
  on :443 it is indistinguishable from ordinary HTTPS), tunable per side
- **Inbounds**: SOCKS5 with user/password auth (RFC 1929) and an
  HTTP proxy on the same port (CONNECT + absolute-form); LAN exposure
  is opt-in
- **Transparent modes**: firewall-based TPROXY (IPv4+IPv6, no local
  DNS dependency) or a fully userspace TUN TCP/IP stack (no iptables
  at all)
- **Fake-IP DNS**: local token answers (198.18.0.0/15 / fc00::/18)
  make DNS pollution impossible by construction; a filter list hands
  real answers to STUN/NTP/games; the token map persists across
  restarts
- **Split routing**: first-match rules on domain suffix (wildcard),
  exact domain, keyword, IP CIDR, list files (Loyalsoldier/v2ray
  format), GeoIP country lists; actions `direct`, `proxy`, or a
  named server/group
- **Multi-server pools**: mix QUIC and KCP servers in one config;
  automatic groups — `url-test` (fastest wins with hysteresis),
  `fallback` (priority failover), `load-balance` (round-robin or
  sticky-by-destination) — all health-probed through each server's
  own tunnel
- **Remote rule providers**: rule lists fetched by URL over the
  tunnel or direct, auto-refreshed, atomically hot-swapped
- **Hot reload**: `SIGHUP` re-reads routing rules, providers, geoip
  lists and the fake-IP filter without dropping the tunnel
- **Layered DNS** on both sides: answer cache → /etc/hosts → racing
  upstream probes (dead resolvers cost nothing)
- **Clean-exit contract**: every firewall/route mutation is
  transactional and reverted on any exit — including `kill -9`
  (adopted and cleaned up on the next start)
- **IPv6 end-to-end**: dual-stack interception, v6-through-tunnel for
  v4-only clients, per-server v4/v6 loop-prevention exceptions

Benchmarks, design notes and lab reports live in `docs/`.

## Quick start

Build (Rust stable):

```sh
cargo build --release          # TUN mode additionally:
cargo build --release --features tun-mode
```

Generate a CA and server certificate once (SAN must match the name
clients dial):

```sh
mkdir -p /etc/magicalane/certs && cd /etc/magicalane/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ca.key -out ca.pem -subj "/CN=my magicalane CA"
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr -subj "/CN=my-server"
printf 'subjectAltName=DNS:my-server,DNS:localhost,IP:203.0.113.10\n' > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out server.pem -days 825 -extfile ext.cnf
```

Copy the starting configs and edit hosts/paths/password:

```sh
cp configs/server.toml /etc/magicalane/server.toml   # server side
cp configs/client.toml /etc/magicalane/client.toml   # client side
```

Run both sides and test through the local proxy:

```sh
magicalane --config /etc/magicalane/server.toml
magicalane --config /etc/magicalane/client.toml
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

More examples — KCP, TUN mode, a full feature tour — are in
[`configs/`](configs/README.md); every shipped config is
parse-checked by the test suite.

## Configuration

Both sides read one TOML file via `--config`. Common top-level keys:
`password`, `bandwidth` (bytes/s pacing hint), `verbose`.

> **Format note**: `kind` must be an **inline table**
> (`kind = { Client = { ... } }`) — the parser rejects `[kind.Client]`
> headers. Top-level `[table]` sections (`[dns]`, `[tuning.*]`) go
> **after** all bare keys.

### Server

```toml
password = "change-me"
bandwidth = 65536
verbose = true
kind = { Server = { port = 4433,
                    ca = "/etc/magicalane/certs/server.pem",
                    key = "/etc/magicalane/certs/server.key",
                    protocol = "kcp",   # quic (default) | kcp
                    tls = true } }      # kcp only; default true

# Server-side DNS for tunnel-routed domains (racing + cache).
[dns]
upstream = ["1.1.1.1:53", "8.8.8.8:53"]   # default: resolv.conf servers
cache_size = 4096
```

### Client

```toml
password = "change-me"
bandwidth = 65536
verbose = true
kind = { Client = {
    # Primary tunnel server (referenced as "default" by rules/groups).
    proxy = { host = "my-server", port = 4433,
              ca_path = "/etc/magicalane/certs/ca.pem",
              protocol = "quic" },          # quic (default) | kcp (+tls)

    # Additional servers: mixed transports in ONE pool.
    server = [ { name = "work", host = "work.example.com", port = 4433,
                 protocol = "kcp",
                 ca_path = "/etc/magicalane/certs/ca.pem",
                 ip = "203.0.113.9" } ],    # optional pinned IP

    # Automatic proxy groups (all health-probed; no manual mode).
    group = [
      { name = "auto", gtype = "url-test",
        servers = ["default", "work"],
        url = "http://www.gstatic.com/generate_204",
        interval = 300, tolerance = 50 },   # ms switch hysteresis
      { name = "backup", gtype = "fallback",
        servers = ["work", "default"] },
      { name = "lb", gtype = "load-balance", strategy = "sticky",
        servers = ["default", "work"] },    # round-robin (default) | sticky
    ],

    # Local inbounds. The port serves SOCKS5 AND HTTP proxy; without
    # allow_lan it binds 127.0.0.1 only. socks5_users = ["user:pass"]
    # enables RFC 1929 auth (HTTP side answers 407 + Basic).
    socks5_port = 1080,
    socks5_users = ["alice:secret"],
    allow_lan = true,                        # or bind = "0.0.0.0"

    # Transparent interception: mode = "off" | "tproxy" | "tun".
    tproxy = { mode = "tproxy", tcp_port = 7895, udp_port = 7896,
               dns_port = 15353,             # 0 disables DNS handling
               dns_mode = "fakeip" },        # fakeip | tunnel | off

    routing = {
      default = "auto",                      # unmatched → a group!
      aaaa = "auto",                         # auto | fake | empty
      direct_dns = ["223.5.5.5:53", "119.29.29.29:53"],
      server_ip = "203.0.113.10",            # pin primary (no DNS bootstrap)
      geoip_dir = "/etc/magicalane/geoip",
      fakeip_filter = ["stun.*.*", "*.ntp.org"],   # REAL answers for these
      fakeip_cache = "/var/lib/magicalane/fakeip.map",  # persist tokens
      rule = [
        { domain_suffix = ["*.corp.example.com"], action = "work" },
        { domain_keyword = ["mirror"],        action = "lb" },
        { domain_suffix = ["cn", "baidu.com"], action = "direct" },
        { geoip = "cn",                       action = "direct" },
        { ip_cidr = ["192.168.0.0/16", "10.0.0.0/8"], action = "direct" },
        { list_file = "/etc/magicalane/gfwlist.txt", action = "proxy" },
      ],
      provider = [
        { name = "gfw", url = "https://example.com/gfwlist.txt",
          interval = 86400, via = "proxy", action = "proxy" },
      ],
    },
} }
```

(The example above is spread out for readability — the real `kind`
value must be one inline line; see `configs/client-full.toml`.)

**Rule evaluation**: top-to-bottom, first match wins, `default`
catches the rest. Actions: `direct` (local resolution + connect,
marked to bypass interception), `proxy` (the primary), or any
server/group name. Suffix matchers are label-aligned wildcards
(`qq.com` covers `weixin.qq.com`; a `*.` prefix is accepted syntax).
GeoIP rules load `<geoip_dir>/<cc>.txt` — plain CIDR lists such as
gaoyifan/china-operator-ip; a missing file only warns. `list_file`
accepts Loyalsoldier/v2ray domain lists; lines with `/` are parsed as
CIDRs, so one file may mix both.

**Transport tuning** (optional, both sides):

```toml
[tuning.kcp]
interval = 10        # internal clock ms
nodelay = true
resend = 2           # fast retransmit aggressiveness
nc = true            # disable congestion control
sndwnd = 512         # packets
rcvwnd = 512
mtu = 1200

[tuning.quic]
congestion = "bbr"   # cubic (default) | bbr | new-reno
send_window = 16777216
receive_window = 16777216
stream_receive_window = 8388608
```

## How the pieces fit

### Transparent interception

`tproxy.mode = "tproxy"` installs firewall rules (iptables/ip6tables +
policy routing) redirecting all local TCP/UDP — both address families
— into the client; rules and routes are removed on exit and adopted
from crashed runs. `mode = "tun"` instead creates a TUN device and a
userspace TCP/IP stack (smoltcp): no iptables at all, same routing
engine — ideal where netfilter is unavailable (needs the `tun-mode`
build, `/dev/net/tun`, CAP_NET_ADMIN). Every tunnel server's address
automatically gets loop-prevention exceptions in both modes.

### Fake-IP DNS

With `dns_mode = "fakeip"` the client answers A/AAAA queries locally
from 198.18.0.0/15 / fc00::/18 (TTL 1). No real query leaves the
machine — DNS pollution is impossible by construction. Connections to
tokens are mapped back to their domain at connect time and routed by
rules; tunnel-routed domains resolve **server-side** (correct CDN
affinity on the far end), direct-routed domains resolve locally via
`direct_dns`. `aaaa = "auto"` fakes AAAA whenever the v6 interception
plane installs — a v4-only client can still reach v6-only sites
through the server's egress. Filtered domains (STUN/NTP/games) get
real answers; `fakeip_cache` keeps tokens stable across restarts.

### Multi-server groups

All group selection is automatic. Health probes fire every `interval`
seconds — an HTTP GET **through each member's own tunnel** — marking
a server dead after 3 consecutive failures and alive after one
success. `url-test` serves the fastest member and switches only on a
win larger than `tolerance` ms; `fallback` walks `servers` in order
and fails over/restores within one probe interval; `load-balance`
spreads connections (`round-robin`) or pins them per destination
(`sticky`). Groups may reference other groups (cycles are rejected at
startup).

### Layered DNS (both sides)

Lookup order: answer cache → `/etc/hosts` → racing upstream probes
(first answer wins; search domains applied) → system resolver.
Client-side `direct_dns` and server-side `[dns] upstream` both accept
a single address or a list; answers are ordered getaddrinfo-style
(v6 first on dual-stack hosts).

### Hot reload

`SIGHUP` re-reads the config file and applies the routing layer
live: rules, providers, geoip lists, the fake-IP filter. Transport
and listener changes still need a restart. `SIGTERM`/`SIGINT` tear
down every network mutation (the clean-exit contract).

## Development

```sh
cargo test                        # unit + config-parse tests
cargo clippy --all-targets        # lint (CI-clean)
./env/up.sh                       # isolated podman lab (client/server/origin)
./env/verify.sh full              # end-to-end suite (51 tests, all modes)
./env/down.sh                     # tear the lab down
```

The lab (`env/`) exercises every feature against real containers:
transports, transparent modes, fake-IP, routing, groups, providers,
auth, kill -9 residue checks. Transport benchmarks: `env/bench.sh`.
Plans and reports: `docs/plans/`, `docs/reports/`.
