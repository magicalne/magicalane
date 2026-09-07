# Magicalane - A QUIC based proxy

## Download

Checkout the recent releases.

## Run

Both sides read a TOML config via `--config`. The tunnel transport is `quic` (default) or `kcp`; KCP can additionally layer TLS (`tls = true`, default).

`server`:

```toml
password = "your-password"
bandwidth = 65536
verbose = true
kind = { Server = { port = 4433, ca = "server.pem", key = "server.key", protocol = "kcp", tls = true } }
```

`client`:

```toml
password = "your-password"
bandwidth = 65536
verbose = true
kind = { Client = { proxy = { host = "your.hostname", port = 4433, ca_path = "ca.pem", protocol = "kcp", tls = true }, socks5_port = 1080, tproxy = { tcp_port = 7895, udp_port = 7896 } } }
```

Then start each with `magicalane --config <file>`; the client serves SOCKS5 on `socks5_port`.

## Transparent mode + fake-IP DNS + split routing

Set `tproxy.mode = "tproxy"` for transparent interception (all TCP/UDP,
both IPv4 and IPv6, firewall-based; routes/rules are transactional —
removed on any exit, adopted from crashes on restart).

With `dns_mode = "fakeip"`, DNS is answered LOCALLY with tokens
(198.18.0.0/15 for A, fc00::/18 for AAAA): no real query ever crosses
your network, so DNS pollution is impossible by construction.
Connections to tokens are mapped back to their domain at connect time
and routed by rules — for example China domains direct, everything
else through the tunnel (direct connections resolve locally, getting
correct in-country CDN answers):

```toml
kind = { Client = { proxy = { host = "your.hostname", port = 4433, ca_path = "ca.pem", protocol = "quic" }, socks5_port = 1080,
  tproxy = { mode = "tproxy", tcp_port = 7895, udp_port = 7896, dns_port = 15353, dns_mode = "fakeip" },
  routing = { default = "proxy", aaaa = "auto",
    rule = [ { domain_suffix = [ "cn", "baidu.com", "qq.com" ], action = "direct" },
              { ip_cidr = [ "192.168.0.0/16", "10.0.0.0/8" ], action = "direct" },
              { list_file = "/etc/magicalane/china-list.txt", action = "direct" } ] } } }
```

- Rules evaluate top-to-bottom, first match wins; `default` catches the rest.
- `list_file` loads Loyalsoldier/v2ray-format domain lists (one domain
  per line, `#` comments, optional `domain:`/`full:` prefixes). Lines
  with `/` are auto-detected as CIDRs, so one file can mix domains and
  IP ranges.
- `geoip = "cn"` classifies REAL-IP connections (literal IPs, DoH-resolved,
  hardcoded) by country: it loads `<geoip_dir>/cn.txt` (default
  `/etc/magicalane/geoip`), a plain CIDR list — use chnroutes2
  (`chnroutes.txt` / `chnroute6.txt`) or gaoyifan/china-operator-ip
  (`china.txt` / `china6.txt`), e.g.
  `curl -o /etc/magicalane/geoip/cn.txt .../china.txt`. Other countries
  work the same way (`geoip = "us"` → `us.txt`). Missing file = warning,
  rule stays inert.
- `aaaa = "auto"` hands out fc00::/18 tokens whenever the IPv6
  interception plane installs (it only needs local interception, so
  even v4-only clients can reach v6-only sites through the tunnel —
  the server connects over its own IPv6 egress; `curl -6 ifconfig.me`
  then reports the server's IPv6).
- Hardcoded resolvers (8.8.8.8) can't bypass: the udp/53 redirect is
  destination-agnostic.
- UDP (incl. QUIC/HTTP3-style flows) routes by the same rules; tunnel
  destinations are resolved server-side.

### Layered DNS (both sides)

Resolution is cached, hosts-aware, and redundant:

- client `direct_dns` accepts a single resolver or a **list** — probes
  race across all upstreams, first answer wins, dead entries cost
  nothing (`direct_dns = ["223.5.5.5:53", "119.29.29.29:53"]`)
- the server resolves tunnel-routed domains through `[dns] upstream`
  (same racing; defaults to every nameserver in resolv.conf) with a
  TTL-bound answer cache:

```toml
[dns]
upstream = ["1.1.1.1:53", "8.8.8.8:53"]
cache_size = 4096
```

Lookup order everywhere: cache → /etc/hosts → racing probes (search
domains applied) → system resolver. Answers order getaddrinfo-style
(v6 first on dual-stack hosts).

Measured (local lab): fake-IP answers p50 ≈ 0.11 ms; full connect via
token p50 ≈ 1.4 ms.

## Multiple servers: automatic proxy groups

One client can pool several tunnel servers — **mixed transports in one
pool** (QUIC and KCP side by side) — and route each connection to a
server or group by domain rule. All selection is automatic: the
strategy decides, backed by active health probes (an HTTP GET through
each server's own tunnel; dead after 3 consecutive failures, alive
again after one success).

```toml
[kind.Client.proxy]            # primary server, name "default"
host = "a.example.com"
port = 4433

[[kind.Client.server]]         # additional servers
name = "work"                  # referenced by rules/groups
host = "b.example.com"
port = 4433
protocol = "kcp"               # quic | kcp, freely mixed
ip = "203.0.113.9"             # optional pin (skip DNS for this server)

[[kind.Client.group]]
name = "auto"
type = "url-test"              # url-test | fallback | load-balance
servers = ["default", "work"]  # servers or other groups (no cycles)
url = "http://www.gstatic.com/generate_204"   # probe (default)
interval = 300                 # seconds
tolerance = 50                 # ms: url-test switch hysteresis

[[kind.Client.group]]
name = "lb"
type = "load-balance"
strategy = "round-robin"       # round-robin (default) | sticky
servers = ["default", "work"]
```

Group semantics:

- **`url-test`** — probes every member through its own tunnel, serves
  the fastest; switches only when a challenger beats the incumbent by
  more than `tolerance` ms (anti-flap)
- **`fallback`** — strict `servers` priority: the first alive member
  serves; the next takes over within one probe interval on death, and
  priority is restored on recovery
- **`load-balance`** — `round-robin` spreads connections evenly;
  `sticky` hashes the destination so one site keeps one egress while
  it lives. Dead members are skipped automatically.

Rules (and `default`, and providers' `action`) accept any server or
group name in addition to `proxy`/`direct`; suffix rules are
wildcards (`qq.com` covers subdomains; `*.example.com` is accepted
syntax). New matcher: `domain_keyword` (substring).

```toml
[kind.Client.routing]
default = "auto"               # unmatched traffic → the url-test group

[[kind.Client.routing.rule]]
domain_suffix = ["*.corp.example.com", "corp.example.com"]
action = "work"                # → that server

[[kind.Client.routing.rule]]
domain_keyword = ["mirror"]
action = "lb"                  # → the load-balance group
```

Every server's address gets the loop-prevention exceptions (iptables
RETURN rules + TUN routes) automatically, v4 and v6.
