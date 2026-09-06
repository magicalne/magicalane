# Gap analysis: magicalane vs Clash Premium / mihomo

**Date: 2026-09-06 · post layered-DNS delivery (87d84de)**

Scope: honest feature comparison to drive the roadmap. Clash Premium is
EOL (Tencent takedown, Nov 2023); its successor **mihomo (Clash.Meta)**
inherits the feature set — both are used as the reference here.

## 1. Feature matrix

| Area | magicalane today | Clash Premium / mihomo | Gap |
|---|---|---|---|
| **Transport** | own QUIC (BBR) + KCP+TLS, tunable, pooled sessions | speaks *other* proxies: SS/SSR, VMess/VLESS, Trojan, Hysteria2, TUIC, WireGuard, Snell, SSH | by design (own protocol); chaining out to generic proxies missing |
| **Inbound** | SOCKS5 (no auth, 0.0.0.0) | SOCKS5+auth, HTTP, mixed, SS inbound | HTTP proxy + inbound auth missing; **LAN exposure without auth is a footgun** |
| **Transparent** | tproxy v4+v6 (TCP REDIRECT + UDP TPROXY, workstation+gateway), clean-exit contract, fake-IP DNS both families | tproxy/redir + full **TUN** (gVisor/system stack, auto-route) | **TUN mode is a stub** (smoltcp TODO) — required for Android/router/iOS-adjacent use |
| **Routing rules** | domain_suffix, domain exact, ip_cidr, list_file (mixed), geoip (country txt), first-match, default | + DOMAIN-KEYWORD, DOMAIN-REGEX, GEOSITE, SRC-IP-CIDR, SRC/DST-PORT, **PROCESS-NAME/PID**, RULE-SET, SUB-RULE, logical AND/OR/NOT, ASN | several rule types missing (most are small engine additions) |
| **Rule data** | local files only (Loyalsoldier format, chnroutes) | **rule-providers**: remote URL + interval + auto-update, mrs/binary formats, geosite categories | no auto-update; no geosite-style category tags |
| **Proxy groups** | **single server** | select / url-test / fallback / load-balance / relay chains, health checks | no multi-server at all — the biggest architectural gap |
| **DNS** | fake-IP (instant, pollution-proof), layered resolver (cache→hosts→racing→system) both sides, RFC 6724 ordering | fake-ip + redir-host, DoH/DoT/DoQ upstreams, nameserver-policy, fallback+geoip, **fake-ip-filter**, persistent fake-ip cache | fake-ip-filter + cache persistence missing (compat!); DoH upstream missing; our racing+cache is on par or better than base Clash |
| **Sniffer** | none (real-IP conns classified by geoip only) | TLS SNI / HTTP host sniffing → re-domainize IP connections | missing — closes the DoH/literal-IP "domain lost" hole |
| **API/UI** | none | REST controller, external UIs (yacd/metacubexd), live connections, traffic stats, **hot reload** | nothing — the whole operations surface |
| **Config lifecycle** | restart to apply | hot reload (SIGHUP + API), profile providers | no hot reload |
| **Observability** | logs, bench tooling | per-connection live view, traffic API, pprof | nothing beyond logs |

## 2. Known internal limitations (self-found)

1. **UDP reply source address**: TPROXY replies originate from the
   interceptor socket's address, not the original destination — strict
   peer-checking apps (DTLS, some games) may reject. (QuicEnabled apps
   tolerate; verified echo/DNS flows fine.)
2. **Fake-IP map is in-memory**: client restart invalidates mappings
   while apps may still hold cached tokens (mitigated by TTL=1; Clash
   persists the map to disk).
3. **KCP transport is IPv4-only on the wire** (destination families
   unaffected — server resolves); QUIC is dual-stack.
4. **Gateway mode + fakeip**: forwarded-clients' DNS is answered by the
   gateway's fake layer, but token mapping is shared across all clients
   (fine) — no per-source-device policy.
5. TUN mode: device + routes + contract exist; smoltcp stack TODO.

## 3. Prioritized gaps

### Tier 1 — identity-aligned, high value

| # | Feature | Why | Effort |
|---|---|---|---|
| 1 | **SOCKS5 inbound auth + bind-address** (`allow-lan`) | security footgun today: any LAN peer can use the client | S (1-2d) |
| 2 | **fake-ip-filter** + fake-ip cache persistence | compat (STUN/NTP/games break on tokens) + restart resilience | S (1-2d) |
| 3 | **HTTP proxy inbound** (with CONNECT) | corporate/tooling compatibility, cheap alongside SOCKS | S (1-2d) |
| 4 | **rule-providers**: remote lists + interval + atomic swap | no more cron; parity with Clash workflows (geosite/geoip/china lists all become URLs) | M (2-4d) |
| 5 | **more rule types**: keyword, regex, src-ip-cidr, src/dst-port | engine additions; src rules enable per-device policy in gateway mode | S-M (2-3d) |
| 6 | **hot reload** (SIGHUP): rules/lists/geoip swap atomically | ops sanity; enables #4 | M (2-3d) |
| 7 | **sniffer (TLS SNI → re-domainize)** | closes the DoH/literal-IP hole properly (route by domain even for IP conns) | M-L (4-7d) |
| 8 | **REST controller + live connections API** (yacd-compatible subset) | visibility + UI ecosystem for free | M-L (4-7d) |

### Tier 2 — architectural, big but transformative

| # | Feature | Why | Effort |
|---|---|---|---|
| 9 | **multi-server + proxy groups** (select/url-test/fallback/load-balance) with health checks | resilience across servers — THE headline Clash concept; our single-server is the biggest gap | L (1-2w) |
| 10 | **TUN mode completion** (smoltcp stack) | router/Android/desktop without iptables; makes magicalane a real VPN-shaped product | L (1-2w) |
| 11 | **PROCESS-NAME routing** (Linux cgroup/sockdiag) | per-app policy on a workstation — premium's killer niche feature | L (1w) |

### Tier 3 — likely out of scope (state explicitly)

- **Speaking other proxy protocols** (SS/VMess/Trojan/VLESS/Hysteria/
  TUIC/WireGuard/Snell): magicalane's identity is its own QUIC/KCP
  transport; interop only matters if migrating off existing servers.
  A generic **SOCKS5/HTTP upstream** (relay chain) would cover the
  realistic interop slice for a fraction of the cost.
- **eBPF**, **redir-host DNS mode** (we believe fake-ip is strictly
  better for this design), **ASN rules**, **mrs binary geodata**,
  **utls fingerprinting**, **Reality**: niche/duplicative.

## 4. Recommended order (next 3 work items)

1. **Security bundle**: inbound auth + allow-lan/bind + HTTP inbound (#1 #3)
2. **Compat bundle**: fake-ip-filter + persistent fake-ip map (#2)
3. **rule-providers + hot reload** (#4 #6) — changes the daily-use story
   from "edit files + restart" to Clash-grade operation

Then reassess: multi-server groups (#9) vs TUN completion (#10) is the
fork between "proxy power-user tool" and "VPN product".
