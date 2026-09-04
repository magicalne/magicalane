# Smart Transparent Client: Fake-IP DNS + Split Routing + Full IPv6

**Status: draft — awaiting approval**
**Date: 2026-09-04**
**Builds on: transparent client (c22177b), follow-ups F1-F6 (0868ae5)**

## Summary

Transform the tproxy-mode client from an "all-or-nothing" transparent proxy into a
**domain-aware split router**: a fake-IP DNS engine answers every query instantly with
mapping tokens (no DNS round-trip, no pollution possible), every intercepted connection
carries its domain name to a first-match routing engine, matched connections either go
direct (local resolution + direct connect, e.g. China domains) or through the tunnel
(server-side resolution, e.g. blocked domains), and the interception layer itself becomes
dual-family — IPv6 traffic (fake-AAAA via fc00::/18 and literal v6 connections) is fully
intercepted by an ip6tables mirror, closing the existing v6 leak.

One goal, six checkpoints. Each checkpoint lands green (build, `cargo test`, clippy,
`env/verify.sh`) and is committed.

## The Single Goal

> Every connection the client makes is intercepted (v4 and v6), carries its domain when
> one exists (fake-IP mapping), and is routed per user rules — direct or tunneled — with
> zero DNS leakage, zero DNS pollution exposure, and correct CDN affinity on both paths.

Concretely, after this lands:

```
curl http://bilibili.com   → direct, resolved via China DNS, client egress IP
curl http://twitter.com    → tunnel, resolved at server, server egress IP
dig AAAA anything          → instant fc00::/18 token (or empty if no v6)
app → literal [2600:...]:443 → intercepted by ip6tables mirror, routed by rules
kill -9 client             → v4 AND v6 firewall state fully reverted
```

## Why this architecture (decisions already made in discussion)

1. **Fake-IP moves the routing decision to connect time**, where the domain is known.
   DNS routing (China-DNS-for-China vs server-DNS-for-blocked) stops being a
   chicken-and-egg problem: the client resolves *nothing* at DNS time.
2. **DNS pollution is eliminated by construction** — no real DNS answer ever crosses
   the client's network in plaintext.
3. **Option B for IPv6 chosen by user**: fake AAAA records from fc00::/18 + full v6
   interception. Auto-fallback to empty AAAA on hosts without v6 (see assumptions).
4. **Split routing data** comes from user-maintained plain-text domain lists
   (Loyalsoldier/v2ray-rules-dat format), loaded at startup. No geoip in this pass.
5. **Direct connections must escape re-interception** — SO_MARK on our own outbound
   sockets, excluded at the top of the mangle chains (cleaner than uid/cgroup matching).

## Architecture

### Data flow (after)

```
App: A? twitter.com ──► dns interceptor ──► 198.18.0.7 (<1ms, TTL=1)   ┐ mapping recorded
App: AAAA? twitter.com ──► dns interceptor ──► fc00::abcd (<1ms)       ┘ 7 ↔ twitter.com

App connects 198.18.0.7:443 (or [fc00::abcd]:443)
  ├─ iptables REDIRECT (v4 local) / ip6tables mirror ──► tproxy listener
  ├─ getsockname → fake IP ──► FakeIpMap lookup ──► "twitter.com"
  ├─ RoutingEngine::decide("twitter.com")
  │     rule 1: suffix .cn/.baidu.com/... → no match
  │     rule 2: ip_cidr LAN → no match
  │     default: proxy
  ├─ proxy  → connector.connect(Addr::Domain("twitter.com", 443)) → tunnel → server resolves
  └─ direct → DirectConnector: resolve via direct_dns (or system) → TcpStream::connect
              (socket has SO_MARK=0x2A2 → excluded from MGL-* chains)

App connects 2600:... (literal, no DNS)
  └─ ip6tables MGL6 mirror intercepts ──► v6 tproxy listener ──► no fake mapping
     ──► RoutingEngine::decide(ip) ──► ip_cidr/geoip-less/default rules
```

### Component map

| Component | Location | New/Changed |
|---|---|---|
| Fake-IP pools + domain↔IP LRU | `src/dns/fakeip.rs` | new (~250 lines) |
| QNAME parser + response builder | `src/dns/proto.rs` | new (~150 lines) |
| DNS interceptor fake-IP mode | `src/dns/mod.rs` | changed (mode switch) |
| Routing engine (suffix/exact/cidr/file) | `src/routing/mod.rs` | new (~250 lines) |
| Routing config parsing | `src/config.rs` | changed |
| DirectConnector + SO_MARK helper | `src/connector.rs` | changed (~120 lines) |
| TCP dispatch: fake lookup → rules → path | `src/tproxy/mod.rs` | changed |
| UDP dispatch: fake dst → domain → path | `src/udp/mod.rs` | changed |
| ip6tables mirror + v6 policy routes + mark exclusion | `src/tproxy/rules.rs` | changed (~200 lines) |
| v6 transparent listener (IPV6_TRANSPARENT) | `src/tproxy/mod.rs` | changed |
| Wiring: routing config, direct_dns, server_ip pin | `src/main.rs` | changed |
| Dual-stack podman network + new tests | `env/*`, `env/tests/*` | changed + 6 new |

Server side: **unchanged**. The tunnel already carries `Addr::DomainName` end-to-end and
the server resolves dual-stack (`getaddrinfo` → A+AAAA) — verified working since F6.
`DnsRelayStream` is kept for `dns_mode = "tunnel"` (fallback), unused in fakeip mode.

### Key constants

```
FAKE_V4_RANGE   = 198.18.0.0/15   (RFC 2544 benchmark space; Clash convention)
FAKE_V6_RANGE   = fc00::/18       (ULA space; Clash convention)
FAKE_TTL        = 1 second        (mapping is authoritative, not the DNS answer)
MAP_CAPACITY    = 65536 entries per family (LRU; far above real per-host domain counts)
SO_MARK_DIRECT  = 0x2A2           (excluded in MGL-OUT/MGL-PRE/MGL6-* first rule)
MGL6 chains     = MGL6-OUT, MGL6-PRE, MGL6-NAT (mirror of MGL-*)
v6 policy route = fwmark 0x2A1 lookup 141; local ::/0 dev lo table 141 (mirror of v4)
```

### Config (full sketch)

```toml
[kind.Client]
socks5_port = 1080

[kind.Client.tproxy]
mode = "tproxy"
tcp_port = 7895
udp_port = 7896
dns_port = 15353
dns_mode = "fakeip"          # fakeip (default) | tunnel | off

[kind.Client.routing]
default = "proxy"            # unmatched → proxy | direct
aaaa = "auto"                # auto (fake iff v6 interception active) | fake | empty
direct_dns = "223.5.5.5:53"  # optional; resolver for direct-routed domains; default: system
server_ip = "203.0.113.10"   # optional; pin server IP (bootstrapping anti-pollution)

[[kind.Client.routing.rule]]
domain_suffix = ["cn", "baidu.com", "qq.com", "taobao.com"]
action = "direct"

[[kind.Client.routing.rule]]
domain = ["www.exact-match.com"]
action = "proxy"

[[kind.Client.routing.rule]]
ip_cidr = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fc00::/7", "fe80::/10"]
action = "direct"

[[kind.Client.routing.rule]]
list_file = "/etc/magicalane/china-list.txt"   # one domain per line, suffix match
action = "direct"
```

Rule evaluation: first match wins, top to bottom, then `default`.

## Checkpoints

Each checkpoint: implement → `cargo build --release` → `cargo test` → `cargo clippy`
(0 warnings) → `env/verify.sh` (existing 26 green unless the checkpoint migrates a
behavior, in which case the migrated test is updated in the same commit) → commit.

### CP1 — Fake-IP engine, v4 (the DNS half)

- `src/dns/fakeip.rs`: `FakeIpMap` — v4 pool from 198.18.0.0/15, bidirectional
  domain↔IP LRU (`HashMap<IpAddr, String>` + `HashMap<String, IpAddr>` with capacity
  eviction), `assign(domain) -> Ipv4Addr`, `lookup(ip) -> Option<Domain>`.
- `src/dns/proto.rs`: minimal DNS codec — parse header + single question QNAME
  (handles compression pointers in queries by rejecting, labels ≤63, total ≤255),
  build A response copying the question verbatim (preserves 0x20 case), QR/RA bits set,
  TTL=1. PTR queries → NXDOMAIN template.
- `src/dns/mod.rs`: `dns_mode = "fakeip"` path in `serve_client` — parse QNAME →
  assign fake IP → respond locally. **No tunnel round-trip.** Keep existing tunnel
  relay path under `dns_mode = "tunnel"`.
- `src/tproxy/mod.rs` dispatch: on accepted connection, if original dst ∈ 198.18.0.0/15
  → `FakeIpMap::lookup` → replace IP-Addr with Domain-Addr. No rules yet; all → tunnel.
- Unit tests: pool exhaustion/eviction, QNAME parse (valid/malformed/compression),
  response byte layout, round-trip map.
- Env test (new `022-fakeip-a.sh`): `getent hosts origin` returns a 198.18.x.x address
  in <50ms; curl through it still reaches origin (tunneled by domain); test 018
  (ws-dns) updated to expect fake range + working connection.

**Exit criteria:** every DNS answer is local and instant; connections carry domains;
no DNS query leaves the client for tunneled domains.

### CP2 — Routing engine + DirectConnector (the split half)

- `src/routing/mod.rs`: `RoutingEngine { rules, default }` with
  `Action::{Proxy, Direct}`, `decide(&Target) -> Action` where Target is Domain or Ip.
  Matchers: `DomainSuffix` (label-aligned suffix), `DomainExact`, `IpCidr` (v4+v6
  parse), `ListFile` (loaded into suffix set at startup). First match wins.
- `src/config.rs`: parse the `[routing]` block + rule arrays (serde, defaults:
  `default="proxy"`, `aaaa="auto"`).
- `src/connector.rs`: `DirectConnector` — resolve via `direct_dns` resolver (custom
  UDP DNS query through system stack, *not* our interceptor; fall back to system
  `getaddrinfo` when unset) → `TcpStream::connect` trying all addrs (v6 preferred per
  RFC 6724 order as returned). Outbound sockets created with `SO_MARK=0x2A2`.
- `src/tproxy/rules.rs`: prepend `-m mark --mark 0x2A2 -j RETURN` to MGL-OUT and
  MGL-PRE (direct traffic escapes interception; same for the v6 chains in CP3).
- `src/tproxy/mod.rs`: dispatch → `decide()` → DirectConnector or tunnel connector.
- Env fixture: `env/fixtures/china-list.txt` (small: `testsvc-direct`, `origin-local`
  aliases) + second directly-reachable fixture service on the client network;
  routing rule direct for that suffix only.
- Env test (new `023-split-direct.sh`): direct-suffix fetch shows **client** egress
  identity; all other fetches show **server** egress identity. Proves split + correct
  resolver usage.

**Exit criteria:** China-style split routing works; direct path uses local/China
resolution; tunneled path unaffected; direct traffic not re-intercepted.

### CP3 — ip6tables mirror + v6 interception (the leak fix)

- `src/tproxy/rules.rs`: detect v6 availability (`ip -6 route show table main`
  non-empty). If present: create MGL6-OUT/MGL6-PRE/MGL6-NAT mirroring the v4 structure
  (server-v6 exception if server resolved v6, mark exclusion first, loopback/multicast
  RETURNS, v6 REDIRECT for local TCP + udp/53, TPROXY v6 for UDP + PREROUTING),
  `ip -6 rule add fwmark 0x2A1 lookup 141`, `ip -6 route add local ::/0 dev lo
  table 141`. Teardown mirrors apply (same clean-exit contract, same restore mechanism
  via `ip6tables-restore`).
- `src/tproxy/mod.rs` + `src/dns/mod.rs` + `src/udp/mod.rs`: v6 transparent listeners
  (`IPV6_TRANSPARENT` = 72, bind `[::]:port`, dual socket family alongside v4 —
  v4 stays iptables-REDIRECT, v6 uses its own TPROXY listener).
- Dispatch: v6 original dst → fake v6 lookup (CP4) or real IP rules.
- Env: `env/up.sh` gains dual-stack network (`podman network create --ipv6`) when
  supported; origin/testsvc bind v6.
- Env test (new `024-v6-intercept.sh`): connect to origin's literal v6 address →
  connection succeeds **through the tunnel** (server-side egress identity visible to
  testsvc), proving no direct v6 leak. `025-v6-residue-kill9.sh`: kill -9 client →
  `ip6tables -S` shows zero MGL6-* chains, `ip -6 rule` has no 0x2A1 entry.

**Exit criteria:** IPv6 can no longer bypass the client; v6 connections are
rule-routable; clean-exit contract holds for the v6 plane.

### CP4 — Fake-IP v6 pool + fake AAAA (the parity half)

- `src/dns/fakeip.rs`: v6 pool from fc00::/18, shared bidirectional map keyed by
  `IpAddr`; `assign_v6(domain)`, unified `lookup`.
- `src/dns/proto.rs`: AAAA response builder.
- `aaaa = "auto"`: fake AAAA iff CP3 installed v6 interception; `"empty"`/`"fake"`
  override. Default auto.
- Dispatch: v6 fake dst → domain → rules (same engine; DirectConnector already
  dual-stack).
- Env test (new `026-fakeip-aaaa.sh`, v6 env only): `dig AAAA` returns fc00::/18
  answer; curl (forcing v6) reaches origin through tunnel; direct-suffix v6 works too.

**Exit criteria:** apps see and use v6 tokens; full family parity; v4-only hosts
degrade gracefully (auto → empty AAAA, everything still works via v4).

### CP5 — UDP + hardcoded DNS + bootstrapping (the completeness half)

- `src/udp/mod.rs`: UDP packets to fake dst (v4+v6) → domain lookup → route:
  tunnel = existing UDP flow with Domain Addr (verify server `UdpFramedStream`
  resolves domain names — it handles the magic DNS hostname today; extend if it
  only accepts IPs), direct = local UDP socket with SO_MARK, resolved via direct_dns.
  Unmapped dst → ip rules/default.
- Hardcoded-DNS apps (8.8.8.8:53): caught by udp/53 REDIRECT → fakeip mode answers
  locally (CP1 already covers the DNS side; this checkpoint verifies QUIC/HTTP3
  traffic to fake IPs rides the UDP relay by domain).
- `server_ip` pin in config: used for rule exclusions directly; hostname resolution
  happens pre-rules only when unpinned (anti-pollution bootstrapping).
- Env test (new `027-hardcoded-dns-udp.sh`): python UDP DNS query to 8.8.8.8:53 gets
  fake answer; subsequent QUIC/UDP flow to the fake IP is routed per rules.

**Exit criteria:** UDP traffic (incl. HTTP/3-style) is domain-routed; DNS-side
tricks can't leak; bootstrapping no longer depends on plaintext DNS.

### CP6 — End-to-end hardening, benchmarks, docs (the proof half)

- Full `env/verify.sh full` green on dual-stack env: 26 existing (018 updated) +
  6 new = 31 tests.
- Residue suite extended: graceful + kill -9 on dual-stack → both families clean.
- Benchmarks (`env/bench.sh` extended with `--profile fakeip`):
  - fake-IP DNS answer latency: p50 < 1ms (was ~300ms tunneled RTT)
  - connect p50 through fake path: < 2ms (QUIC) / < 5ms (KCP pooled)
  - direct-path throughput vs tunneled (expected: direct ≈ line rate, no tunnel RTT)
- Docs: README routing section, AGENTS.md env notes (dual-stack flag, china-list
  fixture), this plan updated with final numbers.

**Exit criteria:** measurable proof of every claim; suite stable ×3 consecutive runs.

## Files touched

- [ ] `src/dns/fakeip.rs` (new)
- [ ] `src/dns/proto.rs` (new)
- [ ] `src/dns/mod.rs` (fakeip mode)
- [ ] `src/routing/mod.rs` (new)
- [ ] `src/connector.rs` (DirectConnector + SO_MARK)
- [ ] `src/tproxy/mod.rs` (dispatch + v6 listeners)
- [ ] `src/tproxy/rules.rs` (mark exclusion + ip6tables mirror + v6 routes)
- [ ] `src/udp/mod.rs` (fake dst routing + direct UDP)
- [ ] `src/config.rs` (routing config)
- [ ] `src/main.rs` (wiring)
- [ ] `src/lib.rs` (module exports)
- [ ] `env/up.sh` / `env/down.sh` (dual-stack network)
- [ ] `env/fixtures/china-list.txt` (new fixture)
- [ ] `env/configs/*` (routing sections)
- [ ] `env/tests/022-fakeip-a.sh` … `027-hardcoded-dns-udp.sh` (6 new)
- [ ] `env/tests/018-tproxy-ws-dns.sh` (update expectations)
- [ ] `env/verify.sh` (register new tests + v6 profile)
- [ ] `env/bench.sh` (fakeip profile)
- [ ] `README.md`, `AGENTS.md`

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Mapping evicted while connection in flight | LRU capacity 65k/family, TTL-independent; on miss fall back to IP rules (never drop) |
| App caches fake DNS beyond TTL | TTL=1; LRU keeps hot entries; Clash proves this works in practice at scale |
| ip6tables-restore unavailable in env container | Verify in Containerfile at CP3 start; `apt-get install iptables` already covers ip6tables; fallback = v6 block mode (REJECT all client v6), config `ipv6_intercept = "block"` |
| SO_MARK requires CAP_NET_ADMIN | Client already manipulates iptables → capability present; assert at startup, clear error if not |
| REDIRECT on ip6tables nat for local TCP | ip6table_nat supports REDIRECT since kernel 4.18; if env kernel lacks it, v6 local TCP falls back to TPROXY+policy-route (v4 gateway path already proves this flow) |
| Fake-IP breaks apps doing PTR/reverse lookups | PTR → NXDOMAIN (documented; same behavior as Clash) |
| DirectConnector re-intercepted → loop | SO_MARK exclusion is rule #1 in every chain; env test asserts direct fetch works (a loop would hang it) |
| UDP domain Addr unsupported by server relay | Verify `UdpFramedStream` first in CP5; extend server if needed (small change: resolve via `ToSocketAddrs` like TCP path) |
| Dual-stack podman network flakiness | `--ipv6` flagged env profile; v4-only env keeps all 26 tests green (v6 tests skip with `ok # skip`) |

## Non-goals

- DNSSEC validation, recursive resolver, DoH upstream (point `direct_dns`/server
  upstream at unbound if ever needed)
- geoip database rules (ip_cidr + domain lists cover this pass; geoip = future stub)
- TUN-mode integration of fake-IP (tproxy mode only; TUN stays feature-flagged)
- KCP transport v6 on the wire (destination families are unaffected — server resolves;
  quinn dual-stack already merged in F6)

## Assumptions (defaults chosen; change if you disagree)

1. **TTL = 1s** on fake answers (Clash default; mapping cache is authoritative).
2. **`aaaa = "auto"`** default: fake AAAA only when v6 interception is actually
   installed (v4-only hosts get empty AAAA — safe degradation).
3. **`direct_dns` default = system resolver** (works everywhere; China users set
   223.5.5.5 to dodge ISP ad-injection).
4. **`dns_mode = "tunnel"` kept** as a fallback config (no removal of existing
   behavior; fakeip is the new default when routing is configured).
5. **China list** for tests is a tiny in-repo fixture; production lists are
   user-supplied files (Loyalsoldier format, one domain per line).
6. **First match wins** rule order (documented in README).

## Open questions (product forks — need your call)

1. **Default action when `[routing]` is absent entirely**: keep today's behavior
   (everything tunneled) — or require explicit config? *(Recommend: absent routing =
   all-tunneled, exactly today's behavior; fake-IP still active in tproxy mode.)*
2. **Should `domain_suffix` match be label-aligned strict** (`qq.com` matches
   `weixin.qq.com` but NOT `notqq.com`) — assume yes, standard behavior. OK?
3. **Env dual-stack**: make it default for `env/up.sh` or opt-in flag
   (`--ipv6`)? *(Recommend opt-in first, flip to default after CP6 proves stable.)*

## Acceptance criteria (mirrors checkpoints; each independently verifiable)

- [ ] `getent hosts <tunneled-domain>` returns 198.18.0.0/15 in <50ms; connection works
- [ ] `dig AAAA <tunneled-domain>` returns fc00::/18 (dual-stack env, `aaaa=auto/fake`)
- [ ] Direct-suffix fetch shows client egress; tunneled fetch shows server egress
- [ ] Direct-path resolution does NOT use the tunnel (no dns magic-addr traffic)
- [ ] Literal v6 connection is intercepted (server-side egress proof) — no leak
- [ ] `iptables -S` + `ip6tables -S` after kill -9: zero MGL/MGL6 chains; no mark rules
- [ ] `env/verify.sh full` green: 26 existing (018 adapted) + 6 new, ×3 consecutive runs
- [ ] `cargo test` green incl. new unit tests; `cargo clippy` 0 warnings
- [ ] Bench: DNS p50 <1ms local; connect p50 <2ms (QUIC) via fake path
- [ ] README + AGENTS.md document routing config and dual-stack env usage
