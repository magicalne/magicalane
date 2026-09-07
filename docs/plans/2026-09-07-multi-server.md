# Multi-Server Support: Automatic Proxy Groups (url-test / fallback / load-balance) + Per-Domain Server Selection

## Summary

Today a client configures exactly one tunnel server (`[kind.Client.proxy]`). This plan adds multiple servers and fully automatic proxy groups over them — `url-test` (pick the fastest, continuously), `fallback` (priority list, first alive wins), `load-balance` (round-robin or sticky-by-destination spread) — and extends routing rules so a domain (wildcard/suffix) can pin traffic to a specific server or group: `action = "work-vpn"`. No manual selection: the strategy decides, backed by active health probes.

## Context

- Gap analysis (`docs/reports/2026-09-06-gap-analysis-clash.md`) lists "single server / no proxy groups" as the remaining architectural gap. This closes it.
- Current wiring: `main.rs` builds one `QuicConnector` **or** `KcpConnector` and threads the generic `C: Connector` through `run_client` → socks5 / tproxy / tun / udp. `RoutingEngine::decide()` returns `Action::{Proxy, Direct}`; every `Action::Proxy` site calls the same connector.
- The heterogeneous-connection problem is already solved on the server side by the `Remote` enum (`src/dispatch.rs`: `Tcp | Dns | Udp` forwarding `AsyncRead/Write`). We replicate that pattern client-side.
- Health probing: `src/httpfetch.rs::fetch_over<S>` already does HTTP GET over any stream — the probe primitive exists.
- KCP has a prewarm session pool per connector; QUIC holds one long-lived connection per `ClientActorHndler`. Both are `Clone`, so per-server connector instances are cheap and independent.

## Goals

1. Multiple servers in one client config, **mixed transports allowed** (server A QUIC + server B KCP in the same pool).
2. Group policies, all automatic: `url-test`, `fallback`, `load-balance` (round-robin + sticky-by-destination). No `select`/manual mode — the chosen strategy always decides.
3. Routing rules target a server or group by name: `action = "hk"`, `default = "auto"`, with domain wildcard semantics (`domain_suffix = ["*.corp.example.com"]`, plus new `domain_keyword`).
4. Groups track server health (active probes through each tunnel) and avoid dead servers automatically.
5. Full back-compat: single-server configs (even the `[kind.Client.proxy]` shorthand) keep working unchanged; `action = "proxy"` means "the default target".

## Non-goals

- REST API / WebUI / any manual selection mode (a future feature of its own).
- `relay` groups (server chaining), `REJECT` action, per-connection subscription providers (server list by URL).
- Any change to the server side — servers are unaware they're pooled.

## Approach

### 1. Config surface (`src/config.rs`)

```toml
[kind.Client.proxy]            # primary server (back-compat; implicit name "default")
host = "a.example.com"         #   rules/groups may also reference it by name "default"
port = 4433

[[kind.Client.server]]         # additional servers
name = "work"                  # required, unique
host = "b.example.com"
port = 4433
protocol = "kcp"               # quic (default) | kcp — mixed freely
ca_path = "..."
ip = "203.0.113.9"             # optional pin (per-server server_ip)

[[kind.Client.group]]
name = "auto"
type = "url-test"              # url-test | fallback | load-balance
servers = ["default", "work"]  # server names or other groups (no cycles)
url = "http://www.gstatic.com/generate_204"   # probe URL (default gstatic 204)
interval = 300                 # seconds (default 300)
tolerance = 50                 # ms; url-test hysteresis (default 50)

[[kind.Client.group]]
name = "lb"
type = "load-balance"
strategy = "round-robin"       # round-robin (default) | sticky
servers = ["default", "work"]
```

Rule targeting — `action` accepts any name in addition to `proxy`/`direct`:

```toml
[[kind.Client.routing.rule]]
domain_suffix = ["*.corp.example.com", "corp.example.com"]   # "*.": stripped, suffix semantics
action = "work"                 # → server (or group) named "work"

[kind.Client.routing]
default = "auto"                # unmatched → group "auto" (still accepts "proxy"/"direct")
```

- `action = "proxy"` / `default = "proxy"` keep today's meaning: the primary server (`[kind.Client.proxy]`).
- Unknown names fail fast at startup with the offending rule/field in the error.
- New matcher `domain_keyword = [...]` (substring) — cheap, complements suffix/exact.
- Groups may reference other groups (resolution at lookup time, cycle = config error detected at startup).

### 2. Heterogeneous tunnel connections (`src/tunnel.rs`, new)

```rust
pub enum TunnelStream { Quic(QuicStream), Kcp(EitherKcpStream) }   // AsyncRead/Write forwarding (Remote pattern)

pub enum TunnelConnector { Quic(QuicConnector), Kcp(KcpConnector) }

impl Connector for TunnelConnector { type Connection = TunnelStream; ... }
```

`run_client` and every serve path (socks5, tproxy, tun, udp) drop the `<C, IO>` generics for the tunnel side and take `ProxyPool` directly (they stay generic nowhere or only over the local side, which is always `TunStream`/`TcpStream` anyway — mechanics unchanged since `Proxy::new` remains generic). `Proxy<TunnelStream, TunnelStream>` for tunnels; direct paths keep `TcpStream`.

### 3. The pool (`src/tunnel.rs`)

```rust
pub struct ServerEntry { name: Arc<str>, connector: TunnelConnector,
                         state: Arc<RwLock<ProbeState>> }   // alive, latency, last_probe

pub struct ProxyPool {
    servers: HashMap<Arc<str>, Arc<ServerEntry>>,
    groups:  HashMap<Arc<str>, Arc<Group>>,
    default: Target,             // Target::Server("default") | Group(...)
}

pub enum Target { Server(Arc<str>), Group(Arc<str>) }
```

- `pool.connect(target: Option<&str>, dst: Addr)`: resolve name → server/group → concrete `TunnelConnector` (strategy applied) → `connect(dst)`. `None` = default target.
- Every former `Action::Proxy => connector.connect(...)` site becomes `pool.connect(decision.server(), addr)`.

### 4. Strategies (in `ProxyPool`, one spawned probe task per group needing health)

- **`url-test`**: probe all member servers through their own tunnel (`fetch_over(TunnelStream, 204-url)`, elapsed = latency). Best = min latency among alive; switch only if the new best beats the incumbent by `tolerance` ms (anti-flap, Clash semantics). Dead after 3 consecutive failures; alive after 1 success.
- **`fallback`**: same probe data; chosen = first alive member in `servers` order.
- **`load-balance`**:
  - `round-robin`: atomic counter per group over the alive members.
  - `sticky`: `DefaultHasher` of the connection's destination (domain if known, else IP) → consistent member index; falls back to round-robin while members are dead.
- Probes run on `interval`; first probe immediately at startup. Probe traffic goes **direct** through that server's own tunnel (never through another server).

### 5. Routing engine (`src/routing/mod.rs`)

- `Action` stays `Copy` (`Proxy | Direct`) but `decide()` gains a sibling returning the full decision:
  ```rust
  pub struct Decision { pub action: Action, pub server: Option<Arc<str>> }
  pub fn decide_named(&self, target: Target<'_>) -> Decision
  ```
  Rules compiled with their `action` name resolved to `Option<Arc<str>>` at build time (`None` = primary). `TproxyRouter::route` returns `(Addr, Decision)`; call sites unchanged except reading both fields.
- Wildcard unification: `normalize()` strips a leading `*.` (suffix matcher already covers subdomains; `*.` becomes accepted syntax, matching the `fakeip_filter` convention).

### 6. Bootstrap concerns

- Per-server optional `ip` pin (analogous to today's `server_ip`): the client resolves/connects that server without plaintext DNS. Multiple servers each get their own pin; `routing.server_ip` remains the pin for `[kind.Client.proxy]`.
- The tproxy/TUN "server exception" routes (avoid intercepting our own tunnel traffic) must cover **all** server IPs: today one route for `proxy.host`; extend to every server with a known/pinned IP.

### 7. Env & tests

- `env/up.sh`: new container `magicalane-server2` (same image; QUIC :4533, and a KCP :4534 process in the same container when the transport matrix needs it — ws-daemon pattern). Second cert (`env/certs.sh` addition).
- Config variants: `client-{transport}-ws-multi.toml` — two servers (primary + server2, different protocols where the transport allows), groups, named rules.
- New tests:
  - **036-per-server-rules**: `*.testsvc` → server2, origin → primary. Oracle: each server's log lines (relay dst hostnames distinguish which server served). Asserts per-domain selection + wildcard.
  - **037-group-fallback**: group `[server2, primary]`; kill server2 mid-test; domain → group still resolves through primary (probe interval small, e.g. 2s). Restart server2, assert it's picked again (alive again).
  - **038-lb-and-urltest**: round-robin group over both servers — two sequential connections hit different servers (log oracle); url-test with `tolerance` picks the (only) alive server after one dies.
- Cargo tests: group selection logic (min-latency + tolerance hysteresis, fallback order, rr order, sticky hash stability), config parse (servers/groups/named actions/unknown name error), wildcard normalization, cycle detection.
- README + gap-analysis doc updated (multi-server moves from "missing" to shipped).

### Checkpoints

- **CP1**: config + `TunnelStream`/`TunnelConnector` + de-genericized `run_client` (single server via pool, all existing tests green) — pure refactor, no behavior change.
- **CP2**: `ProxyPool` with plain servers + named rule targets wired through socks5/tproxy/tun/udp; cargo tests; test 036.
- **CP3**: strategies + probe tasks; cargo tests; tests 037/038.
- **CP4**: mixed-protocol pool coverage, README/docs, full suite ×3.

## Files touched

- [ ] `src/config.rs` — `ServerSpec`, `GroupSpec`, named actions, `domain_keyword`, per-server `ip`
- [ ] `src/tunnel.rs` (new) — `TunnelStream`, `TunnelConnector`, `ServerEntry`, `ProxyPool`, strategies, probes
- [ ] `src/routing/mod.rs` — `Decision`/`decide_named`, wildcard normalize, keyword matcher
- [ ] `src/main.rs` — build pool from config, probe tasks, SIGHUP path, per-server exception routes
- [ ] `src/tproxy/mod.rs`, `src/tun/mod.rs`, `src/udp/mod.rs`, `src/socks5/*` — decision call sites
- [ ] `env/up.sh`, `env/certs.sh`, `env/down.sh` — server2 container + certs
- [ ] `env/configs/client-*-ws-multi.toml`, `env/tests/03{6,7,8}-*.sh`
- [ ] `README.md`, `docs/reports/2026-09-06-gap-analysis-clash.md`

## Risks & tradeoffs

- **De-genericization churn**: `serve<C, IO>` signatures simplify (tunnel side becomes concrete); `Proxy::new` stays generic so relays are untouched. Mechanical, verified by existing 45-test suite.
- **Probe cost/complexity**: active probes through each tunnel add traffic (one 204 GET per interval per server — negligible) and a background task per group; failure thresholds are conservative (3 dead / 1 alive) to avoid flapping.
- **No manual mode**: a deliberate scope cut — strategies decide (REST API/WebUI is gap #9, separate future work).
- **Sticky lb rehashing**: member death rehashes destinations across remaining servers — accepted (standard consistent-hashing caveat at this scale).
- **QUIC one-connection-per-server**: pooling servers multiplies long-lived QUIC connections linearly — bounded by config size, fine.

## Acceptance criteria

1. Single-server configs (all existing env configs, unit tests) behave identically — full suite green without edits to their configs.
2. A client with servers A(QUIC) + B(KCP) routes `*.testsvc` → B and everything else → A, verified by server-side log oracles (test 036, both transports).
3. With group `[B, A]` and B killed, tunneled domains still resolve via A within one probe interval; recovery within one interval after B restarts (test 037).
4. Round-robin group alternates servers across sequential connections; url-test converges to the sole alive server (test 038).
5. Unknown action/group/server names, group cycles, and empty groups are config-load errors naming the offender.
6. `cargo test` (strategy + parse + matcher units), `cargo clippy` 0 warnings, `env/verify.sh full` ×3 consecutive green.

## Assumptions (decided)

- Group types: `url-test`, `fallback`, `load-balance` only — all automatic (user decision 2026-09-07: no `selected` field, no manual mode).
- Load-balance strategies: `round-robin` (default) + `sticky` (destination hash).
- Env coverage: multi-server tests run on QUIC, plus one mixed-protocol (QUIC+KCP in one pool) assertion in test 036.
- The primary server (`[kind.Client.proxy]`) is referenceable as `"default"` in groups and rules; `[[server]]` entries require explicit unique names.
