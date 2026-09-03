# Follow-up plan: DNS fix, ws harness, KCP improvements, TUN, BBR default, IPv6

> Path: `docs/plans/2026-09-04-followups.md`
> Status: draft for review — no implementation yet.
> Supersedes the "follow-up items" section of `c22177b`'s commit message.

## Summary

Six follow-up items from the transparent-client delivery and benchmark
findings, ordered by user-visible impact: fix the DNS module's circular
dependency, make the ws test harness reliable, give KCP session reuse and a
real congestion controller, make BBR the QUIC default, implement TUN mode,
and add IPv6. Each is scoped to be independently deliverable and verifiable
by the harness (`env/verify.sh`) per the mandatory protocol.

## Context

- `docs/plans/2026-09-03-transparent-client.md` — the original plan (phases
  1–4); phases 1–2 partially delivered in `c22177b`, phase 3 (TUN) stubbed,
  phase 4 (IPv6) not started.
- `docs/reports/2026-09-03-transport-benchmarks.md` — KCP connect ~300×
  slower than QUIC (no session reuse); BBR transformative under loss.
- `docs/reports/2026-09-03-badnet-usability.md` — cubic unusable on WAN;
  BBR the only viable cross-country config; KCP needs real CC.
- Verification framework: `env/verify.sh` (26 tests), `env/bench.sh`,
  `env/badnet.sh` — all mandatory per AGENTS.md.

## F1 — DNS module: fix the circular dependency

**Problem**: The DNS interceptor starts before the QUIC tunnel is
established. The first DNS query triggers `connector.connect()` which
initiates the QUIC handshake. But the QUIC client needs to resolve
`magicalane-server` to an IP address — via DNS — which goes through the
DNS interceptor → circular.

**Fix**: Pre-resolve the server address BEFORE starting the DNS interceptor.
The connector already resolves at construction (`ClientActorHndler::new` /
`KcpConnector::new`), so the address is cached. The DNS module's
`query_once()` should use the already-resolved server address directly,
bypassing system DNS for the tunnel connection.

**Approach**:
1. In `run_client()`, resolve `server_host` to an IP before spawning the
   DNS module; pass it into the connector config (or verify the connector
   already caches it — it does, via `to_socket_addrs()` at construction).
2. The DNS module already uses `connector.connect()` which goes through the
   cached connection. The circularity is only on the FIRST query (the QUIC
   handshake). Since the connector was constructed before the DNS module
   starts, the server address is already resolved. The issue is that the
   QUIC connection is lazy — it connects on first stream open, which IS
   the DNS query. So the fix is: eagerly connect the QUIC tunnel before
   starting the DNS interceptor.
3. Add a warm-up step in `run_client()`: after connector construction and
   listener binds, open a dummy tunnel stream (connect to a known address
   like 127.0.0.1:1) to force the QUIC handshake, THEN start the DNS
   interceptor and apply rules.

**Files**:
- [ ] `src/main.rs` — warm-up tunnel connection before DNS interceptor
- [ ] `env/tests/018-tproxy-ws-dns.sh` — un-skip (remove the `exit 0`)

**Acceptance**: `env/verify.sh 018-tproxy-ws-dns` passes: `getent hosts
origin` resolves through the tunnel to origin's real IP.

## F2 — ws test harness: fix process management

**Problem**: The ws client (second magicalane instance for transparent
interception) dies when started from within `verify.sh`'s test subshells
via `podman exec -d`. Works from interactive shells; dies from scripted
ones. Root cause: `podman exec -d` session lifecycle signals.

**Fix (two options, recommend A)**:

**Option A — in-container supervisor script**: Write a tiny script inside
the client container (`/usr/local/bin/ws-start`) that starts the ws client
with `setsid` + full detachment, plus a PID file. The test helpers call
this script instead of `podman exec -d` directly.

**Option B — test from the app container**: Instead of running the ws
client inside the client container, run it in the tproxy-app container
(which already exists for the tproxy profile). The app container has
NET_ADMIN and can run the ws config. Tests then `exec_a curl ...` to
verify transparent interception. This avoids the process management issue
entirely (the ws client IS the container's main process).

**Files**:
- [ ] `env/tests/helpers.sh` — ws_start/ws_stop using option A or B
- [ ] `env/tests/017-tproxy-ws-transparent.sh` — un-skip
- [ ] `env/tests/019-tproxy-ws-udp.sh` — un-skip
- [ ] `env/tests/020-residue-graceful.sh` — un-skip
- [ ] `env/tests/021-residue-kill9.sh` — un-skip

**Acceptance**: `env/verify.sh 017-tproxy-ws-transparent 020-residue-graceful
021-residue-kill9` all pass on quic and kcp.

## F3 — KCP session reuse / connection pooling

**Problem**: Each socks5 CONNECT creates a new KCP conversation + TLS
handshake (~204 ms clean link, ~855 ms cn-us). QUIC reuses one connection
(0.7 ms per additional stream). This is a ~300× connect gap.

**Fix**: Pool KCP sessions. One long-lived KCP conversation with
multiplexed streams (similar to QUIC's bi-streams).

**Approach**:
1. `KcpConnector` maintains a single shared KCP session (one conv ID).
2. Multiplexing: each relay request gets a stream ID; datagrams are framed
   as `[stream_id u32][u16 len][payload]` within the KCP session.
3. Server side: the `DispatchConnector`'s KCP path demultiplexes by
   stream_id, creating a virtual stream per relay.
4. Auth: password is sent once per session (first stream), not per stream.

**Files**:
- [ ] `src/kcp/session.rs` — add stream multiplexing layer
- [ ] `src/kcp/connector.rs` — pool sessions, assign stream IDs
- [ ] `src/kcp/listener.rs` — demux by stream ID
- [ ] `env/bench.sh` — verify connect time drops to ~1 ms

**Acceptance**: `env/bench.sh --transports quic,kcp` shows KCP connect p50
< 5 ms (currently ~204 ms). All 26 verification tests still pass.

## F4 — BBR as the QUIC default

**Problem**: Cubic is the default congestion controller; under 2% loss it
delivers 0.92 MB/s vs BBR's 19.1 MB/s (20× difference). Most real-world
proxy usage involves some loss.

**Fix**: Change the default `congestion` in `QuicTuning` from `"cubic"`
to `"bbr"` when no explicit tuning is set.

**Files**:
- [ ] `src/config.rs` — `QuicTuning::congestion_name()` default → `"bbr"`
- [ ] `env/bench.sh` — verify the default now benchmarks as BBR

**Acceptance**: `env/bench.sh --matrix --transports quic,quic-bbr` shows
both variants producing identical results (since quic now defaults to bbr;
the explicit cubic variant would need a new tag).

## F5 — TUN mode implementation

**Problem**: Phase 3 of the transparent client plan is stubbed. TUN
provides firewall-free transparent interception with native UDP support.

**Approach** (per locked decision D3 — both stacks, abstracted):
1. `src/tun/stack.rs` — trait: IP packet in → established TCP flow
   callbacks out. Two implementations:
   - `src/tun/smoltcp.rs` — Rust-native, small footprint
   - `src/tun/gvisor.rs` — gVisor netstack bindings (heavier, battle-tested)
2. `src/tun/mod.rs` — TUN device creation, route manager (clean-exit
   contract shared with tproxy rules), packet read/write loop
3. Config: `mode = "tun"` activates TUN instead of tproxy rules
4. UDP: native datagram handling (no TCP semantics needed per-flow)
5. Benchmark both stacks; feature-flag the loser

**Files**:
- [ ] `src/tun/mod.rs` — device + route manager
- [ ] `src/tun/stack.rs` — stack abstraction trait
- [ ] `src/tun/smoltcp.rs` — smoltcp implementation
- [ ] `src/tun/gvisor.rs` — gVisor implementation
- [ ] `Cargo.toml` — add `tun`, `smoltcp` deps (behind feature flag)
- [ ] `env/tests/022-tun-transparent.sh` — transparent fetch via TUN
- [ ] `env/bench.sh` — TUN mode throughput comparison

**Acceptance**: `env/verify.sh 022-tun-transparent` passes on quic+kcp;
`env/bench.sh` includes TUN mode; both stacks benchmarked and documented.

## F6 — IPv6

**Problem**: Everything is IPv4-only. Modern networks prefer IPv6; a
silent IPv6 leak bypasses the tunnel entirely.

**Approach** (per locked decision D2 — after all IPv4 features):
1. QUIC endpoint: dual-stack bind (`[::]` with `IPV6_V6ONLY=false`)
2. KCP: same dual-stack UDP socket
3. TPROXY rules: ip6tables mirror chains (MGL6-*)
4. TUN: v6 addresses + routes
5. DNS module: v6 upstream resolution (AAAA records)
6. socks5 proto: already supports IPv6 addresses (`Addr::SocketAddr`)
7. Test env: `podman network create --ipv6` for the test network

**Files**:
- [ ] `src/quic/server/mod.rs` — dual-stack bind
- [ ] `src/quic/client.rs` — dual-stack connect
- [ ] `src/kcp/listener.rs` — dual-stack bind
- [ ] `src/kcp/connector.rs` — dual-stack connect
- [ ] `src/tproxy/rules.rs` — ip6tables chains
- [ ] `src/dns/mod.rs` — v6 upstream
- [ ] `env/up.sh` — IPv6 test network
- [ ] `env/tests/023-v6-transparent.sh` — v6 transparent fetch

**Acceptance**: `env/verify.sh 023-v6-transparent` passes; no IPv6 leak
(v6 traffic either goes through the tunnel or is blocked).

## Ordering

```
F1 (DNS fix)           ────┐
F2 (ws harness)        ────┤── do first: unblocks the 5 skipped tests
                           │
F4 (BBR default)       ────┤── quick win: one-line config change
                           │
F3 (KCP reuse)         ────┤── biggest performance impact
                           │
F5 (TUN)               ────┤── large feature, benefits from F2+F3
                           │
F6 (IPv6)              ────┘── last, per decision D2
```

## Risks & tradeoffs

- **F3 (KCP reuse)**: changes the KCP wire protocol; old clients/servers
  incompatible. Mitigate with a protocol version byte.
- **F5 (TUN)**: smoltcp/gVisor add significant dependencies; behind
  feature flags to keep the default build lean.
- **F6 (IPv6)**: dual-stack QUIC can have subtle MTU/PMTU issues; test
  thoroughly with netem profiles.
