# Server-side memory growth: reproduce-first harness, root-cause, fix

> Path: `docs/plans/29-server-mem-growth.md` — issue: #29

## Summary

The remote server process grows RSS (~12 MB/h measured pre-v0.1.3 on the QUIC unit; still wedging on v0.1.4) until a 2 vCPU / 439 MB instance swap-thrashes (disk read IOPS pinned) and every transport stops processing flows. This plan: build a soak harness that **quantifies the growth slope on master before any fix**, isolate the transport/path with evidence, land the fix with a regression test that fails pre-fix, and document a systemd memory guard.

## Context

Issue #29. Related: #23 (client-side UDP self-relay leak, fixed in v0.1.3). Incidents coincide with high stream churn (an endpoint reconnecting ~300 streams/h for 48 h+), so teardown-retention suspects grow fastest under churn. Production server runs quic + kcp + tcp listeners (separate instances). Constraint: **no dependency bumps** (quinn 0.11 / rustls pinned); scope is server-side only.

Server-side teardown path today (all three transports share it at the bottom):

- quic: `src/quic/server/mod.rs` spawns per-connection task → `conn.rs` `accept()` loop spawns per-stream `Stream` relay tasks (`src/quic/server/stream.rs`) → generic `Proxy` copy loop (`src/proxy.rs`).
- kcp: `src/kcp/listener.rs` dispatch by conv id → per-session `drive_session` + per-session `handle_session` (TLS + auth) → same generic `Stream` relay.
- tcp: `src/tcp/listener.rs` per-conn task (TLS + auth, 10 s handshake bound) → same generic `Stream` relay.
- `LocalConnector`/`DispatchConnector` (`src/connector.rs`, `src/dispatch.rs`) → tokio `TcpStream`; DNS answers cached in `Resolver` (capped 4096, LRU-evict — bounded).
- Each relay allocates 2 × `bandwidth` (64 KiB in prod config) of `BytesMut` upfront (`Proxy::new`).

## Goals

- Quantified RSS slope (MB/h) per transport under churn on current master — **before** any fix.
- Root cause identified with instrumented evidence (counters / FD&thread deltas / bisected load profile), documented in this plan.
- Fix + regression test that fails pre-fix (canonical: `env/tests/031-reg-server-mem-churn.sh`; plus a manual cargo soak).
- Post-fix slope flat within threshold (<5 MB/h on a multi-hour local soak; accelerated CI-window threshold for the env test).
- systemd `MemoryHigh=`/`MemoryMax=` + `Restart=always` operational guard documented in `docs/deploy-gateway.md`.

## Non-goals

- Client-side/gateway behavior (#23 done), network-path incidents, throughput tuning.
- Dependency version bumps. If the root cause turns out to be inside pinned quinn/rustls with no application-side mitigation, stop and report back.

## Approach

### 1. Harness (repro) — no product behavior changes

**Driver: new `magabench churn` subcommand** (`src/bin/magabench.rs`). It already has the framed-echo protocol and `socks_connect`; add:

```
magabench churn --socks 127.0.0.1:1080 --target 127.0.0.1:9807 \
    --batches 20 --batch-size 500 --reconnect-every 1000 --ping-bytes 64 \
    --sample-pid <server-pid> --pairs
```

- Each iteration = fresh socks5 connection → 1 ping → drop. This is exactly the production churn shape: for quic the client reuses its single QUIC connection (pure **stream churn**); for tcp each iteration is a full **connection churn**; kcp exercises session lifecycle.
- `--reconnect-every K`: kill & re-establish the client-side tunnel (implemented as K iterations then aborting a dedicated driver process, see soak script) so quic **connection churn** can be isolated from stream churn.
- `--sample-pid`: after each batch, read `/proc/<pid>/status` (VmRSS, Threads) and `/proc/<pid>/fd` count; emit `rss_kb=<n> fd=<n> thr=<n>` per batch (with `--pairs`) for slope computation.

**Soak script: `env/soak.sh`** (operator tool, host loopback — no podman, matching the issue's "plain client connectors against a local server are enough"). Modes: `--mode stream|conn|idle`, per-transport (quic/kcp/tcp), `--abandon`/`--unreachable` error-path fractions, `MGL_SOAK_MAGIC=udp|dns` + `MGL_SOAK_TARGET` for the magic-relay paths (the profile that found the real leak), `MGL_SOAK_PORT_BASE` for parallel runs, `MGL_SOAK_SERVER_CPUS` (taskset) to emulate small instances, `MGL_SOAK_KEEP` to leave processes up for inspection, `--max-mb-h` threshold gate.

- For each transport in `quic kcp tcp`: generate configs (server port + tls, client with `ca_path` to `env/certs/` PKI; reuse `env/certs.sh`, SAN `localhost`), start `magabench echo` origin, the `magicalane server` child, the `magicalane client` child.
- Run churn batches, sampling server child RSS per batch; optional `--reconnect-every` restarts the *client* process between batches to force server-side QUIC teardown.
- Print per-transport slope table (least-squares MB/h from batch RSS) + FD/thread deltas; exit non-zero if `--max-mb-h` given and exceeded.

**Regression gate: `env/tests/031-reg-server-mem-churn.sh`** (suite `regression`, runs in `env/verify.sh full`): accelerated churn against the real server binary with a pass/fail threshold (~30 s). Deterministic fd-count pin + bounded-RSS pin; verified failing on a pre-fix build. A standalone cargo-level soak was dropped in favor of this — the measured process is always the real server binary either way, and the env harness also covers kcp/tcp/multi-hour operator runs.

### 2. Measure on master (repro gate)

Matrix (each ~10–20 min wall, accelerated churn ≫ production 300/h):

| mode | quic | kcp | tcp |
|---|---|---|---|
| idle (no load, baseline allocator drift) | ✓ | ✓ | ✓ |
| stream churn (persistent client) | ✓ | ✓ | ✓ |
| connection churn (client restarted per batch) | ✓ | ✓ | ✓ |

Record slopes in `docs/reports/2026-11-06-server-mem-soak.md`. **Gate: at least one mode shows a reproducible positive slope (≫ idle baseline) before any fix is attempted.** If nothing grows in the accelerated window, escalate batch counts / add realistic tails (abandoned mid-handshake streams, wrong-password, unreachable-destination relays — error-path teardown is a prime suspect).

### 3. Root-cause with evidence

1. Per-transport slope isolation (matrix above) narrows the layer: quinn-only → QUIC accept/teardown; all transports → shared relay path (`Stream`/`Proxy`) or allocator.
2. FD/thread deltas: FD growth = socket/handle retention (count open sockets by transport in `/proc/<pid>/fd`); threads growth = task leaks.
3. Server-side instrumented counters (landed as a small permanent debug facility, env-gated `MAGICALANE_DEBUG_COUNTERS=1` → log line every 30 s): conns accepted/closed, relay tasks spawned/finished (quic streams, kcp sessions, tcp conns each), live-task delta. A non-zero steady-state delta pinpoints the retained object class.
4. If counters net to zero but RSS climbs: allocator-level — run the soak under `valgrind --tool=massif` (definitive for real leaks) or `MALLOC_ARENA_MAX=1` A/B to characterize arena creep.

Update this plan's **Findings** section with the evidence and the identified root cause before writing the fix.

### 4. Fix

Chosen by evidence, not guess — candidate classes (verification will pick):

- Retained server-side tasks/state on error teardown paths (e.g. `Stream`/`Connection` holding resources after relay errors) → explicit drop/close.
- quinn endpoint/connection retention on the accept path (server keeps something alive per dead connection) → break the retain cycle at teardown.
- KCP `routes` map / session retention.
- glibc arena creep from churn spikes (real free, RSS not returned) → periodic `malloc_trim` after batch teardowns, or bounded task-spawn concurrency. (Only if massif shows no true leak.)

### 5. Regression + verification

- `env/tests/031-reg-server-mem-churn.sh` — `# suites: regression`, `# transports: any`; runs the accelerated churn (per transport, host loopback, no podman net needed since it spawns its own processes; ~2–4 min), asserts RSS growth ≤ threshold calibrated to ~¼ of the measured pre-fix slope, plus FD count stable. Must fail on pre-fix master (verified during development).
- Full protocol: `cargo test`, `cargo clippy`, `env/verify.sh fast`, the new regression test explicitly, and `env/verify.sh full` (transport-adjacent fix). If the fix touches the relay hot path, `env/bench.sh` before/after.
- Post-fix multi-hour soak locally; record slope in the report doc.

### 6. Deploy docs

Extend `docs/deploy-gateway.md` (server unit section): `MemoryHigh=` (soft throttle), `MemoryMax=` (hard kill), `Restart=always` + `RestartSec` so a worst-case wedge self-heals in seconds instead of taking the instance down for days.

## Files touched

- [x] `docs/plans/29-server-mem-growth.md` (this)
- [x] `src/bin/magabench.rs` — `churn` subcommand (stream/conn/error-path/udp-magic/dns-magic modes) + `/proc` sampler
- [x] `env/soak.sh` — operator soak harness (new)
- [x] `env/tests/031-reg-server-mem-churn.sh` — regression test (new; fails pre-fix, verified)
- [x] `src/quic/server/mod.rs` — env-gated connection counters (`MAGICALANE_DEBUG_COUNTERS=1`)
- [x] `src/udp/mod.rs` + `src/dns/mod.rs` — shutdown-abort teardown fix (cause 1)
- [x] `src/mem.rs` + `src/main.rs` + `src/lib.rs` — periodic `malloc_trim` + arena-cap knob (cause 2)
- [x] `env/verify.sh` — fix: `transports: any` tests were silently skipped in plain phases
- [x] `docs/deploy-gateway.md` — systemd memory guard
- [x] `docs/reports/2026-11-06-server-mem-soak.md` — measurements & findings

## Risks & tradeoffs

- **Leak too slow for CI windows**: accelerate churn (thousands of streams/min) + error-path tails; if still invisible, the regression test asserts the *harness* stays (guards the class of bug) and the soak threshold applies to the operator run — documented explicitly.
- **RSS noise/flakiness**: assert on least-squares slope over ≥8 batches with generous threshold (¼ of pre-fix slope), not single samples; per-transport isolation keeps windows short.
- **In-process measurement contamination**: avoided entirely — the measured process is always the real server *binary* as a child, never the test process.
- **Allocator creep misdiagnosed as leak**: massif/malloc_trim A/B (step 3.4) separates "definitely lost" from "retained by arenas"; only the former is treated as the bug, the latter gets trim/bounding.

## Acceptance criteria

- [ ] Soak harness demonstrates quantified positive RSS slope on master (pre-fix), recorded in `docs/reports/`.
- [ ] Root cause documented in this plan with counter/FD/massif evidence.
- [ ] Fix lands; regression test `env/tests/031-reg-server-mem-churn.sh` fails pre-fix, passes post-fix.
- [ ] Post-fix multi-hour soak slope < 5 MB/h (documented).
- [ ] `cargo test`, `cargo clippy`, `env/verify.sh fast` clean; regression suite green; `env/verify.sh full` if transport-adjacent.
- [ ] `docs/deploy-gateway.md` gains `MemoryHigh=`/`MemoryMax=` + `Restart=always` server-unit guidance.

## Open questions

None blocking — scope fixed by the issue (server-side, no dep bumps, reproduce-first). Assumptions recorded: multi-hour soak run locally by operator; CI-length regression uses the accelerated threshold.

## Findings (root cause — measured 2026-11-06, master 497c392)

**Two distinct causes, both reproduced with quantified slopes before any fix.**

### Cause 1 (primary — the wedge): UDP/DNS magic flows pinned fds + memory for 60s after the client left

Driving the server-side UDP magic relay (`magicalane-udp` via socks CONNECT, framed dst+datagram) on QUIC — the gateway's DNS-tunneling/UDP-flow profile — showed:

| metric | pre-fix (2000 flows) | after churn (60s) |
|---|---|---|
| RSS | 24 MB → 140 MB (**+58 kB/flow, linear**) | stays elevated |
| fd count | 10 → 1810 (**+1/flow, linear**) | drops to 10 exactly at t+60s |

Single-arena control (`MALLOC_ARENA_MAX=1`) grows identically → real retained state, not allocator noise. Mechanism: `UdpFramedStream::poll_read` spawns a recv task holding the flow's `Arc<UdpSocket>` + a 64 KiB buffer with a `FLOW_IDLE` (60s) timeout; when the client departs, the relay's Proxy half shuts the stream down but `poll_shutdown` was a no-op — the parked recv kept the socket until timeout. Under sustained flow churn (every DNS query through the gateway = a flow): pinned fds ≈ rate × 60s → fd exhaustion (`accept()` EMFILE) → **every transport stops accepting while the kernel keeps answering ICMP** — the incident signature. Sibling pattern in `DnsRelayStream` (bounded by 2s × upstreams, fixed for hygiene).

### Cause 2 (secondary — slow growth): glibc arena ratchet, no true leak in the plain relay paths

Accelerated churn on the plain TCP-echo relay paths (no magic hosts), 36-core host:

| mode | transport | slope | per-object |
|---|---|---|---|
| stream churn | quic | 15.7 MB/h @ 326k streams/h | ~48 B/stream (plateaus) |
| conn churn (2s settle) | quic | ~191 MB/h | dead-conn retention until quinn idle timeout, then freed (40s-settle run flattens) |
| stream churn | kcp | 76.8 MB/h @ 18k sess/h | includes idle-window sessions; ~350 B/session permanent ratchet |
| stream churn | tcp+tls | 28.7 MB/h @ 180k conns/h | ~260 B/conn ratchet |

Discriminators: FD/thread counts flat in every plain-relay run; **`MALLOC_ARENA_MAX=1` collapses every plain-path slope to ~0/plateau** (kcp: exactly 0.000 MB/h, RSS pinned for 1250 sessions). Tokio spawns one worker per core; freed chunks strand across arenas and below heap tops; glibc never returns them. On a 2-CPU-pinned server (taskset) plain-path churn is flat even without trim — the ratchet matters on many-core boxes; small instances primarily died of cause 1.

### Fix (server-side only, no dep bumps; `libc` already linked)

1. **Teardown**: `poll_shutdown` on `UdpFramedStream`/`DnsRelayStream` aborts the spawned recv/resolve task and marks the stream shut down; `poll_read` reports EOF after buffered bytes drain; `Drop` aborts as belt-and-braces. Result: fds return to baseline immediately after churn (fd=10 measured at first post-churn sample, was 426+).
2. **Hygiene**: periodic `malloc_trim(0)` timer for `Kind::Server` (`src/mem.rs`; `MAGICALANE_MEM_TRIM_SECS`, default 60, 0=off; optional `MAGICALANE_MALLOC_ARENA_MAX` mallopt cap). KCP prod-like serial churn slope 12.1 → 1.6 MB/h; idle RSS visibly returns pages (9.7 → 9.5 MB).
3. **Operational backstop** (docs/deploy-gateway.md): systemd `MemoryHigh=`/`MemoryMax=` + `Restart=always`, `MALLOC_ARENA_MAX=2` env.

Regression: `env/tests/031-reg-server-mem-churn.sh` pins cause 1 deterministically (fd count) + bounds RSS on the same scenario (pre-fix: fd 1810 / +116 MB — verified failing on a pre-fix build; post-fix: fd ≤ 20 / ≤ 8 MB growth). Trim effectiveness is documented A/B in the report; knob behavior unit-tested in `src/mem.rs`.

<!-- FINDINGS-APPENDED-BY-IMPLEMENTATION -->
