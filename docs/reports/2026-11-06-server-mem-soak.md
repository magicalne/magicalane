# Server memory soak: findings & measurements (issue #29)

Date: 2026-11-06 · base: master `497c392` · host: 36-core dev box, Linux, glibc.

Harness: `env/soak.sh` (real server + client binaries, host loopback) with
`magabench churn` (socks5-driven churn; RSS/fd/threads sampled from the
server's `/proc`). See `docs/plans/29-server-mem-growth.md` for the plan.

## Root cause 1 — UDP/DNS magic-flow teardown retention (the wedge)

Profile: QUIC transport, socks CONNECT to `magicalane-udp:1`, valid
`[dst][datagram]` framing, immediate close (the gateway's
DNS-tunnel/UDP-flow shape), 2000 flows:

| metric            | pre-fix              | post-churn + 60s | post-fix (same load) |
|-------------------|----------------------|------------------|----------------------|
| server RSS        | 24 MB → 140 MB       | stays elevated   | ~10 MB, flat; drops to 9.5 MB while idle |
| server fd count   | 10 → 1810 (+1/flow)  | → 10 at t+60s    | 10 immediately       |

Mechanism: `UdpFramedStream::poll_read` parks a spawned recv task
(`Arc<UdpSocket>` + 64 KiB buffer, `FLOW_IDLE` = 60s timeout); on client
departure `poll_shutdown` was a no-op, so the relay completed only after
the recv timed out. Sustained flow churn pinned fds ≈ rate × 60s →
fd exhaustion (`accept()` EMFILE, every transport dead, ICMP alive) —
the production incident signature. Single-arena control grows
identically ⇒ real retention, not allocator behavior. `DnsRelayStream`
had the same pattern bounded at 2s × upstreams.

Fix: abort pending tasks in `poll_shutdown`, EOF in `poll_read` after
buffered data drains, abort in `Drop` (belt and braces).
`src/udp/mod.rs`, `src/dns/mod.rs`.

## Root cause 2 — glibc arena ratchet (slow growth; no true leak)

Plain TCP-echo relay churn (no magic hosts), default 36 arenas vs
`MALLOC_ARENA_MAX=1`:

| mode | transport | slope (36 arenas) | single arena |
|---|---|---|---|
| stream churn | quic | 15.7 MB/h @ 326k streams/h | ~0, plateaus (9124 kB flat) |
| conn churn, 2s settle | quic | ~191 MB/h (quinn idle-timeout window; 40s-settle flattens) | ramp to bounded window, then flat |
| stream churn | kcp | 76.8 MB/h @ 18k sessions/h (incl. idle window); ~350 B/session after | exactly 0.000 MB/h (RSS pinned, 1250 sessions) |
| stream churn | tcp+tls | 28.7 MB/h @ 180k conns/h; ~260 B/conn | staircase → flat |

fd/thread counts flat everywhere ⇒ no handle leaks. A 2-CPU-pinned
server (`taskset`, like the 2-vCPU production box) is **flat even
without trim** on plain-relay churn — small instances died of cause 1;
many-core instances ratchet without trim.

Fix: periodic `malloc_trim(0)` for `Kind::Server` (`src/mem.rs`,
`MAGICALANE_MEM_TRIM_SECS`, default 60) + optional arena cap
(`MAGICALANE_MALLOC_ARENA_MAX`). Measured effect (kcp, prod-like
serial churn): 12.1 → 1.6 MB/h; idle RSS returns pages (9.7 → 9.5 MB).
Residual mid-arena stranding on 36-core stress profiles remains
(~134 B/conn with trim) and is bounded; `MALLOC_ARENA_MAX=2` takes the
same stress profile from 38.6 → 10.6 MB/h.

## Regression

`env/tests/031-reg-server-mem-churn.sh` (suite `regression`): drives
2000 udp-magic flows, asserts fd ≤ 20 (pre-fix: 1810) and RSS growth
≤ 8 MB (pre-fix: +116 MB). Verified failing on a pre-fix build, passing
post-fix (~31 s). Also fixed `env/verify.sh`: `transports: any` tests
were silently skipped in plain phases.

## Multi-hour validation soak

Post-fix, **defaults** (trim 60s — the shipping configuration), host
loopback, 36-core host, concurrency 8. Round 1 = one continuous
~70-minute cycle (100 batches × 150 per scenario; rates ≈ 100× the
production churn that triggered the incidents):

| scenario (round 1) | slope | volume | fd count | RSS |
|---|---|---|---|---|
| quic stream churn | **0.685 MB/h** | 15,000 streams | 10 → 10 | 9 → 9 MB |
| kcp session churn | **3.73 MB/h** | 15,000 sessions | 10 → 10 | 10 → 12 MB |
| tcp+tls conn churn | **2.97 MB/h** | 15,000 conns | 10 → 10 | 9 → 10 MB |
| quic udp-magic flow churn | **3.27 MB/h** | 15,000 flows | 10 → 10 | 10 → 12 MB |

For contrast, pre-fix udp-magic at this volume retains ~875 MB
(58 kB × 15,000) and pins 15,000 fds (fd-limit death). Every scenario
lands under the <5 MB/h acceptance threshold at ~100× production
churn rates; a second round (another ~70 min) reproduced the same
plateaus (see `env/soak-results/`).

## Bench sanity (no hot-path regression)

`env/bench.sh --transports quic` (while a soak ran on the same host):
connect p50 **0.723 ms** (baseline ~0.7), rtt64 p50 0.379 ms,
dl 135 / ul 158 MB/s, 3.1k conc-rps — within the documented
baseline ranges for a contended host.
