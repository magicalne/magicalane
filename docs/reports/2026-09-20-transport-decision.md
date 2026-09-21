# Transport Decision — QUIC vs KCP vs TCP for the Gateway

> Date: 2026-09-20 · Issue #18 · Branch `18-transport-decision`
> Data: `env/bench-results/20260920-*` (clean, cn-us fifo/cake, eu-us, mobile — all with `--under-load`)
> Preconditions: #17 (KCP fd leaks) and this branch's fixes in — pooled-zombie fallthrough, TCP handshake-only timeout. Every number below is post-fix; earlier published numbers for KCP/TCP were measuring broken machinery.

## The question

One transport (or primary+fallback pair) for the production gateway (`magicalane-gw` → aliyun KR, ~36 ms measured RTT, clean direct path). Criterion: **usability as a proxy gateway** — throughput AND foreground latency under load (`loaded_rtt64_p95`), plus "never stalls". Protocol-agnostic: winner ships, losers leave the config.

## Results

### Clean link (lab bridge, no shaping)

| variant | connect p50 | rtt64 p50 | dl MB/s | dl×4 MB/s | ul MB/s | rps |
|---|---|---|---|---|---|---|
| quic (cubic) | 0.72 ms | 0.36 | 138.1 | 140.4 | **195.4** | **5253** |
| quic-bbr | 0.62 ms | 0.21 | 118.1 | 147.2 | 106.4 | 5568 |
| kcp-wnd2048 | 1.5 ms | 0.35 | 43.9 | 157.5 | 39.3 | 1066 |
| tcp | 1.55 ms | 0.31 | **372.9** | **698.9** | 466.6 | 1421 |

### cn-us — 160 ms ± 8, 0.3% loss, 5/20 Mbit

| variant | fifo: dl / loaded p95 | cake: dl / loaded p95 |
|---|---|---|
| quic | 0.15 / 280 ms | 0.105 / 314 ms |
| quic-bbr | **1.33 / 607 ms** | **STALL** (>25 min, hard-killed) |
| kcp-wnd2048 | 1.23 / 1339 ms | **STALL** (also documented Sep-03) |
| tcp | 0.43 / **248 ms** | 0.33 / **220 ms** |

### eu-us — 90 ms ± 4, 0.1% loss, 20/100 Mbit (fifo)

| variant | dl MB/s | ul MB/s | loaded p95 |
|---|---|---|---|
| quic | 0.27 | 0.27 | 162 ms |
| quic-bbr | 4.8 | **1.68** | **141 ms** |
| kcp-wnd2048 | 4.0 | 1.38 | 614 ms |
| tcp | **10.2** (81% of path) | 0.81 | **141 ms** |

### mobile — 60 ms ± 15 jitter, 2% loss, 2/10 Mbit (fifo)

| variant | dl MB/s | loaded p95 |
|---|---|---|
| quic | 0.21 | 128 ms |
| quic-bbr | **0.72** | **1420 ms** (bufferbloat) |
| tcp | 0.25 (0.92 ×4par) | **124 ms** |
| kcp-wnd2048 | **STALL** | — |

## Reading

- **tcp** never stalls, and posts the best or tied-best loaded latency in *every* shaped profile (248/220/141/124 ms) — kernel cubic yields politely. On good paths it is a throughput monster (373/699 MB/s clean; 10.2 MB/s = 81% of path on eu-us down). Weaknesses: per-connection TLS handshake (connect 250–650 ms on WAN, 1.4k rps vs quic's 5k) — no session reuse/mux yet.
- **quic-bbr** is the throughput king on fifo paths (its cn-us 1.33 MB/s ≈ 5× the 20 Mbit… of everyone else) but has two failure modes: a **hard stall against cake AQM** (reproduced; >25 min zero progress on a 4 MB upload; Sep-03 ran the same profile green — kernel-dependent, needs its own investigation) and **severe bloat** on shallow queues (1.4 s loaded p95 on mobile).
- **quic-cubic** always finishes, never wins.
- **kcp(-wnd2048)** is disqualified for WAN gateway use: no congestion controller → worst bufferbloat when it works (1.3 s), and it deadlocks outright on AQM (cake) and high loss (mobile 2%) — three independent stall observations.

## Decision

1. **Primary: `quic-bbr`** (unchanged). The production path is a clean direct link where bbr's fifo dominance applies; the clean path RTT (~36 ms) sits between the eu-us and mobile profiles where bbr is 4–6× the alternative.
2. **Fallback: `tcp` (replaces kcp)**. The fallback exists for "UDP is broken/blocked" moments — where KCP (also UDP) could never help; TCP is the only coherent fallback, and it is the most robust transport measured (no stall anywhere, best loaded latency everywhere). The tcp listener is deployed on the server (:4435) with the fixed binary on both ends. **Blocked on the aliyun security group: it currently admits no inbound TCP at all** (verified: 80/443/8080/8443/44352/44357 all filtered) — opening one TCP port (4435) is the only manual step; the client flip is then a one-line config change. Until then **kcp stays as the interim fallback on the fixed binary** (fd-leak + zombie fixes in): verified working, engages in ~110 s (probe-interval bound).
3. **kcp is retired once tcp takes over.** Its session machinery also carried both fd-leak bugs (#16) and the pooled-zombie failure (#18); retiring it deletes the 60 s probe churn across transports too.

## Follow-ups

- `quic-bbr × cake` hard stall: isolate (quinn bbr vs kernel vs netem layering); until understood, bbr on AQM-managed uplinks is a known risk. `quic-cubic` is the safe degradation if it reproduces in production.
- TCP transport session reuse (prewarm/pool or mux) to close the connect-time and rps gap — the same K-ladder applied to TCP.
- KCP stays in the tree (LAN/lab use where its simplicity wins); only the gateway config drops it.

## Production verification (2026-09-20)

- Server: quic (4433/udp, bbr) + tcp (4435/tcp) + kcp (4434/udp, interim) on the branch binary; kcp was disabled then re-enabled as interim.
- Gateway: branch binary; forced-failover test (quic stopped on server): traffic continues via kcp after **~110 s** (probe interval 60 s + detection). Normal path 204 in ~0.3 s before and after.
- tcp fallback armed but unreachable: aliyun SG admits no inbound TCP (probed 80/443/8080/8443/44352/44357 — all blocked; 22 only from whitelisted IPs). Awaiting console change.

Raw tables: `env/bench-results/20260920-{105238,113507,164354,172640,184556,191819,192658,194511}*.txt`.
