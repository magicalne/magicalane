# Transport Benchmark Notes — QUIC vs KCP, parameters and regimes

> Date: 2026-09-03 · Repo state: `fcaa9e6`
> Data: `env/bench-results/` (esp. `20260903-103238.txt`, `20260903-103755-d30ms-l2pct.txt`, `20260903-11*.txt`)

## How to read this

All numbers come from `magabench` driven through the full stack —
`bench client → socks5 → transport (+TLS) → server → echo origin` — inside the
podman test env (all containers on one Linux bridge, one host). "Clean link"
means no emulation; "lossy" means netem `delay 30ms loss 2%` on the server.

- **connect** — time to obtain a fresh proxied TCP connection through the client.
  Includes KCP session creation + TLS handshake, or QUIC stream open.
- **rtt64/rtt16k** — request/response round trip for 64B / 16KiB framed messages
  on an established connection.
- **dl / dl4par** — single-connection and 4-connection aggregate download (MB/s).
- **ul** — upload (MB/s, single connection).
- **rps** — 64B request rate over 16 concurrent proxied connections.

Raw tables below; findings and reasoning follow.

## Results — clean link (no emulation)

| variant | connect p50 | rtt64 p50 | dl MB/s | dl×4 MB/s | ul MB/s | rps |
|---|---|---|---|---|---|---|
| quic (cubic) | 0.66 ms | 0.36 ms | **159.0** | **163.7** | **182.4** | 2247 |
| quic-bbr | 0.72 ms | 0.30 ms | 137.5 | 162.1 | 120.5 | **5419** |
| quic-newreno | 0.72 ms | **0.20 ms** | 149.8 | 149.1 | 158.4 | 2842 |
| quic-win32m | 0.75 ms | 0.36 ms | 147.8 | 160.5 | 165.1 | 3280 |
| kcp (default) | 204 ms | 0.49 ms | 21.9 | 74.4 | 14.3 | 899 |
| kcp-wnd2048 | 204 ms | 0.41 ms | **43.9** | **119.4** | 40.5 | 933 |
| kcp-nc0 | 214 ms | 0.36 ms | 4.9 | 10.3 | 3.3 | 938 |
| kcp-i40 | 204 ms | 0.41 ms | 5.6 | 16.9 | 4.2 | 919 |
| kcp-mtu1400 | 204 ms | 0.36 ms | 21.2 | 82.0 | 18.7 | 612 |

## Results — 30 ms delay + 2% loss

| variant | connect p50 | rtt64 p50 | dl MB/s | dl×4 MB/s | rps |
|---|---|---|---|---|---|
| quic (cubic) | 91 ms | 60.7 ms | 0.92 | 0.90 | 48 |
| quic-bbr | 91 ms | 60.6 ms | **19.1** | **41.3** | 45 |
| kcp | 385 ms | 60.6 ms | 3.6 | 8.2 | 40 |
| kcp-wnd2048 | 414 ms | 60.7 ms | 5.5 | 9.5 | **105** |

TLS overhead on KCP (clean link, separate run): 23.2 → 19.7 MB/s dl (~15%),
71.7 → 55.4 MB/s dl×4 (~23%), rtt64 0.38 → 0.44 ms (~15%), connect ~204→202 ms
(handshake RTTs are already amortized inside the session setup).

## Findings

### F1. BBR vs cubic is the single biggest lever on lossy links
With 2% loss, cubic collapses to 0.92 MB/s while BBR sustains 19.1 (single) /
41.3 MB/s (4 streams) — **20–45×**. Why: cubic's window is governed by *packet
loss* (it interprets loss as congestion and multiplicatively decreases); at 2%
loss on a 30 ms path it never grows a window big enough to fill the pipe.
BBR instead *models* bandwidth and min-RTT from delivery-rate samples and paces
to that estimate, so random loss doesn't force window collapse. On the clean
link the gap disappears (138 vs 159 MB/s) — BBR's pacing is slightly
conservative, so cubic keeps the raw-throughput crown where loss ≈ 0.

**Action: default KCP and QUIC deployments on real (internet) links should
prefer `congestion = "bbr"`.**

### F2. KCP throughput is window-bound — wnd2048 doubles it
KCP default (sndwnd/rcvwnd 512 pkts × ~1.2 KB MTU ≈ 600 KB in flight) is the
bottleneck: raising to 2048 takes dl 21.9 → 43.9 MB/s and dl×4 74 → 119 MB/s.
Parallel connections already recover much of it (74 MB/s at default) because
each session brings its own window — evidence that *window*, not CPU or relay
logic, is the limiter. mtu1400 helps only marginally (74 → 82 dl×4); the MTU
headroom on the bridge is small.

### F3. KCP's `nc` and `interval` parameters are not optional
- `nc = false` (enable KCP's internal congestion control): 21.9 → 4.9 MB/s
  (**4.5× slower**). KCP's own CC is a crude slow-start/loss pair; for a proxy
  carrying bulk streams it strangles throughput on fast paths.
- `interval = 40` (classic mode) instead of 10: 21.9 → 5.6 MB/s (**4× slower**).
  The internal clock gates how fast queued segments are serviced.
- The turbo preset `nodelay=1, interval=10, resend=2, nc=1` is the right
  default; our earlier flush() fix (write path flushes immediately instead of
  waiting for the tick) is what brought rtt64 from ~20 ms to ~0.4 ms.

### F4. KCP connect cost: session reuse is the top optimization target
Every socks request creates a *new* KCP conversation + TLS handshake: ~204 ms
p50 on the clean link (and 385 ms–1.4 s p95 under loss). QUIC amortizes: one
connection, password handshake once, then each relay is just `open_bi()` —
0.66–0.75 ms. That is a **~300× setup gap**, and it dominates bursty web-like
workloads (see rps). Parallel throughput partially hides it (F2), but
short-lived connections pay it in full.

**Action: implement session reuse/multiplexing for KCP** (kcptun-style stream
mux over one conv, or a pooled-session connector). This is now the
clearly-ranked #1 KCP work item.

### F5. TLS on KCP costs ~15–25% throughput, ~0 for connect
rustls record encryption/decryption on the relay path: dl 23.2 → 19.7 MB/s,
dl×4 71.7 → 55.4, rtt64 +0.06 ms. Cheap relative to the security gained —
keep `tls = true` by default. (QUIC's TLS is in-scope for its numbers above.)

### F6. Lossy-link KCP vs QUIC-BBR
KCP (nc=1, no real CC) survives loss better than cubic by brute retransmission
(3.6 vs 0.92 MB/s) but is no match for BBR (19.1). KCP-wnd2048 also wins rps
under loss (105 vs 45) because its sessions are independent and its fast
retransmit (`resend=2`) recovers small exchanges quickly, while BBR's pacing
adds serialization to every small request. So: **bulk on loss → BBR; small
bursty requests on loss → KCP-wnd2048.**

### F7. Instrument notes / caveats
- `rtt16384` reads ~42–44 ms p50 on the clean link for *every* variant
  (including QUIC) — a bench-side artifact of the 16 KiB frame path (suspected
  delayed-ACK interaction in the relay chain despite TCP_NODELAY on both bench
  ends). Treat rtt16k as an upper bound; rtt64/rtt1024 are clean (sub-ms).
- Everything is userland-relayed (socks5 + TLS + proxy copies in both
  endpoints) — absolute numbers understate a kernel datapath; comparisons
  between variants are the meaningful part.
- Single host, container bridges, ~0.3 ms base RTT: a best-case LAN. The netem
  runs simulate WAN characteristics, not real internet jitter/bufferbloat.
- connect samples are small (n=20); conc rps uses 16×20 requests.

## Recommended presets

| scenario | choice |
|---|---|
| stable/fast link, bulk | `quic`, default (cubic) |
| real internet / any loss | `quic` + `[tuning.quic] congestion = "bbr"` |
| lossy link, QUIC blocked/undesired | `kcp` + `[tuning.kcp] sndwnd = 2048, rcvwnd = 2048` (keep nc = true, interval = 10) |
| latency-critical small exchanges | `quic` (0.2–0.4 ms rtt) or kcp after session reuse lands |

## Follow-up work (ranked by measured impact)

1. KCP session reuse / stream multiplexing (F4: ~300× connect gap).
2. BBR as default on the QUIC path (F1: 20×+ under loss).
3. Re-examine the 16 KiB RTT artifact (F7) if medium-message latency matters.
