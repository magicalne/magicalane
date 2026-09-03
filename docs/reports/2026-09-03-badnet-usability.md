# Bad-Network Simulation Notes — cross-country usability

> Date: 2026-09-03 · Repo state: post `9383b49` (badnet work)
> Data: `env/bench-results/*cn-us*` · Tooling: `env/badnet.sh`, `magabench --under-load`

## The scenario

Server in another country, client on a limited home uplink. The simulated path
(`cn-us` profile): **RTT 160 ms ± 8 jitter, 0.3% loss each direction, asymmetric
rates 5 Mbit/s up / 20 Mbit/s down**, shaped in *both* directions with a
destination-IP filter so only client↔server traffic is degraded (server↔origin
stays clean, like a real deployment where the origin sits near the server).

Two bottleneck-queue modes:
- `fifo` — netem + tbf with a deep (~400 ms) buffer = **bufferbloat**
- `cake` — netem + cake AQM = **well-managed link**

"Usable" is measured two ways *together* — throughput under load
(`load_dl_mbps`, saturating background download) and foreground latency while
loaded (`loaded_rtt64_p95_ms`). Latency without throughput, or throughput with
1-second latencies, both mean "not usable".

## Results — cn-us, bloated bottleneck (fifo)

| variant | idle rtt64 | dl MB/s | loaded rtt64 p95 | load dl MB/s |
|---|---|---|---|---|
| quic (cubic) | 161 ms | 0.15 | 316 ms | 0.11 |
| quic-bbr | 162 ms | **1.31** | 571 ms | **1.18** |
| kcp | 159 ms | 0.74 | 732 ms | 0.67 |
| kcp-wnd2048 | 159 ms | 1.24 | **1050 ms** | 0.98 |

(connect: quic ~161 ms — one RTT-ish; kcp ~855 ms — fresh session+TLS per
request, even worse on WAN than on LAN.)

## Results — cn-us, managed bottleneck (cake AQM)

| variant | idle rtt64 | dl MB/s | loaded rtt64 p95 | load dl MB/s |
|---|---|---|---|---|
| quic (cubic) | 159 ms | 0.11 | 274 ms | 0.10 |
| quic-bbr | 157 ms | 1.04 | 656 ms | 1.04 |
| kcp | 158 ms | 0.67 | **348 ms** | 0.63 |
| kcp-wnd2048 | — | *reset (dead-link)* | — | — |
| kcp-w2048-nc0 | 319 ms | 0.03 | 516 ms | 0.04 |

## Findings

### F1. Loss-based CC is mathematically unusable at intercontinental RTT
Cubic's 0.15 MB/s is not a fluke — it is the Mathis limit:
`rate ≈ MSS·C/(RTT·√p) ≈ 1200B·1.22/(0.16s·√0.006) ≈ 1.2 Mbit/s`. At 160 ms and
~0.6% path loss, *any* loss-based controller is capped there. Its "low" loaded
latency (316 ms) is just underutilization, not good queue management. BBR
delivers ~10× (1.18–1.31 MB/s ≈ 10 Mbit/s) because it estimates bandwidth from
delivery-rate samples instead of treating loss as congestion.

### F2. Loaded latency must be read next to loaded throughput
The usability plane is 2-D. On it: cubic = (0.1 MB/s, 316 ms) — unusable
bandwidth; bbr = (1.2 MB/s, 571 ms) — usable for browsing/bulk, marginal for
tight interactive; kcp-wnd2048 = (0.98 MB/s, 1050 ms) — bulk okay, interactive
dead while loading; bbr+cake = (1.04 MB/s, 656 ms). No variant gets
"everything": with a 20 Mbit/s shared bottleneck there is a real frontier.

### F3. KCP without congestion control floods the bottleneck — and fights AQM
`nc = true` (KCP's no-CC mode, right for clean LANs) is the *worst* choice
cross-country: loaded p95 1050 ms (fills the entire 400 ms tbf buffer plus
loss-recovery churn). Under cake it gets worse, not better: cake drops to keep
the queue short, KCP-nc1 with a 2048-packet window interprets drops as loss,
retransmits harder, and eventually trips its dead-link counter — **uploads
reset outright**. KCP's own CC (`nc = false`) is too crude for 160 ms paths
(0.03 MB/s, and even *idle* RTT degrades to 319 ms). Conclusion: **KCP needs a
real congestion controller (cubic/BBR-style, not its built-in one) before it
is deployable on intercontinental links** — top follow-up alongside session
reuse (its 855 ms connect on this profile).

### F4. AQM on the bottleneck halves KCP's bloat; BBR mostly doesn't care
cake cut kcp default's loaded p95 from 732 → 348 ms. BBR was roughly unchanged
(571 → 656 ms, within run variance): its ProbeBW gain cycles periodically
overshoot the bottleneck by ~25%, and whatever queue exists absorbs it —
BBR bounds *throughput loss*, not queue delay. Practical read: if you control
the router, AQM + anything beats deep FIFO; if you don't (the usual case for a
cross-country VPS path), your endpoint lever is the congestion controller.

### F5. What actually "guarantees" usability today
Ranked, with current code:
1. **`quic` + `congestion = "bbr"`** — the only configuration that both fills
   the pipe (10× cubic) and keeps loaded latency sub-second on a bloated path.
2. **Client-side self-shaping** (not yet built): cap your own egress slightly
   below the uplink with an AQM (`cake bandwidth 4.5mbit` on the client) so the
   queue forms under your control at the edge — the classic bufferbloat fix
   when the bottleneck can't be managed. Natural next env feature.
3. KCP only with a new congestion controller + session reuse; until then it is
   a LAN/regional transport (its netem-30ms results were decent, its cn-us
   results are not).

## Caveats

- Single saturator + one foreground connection; multiple competing flows
  (fairness) not measured yet.
- cake used with default 100 ms target on an 80 ms baseline delay — a tuned
  `cake rtt` would cut its latency further; numbers here are conservative.
- BBR is BBRv1 (quinn's implementation); startup/ProbeRTT phases visible in
  the p95s.
- Loss is independent (uncorrelated) netem loss; real last-mile loss is bursty.

## Reproduce

```sh
env/up.sh --transport quic
env/badnet.sh apply cn-us            # or: --aqm cake
podman exec magicalane-client magabench run \
    --socks 127.0.0.1:1080 --target bench:9807 \
    --under-load --pings 30 --dl-par 1
env/badnet.sh clear
# full sweeps:
env/bench.sh --matrix --transports quic,quic-bbr,kcp --badnet cn-us --under-load
env/bench.sh --matrix --transports quic,quic-bbr,kcp --badnet cn-us --badnet-aqm cake --under-load
```
