# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

Magicalane is a QUIC-based proxy written in Rust. A local SOCKS5 server forwards traffic over QUIC to a remote server, which relays it to the destination.

## Tech Stack

- Rust (edition 2018)
- QUIC via `quinn` / `quinn-proto` 0.7, TLS via `rustls`/`rcgen` (self-signed cert generation)
- Async runtime: `tokio` + `futures`
- CLI: `structopt`; config: `toml` + `serde`; logging: `tracing` / `env_logger`

## Build & Test

```sh
cargo build            # debug build
cargo build --release  # release build (what CI ships)
cargo test             # unit tests; integration tests in tests/test.rs are #[ignore]d
cargo fmt              # formatting (keep code formatted before committing)
cargo clippy           # lints
```

Integration tests are run manually with `cargo test -- --ignored` since they spin up real client/server endpoints.

## Verification Protocol — MANDATORY

**Any change to the code — new feature, bugfix, refactor, dependency bump — MUST be verified with the harness before committing.** Never commit on a red or unverified suite.

1. **Every code change**:
   - `cargo test` (fast, no containers) AND `cargo clippy` must be clean.
   - `env/verify.sh fast` — smoke suite, ~30 s. Minimum bar for any commit.
2. **Features, transport changes, config changes, PRs**: `env/verify.sh full` (all suites × transports + tproxy, ~2 min). If your feature has a suite (e.g. `dns`, `tproxy-ws`, `residue`), run it explicitly: `env/verify.sh <suite>`.
3. **Bugfixes**: additionally land a **regression testcase** in `env/tests/` (`NNN-reg-<slug>.sh`, `# regression: <commit-or-issue>` in the header). A bugfix without a pin for the bug is incomplete — see `015-reg-fresh-handshake.sh` / `016-reg-relay-no-dup.sh` for the pattern.
4. **Performance-relevant changes**: run `env/bench.sh` (and `--badnet` profiles if loss/latency behavior is affected) and compare against previous results in `env/bench-results/`.
5. If the harness fails, fix before committing — do not skip, comment out, or weaken testcases to get past it.

Reminder: after rebuilding the binary, run `env/down.sh` before `env/up.sh` — running containers are not auto-redeployed.

## Code Layout

- `src/main.rs` — CLI entry point (client/server subcommands)
- `src/lib.rs` — library root, re-exports key items (incl. `generate_key_and_cert_der`)
- `src/config.rs` — TOML config parsing
- `src/error.rs` — error types (`Result`)
- `src/proxy.rs` — core proxy forwarding logic
- `src/connector.rs` — connectors (`LocalConnector`, `QuicConnector`)
- `src/quic/` — QUIC layer
  - `client.rs`, `stream.rs`, `proto.rs`
  - `server/` — QUIC server (conn, stream, mod)
- `src/socks5/` — SOCKS5 local server (proto, conn, server, error)
- `tests/test.rs` — integration tests (ignored by default)

## CI / Release

`.github/workflows/rust.yml` triggers on `v*` tags: builds release binaries for Linux and macOS, runs tests, and uploads `magicalane-linux` / `magicalane-macOS` to the GitHub release.

## Test Environment (`env/`)

Isolated rootless-podman network for verifying the proxy end-to-end without touching host ports/firewall:

```sh
./env/up.sh --transport quic|kcp        # core lab on the chosen transport (default quic)
./env/up.sh --transport kcp --profile tproxy  # + dual-homed tproxy client + app
./env/verify.sh              # fast: smoke suite on quic (~1 min)
./env/verify.sh full         # all suites x transports + tproxy (26 checks)
./env/verify.sh <suite|name> # e.g. smoke, transport, tproxy, regression, 008-tunnel-http-private
./env/status.sh              # containers, listeners, tproxy rules, app routes
./env/down.sh                # remove containers + networks (--purge also drops image/certs)
```

- Interaction is `podman exec` only; nothing is published to the host. Certs/fixtures live under `env/` (gitignored).
- Configs live in `env/configs/{server,client}-{quic,kcp}.toml` (+ `-badpw` variants for the auth negative test).
- **Private test service** (`magicalane-testsvc`, `magabench serve`): HTTP :8080 (`/id`, `/echo`, `/hello`), framed TCP echo :9001, UDP echo :9002, on an `--internal` backend network only the server can reach. If a testcase can talk to it, the traffic provably went through the tunnel; the negative twins assert direct access fails. (This is why the backend must stay `--internal`: the shared rootless netns otherwise routes between all container networks.)
- **Harness**: testcases live in `env/tests/NNN-slug.sh` (metadata headers: suites/transports; helpers in `env/tests/helpers.sh`). `env/verify.sh` is the one entry point; `env/test.sh` is a wrapper for `full`. Suites `dns`, `tproxy-ws`, `residue` are reserved for the transparent-client phases. See "Verification Protocol" above — running it is mandatory for all code changes.
- The tproxy profile uses `env/bridge.py` (IP_TRANSPARENT listener → local socks5) as the stand-in for the future in-process `TransparentProxyConfig` listener; intercepted traffic then flows through the real client/server over the selected transport.
- **After changing Rust code, run `env/down.sh` before `env/up.sh`** — up.sh skips already-running containers, so a rebuild won't deploy into them.
- `env/tproxy-rules.sh apply|clean|show` manages TPROXY mangle + policy routing inside the tproxy-client container.
- Local cargo tests cover the KCP session layer without containers: `tests/kcp_loopback.rs` (raw + TLS echo), `tests/kcp_fullstack.rs` (real listener/connector + origin).
- Override the engine with `CONTAINER_ENGINE=...` if needed.

## Benchmarks (`env/bench.sh`)

End-to-end transport comparison through the real stack (socks5 -> transport -> server -> echo origin), using the `magabench` binary (framed TCP echo origin + socks5-driven load client):

```sh
env/bench.sh                          # quic vs kcp
env/bench.sh --transports quic,kcp,kcp-plain   # include plaintext KCP (TLS overhead)
env/bench.sh --matrix --transports quic,quic-bbr,kcp,kcp-wnd2048   # parameter sweep
env/bench.sh --delay 30 --loss 2     # netem on the server: 30ms RTT, 2% loss
env/bench.sh --pings 200 --dl-bytes 134217728  # knobs pass through to magabench
```

Metrics: fresh-connection setup (p50/p95, includes KCP session+TLS or QUIC stream open), RTT percentiles (64B/1KiB/16KiB), download throughput (single + `--dl-par` parallel aggregate), upload throughput, and concurrent small-request rate (rps). Results print as a comparison table and are saved under `env/bench-results/` (gitignored). The echo origin runs as container `magicalane-bench-echo` (label-owned, removed by `down.sh`).

**Parameter matrix** (`--matrix`): variants are generated into `env/configs/variants/` (gitignored) and deployed via `up.sh --server-config/--client-config`. Built-in tags: `quic`, `quic-bbr`, `quic-newreno`, `quic-win32m` (congestion controller + 32MiB windows), `kcp`, `kcp-wnd2048`, `kcp-nc0` (congestion control on), `kcp-i40`, `kcp-mtu1400`. Add variants by extending `variant_toml` in bench.sh. Tuning is a normal config feature (see `src/config.rs` `KcpTuning`/`QuicTuning` docs).

**Findings so far** (local bridge): clean link — QUIC-cubic fastest single-stream (~159/182 MB/s dl/ul), BBR wins concurrency (5.4k rps vs 2.2k); KCP scales with window (wnd2048: 2× default to ~44 MB/s), keep `nc=true` (cc on costs 4.5×) and `interval=10` (i40 costs 4×). 30ms+2% loss — BBR is transformative (19/41 MB/s vs cubic's 0.9), KCP-wnd2048 best of the KCPs (5.5 MB/s, 105 rps). KCP connect is ~204ms everywhere: fresh session+TLS per request (no reuse yet) — the top optimization candidate (QUIC reuses one connection: 0.7ms).

## Bad-network simulation (`env/badnet.sh`)

Realistic cross-country profiles shaped in **both directions** with dst-IP filtering (only client↔server is degraded; server↔origin stays clean), asymmetric rates, jitter, loss, and a choice of bottleneck queue:

```sh
env/badnet.sh apply cn-us            # 160ms RTT, 0.3% loss, 5/20 Mbit up/down, deep FIFO (bufferbloat)
env/badnet.sh apply cn-us --aqm cake # same path with AQM (managed queue)
env/badnet.sh apply eu-us|mobile     # other profiles; status / clear
# combined with the benchmark:
env/bench.sh --matrix --transports quic,quic-bbr,kcp --badnet cn-us --under-load
```

`magabench --under-load` measures foreground RTT percentiles **while a saturating download runs** plus the sustained load throughput — the "is it usable while downloading" metric. Findings + recommendations in `docs/reports/2026-09-03-badnet-usability.md` (short version: cross-country → QUIC+BBR; KCP needs a real congestion controller and session reuse before WAN use).

## Conventions

- Public API errors: use `crate::error::{Result, Error}` rather than ad-hoc error types (SOCKS5 module has its own `error.rs`).
- Keep async code on tokio; connection/stream logic lives in `conn.rs`/`stream.rs` per module.
- Do not bump dependency versions casually: `quinn` 0.7 / `rustls` 0.18 / `tokio-util` 0.6 are tightly version-coupled (see Cargo.toml).
