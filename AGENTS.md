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
bash env/test.sh             # full assertion suite (10 checks; auto-detects transport + tproxy)
./env/status.sh              # containers, listeners, tproxy rules, app routes
./env/down.sh                # remove containers + networks (--purge also drops image/certs)
```

- Interaction is `podman exec` only; nothing is published to the host. Certs/fixtures live under `env/` (gitignored).
- Configs live in `env/configs/{server,client}-{quic,kcp}.toml` (+ `-badpw` variants for the auth negative test).
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
env/bench.sh --delay 30 --loss 2     # netem on the server: 30ms RTT, 2% loss
env/bench.sh --pings 200 --dl-bytes 134217728  # knobs pass through to magabench
```

Metrics: fresh-connection setup (p50/p95, includes KCP session+TLS or QUIC stream open), RTT percentiles (64B/1KiB/16KiB), download/upload throughput (MB/s), and concurrent small-request rate (rps + p95). Results print as a comparison table and are saved under `env/bench-results/` (gitignored). The echo origin runs as container `magicalane-bench-echo` (label-owned, removed by `down.sh`).

Reference numbers (local bridge, no netem): QUIC ~0.7ms connect / ~0.3ms RTT / ~150MB/s; KCP+TLS ~200ms connect (per-request session+TLS, no reuse) / ~0.4ms RTT / ~20MB/s. Under 30ms+2% loss, KCP download outperformed QUIC ~4x. Known optimization areas: KCP session reuse/multiplexing, window/tick tuning for throughput.

## Conventions

- Public API errors: use `crate::error::{Result, Error}` rather than ad-hoc error types (SOCKS5 module has its own `error.rs`).
- Keep async code on tokio; connection/stream logic lives in `conn.rs`/`stream.rs` per module.
- Do not bump dependency versions casually: `quinn` 0.7 / `rustls` 0.18 / `tokio-util` 0.6 are tightly version-coupled (see Cargo.toml).
