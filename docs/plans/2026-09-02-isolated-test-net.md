# Isolated test network for magicalane verification

> Path: `docs/plans/2026-09-02-isolated-test-net.md`

## Summary

Build a throwaway, fully isolated network environment for verifying magicalane features and bug fixes without touching the host system's network stack (no bound ports, no iptables/nft rules, no certs in `~/.local/share`). The environment runs the real release binary in three container roles — QUIC server, SOCKS5 client, and an origin HTTP service — on a dedicated podman network, with scripts to bring it up, verify end-to-end proxying, and tear it down cleanly. The same scaffolding becomes the testbed for future transports (new protocol = new role/config, not new infra).

## Context

Issue: none yet (free-text task; can be filed as a GitHub issue on approval).

- The toolchain available on this host (Debian, x86_64) is **rootless podman 5.4.2 (netavark/aardvark-dns)** — no docker. `slirp4netns`, `ip`, `unshare` also present.
- Current verification story is weak: `tests/test.rs` integration tests are `#[ignore]`d and run against `localhost` — i.e. they bind real host ports (SOCKS5 :1080, QUIC :443) and are manual.
- Things that "pollute" the host today:
  - `src/socks5/server.rs` binds `0.0.0.0:port` (`Server::new`); `src/quic/server/mod.rs` binds the QUIC UDP port.
  - `src/lib.rs` `generate_key_and_cert_pem` writes self-signed certs into `~/.local/share/<ProjectDirs>` when server config omits `ca`/`key`.
  - `TransparentProxyConfig` (`src/config.rs`) exists for future transparent-proxy work (`tcp_port`/`udp_port`) — that feature will need iptables inside a netns, exactly what this env provides.
- TLS constraint (verified in `src/quic/client.rs`): the client resolves `proxy.host` to an IPv4 addr and uses it as rustls SNI; when `ca_path` is set, that cert is added as trusted CA. The default rcgen self-signed cert has SAN `localhost`, so pointing the client at a container hostname requires a **purpose-generated cert with matching SAN**.
- SOCKS5 `Command::UdpAssociate` is parsed (`src/socks5/proto.rs`) but only `Connect` is served — initial verification is TCP-only.

## Goals

- One-command bring-up (`env/up.sh`), verification (`env/test.sh`), and teardown (`env/down.sh`) of a self-contained client↔server↔origin network.
- Zero host-side residue while running: no host ports bound, no host firewall changes, no files outside the repo checkout (certs under `env/certs/`, gitignored).
- End-to-end functional check: SOCKS5 CONNECT via the local socks port → QUIC tunnel → server-side `LocalConnector` → origin HTTP, verified by content assertions.
- Negative tests: wrong password rejected, unreachable origin returns a proper SOCKS5 error reply (not a hang).
- Fast dev loop: host `cargo build --release`, binary copied into the image; no in-container Rust toolchain.
- **Transparent-proxy (tproxy) lab**: a dual-homed client acting as LAN gateway, so tproxy interception can be developed and verified with zero host firewall changes (feasibility verified rootless on this host — see Risks).
- Extensible roles: adding a transport/feature later means a new config or container role on the same network, plus new checks in `test.sh`.

## Non-goals

- No CI integration in this task (GH Actions runners use docker, not podman; the scripts are host-local for now — follow-up issue).
- No performance benchmarking harness (only a sanity throughput/big-transfer check).
- No UDP-over-SOCKS verification (unimplemented in the code today); UDP transparent interception is covered by the tproxy lab plumbing only, pending the Rust feature.
- **Implementing the tproxy feature in magicalane itself** (`TransparentProxyConfig` is parsed but unused — `tproxy: _` in `src/main.rs`) stays out of scope; this task delivers the *lab* it will be developed against.
- No changes to magicalane's own Rust code — env only.
- No in-container `cargo build` (host toolchain builds the release binary).

## Approach

### 1. Repo layout (`env/`)

```
env/
  Containerfile            # runtime image: debian:bookworm-slim + magicalane + test tools
  certs.sh                 # openssl: test CA + server cert (SAN: magicalane-server)
  configs/
    server.toml            # Kind::Server { port: 4433, ca, key }
    client.toml            # Kind::Client { proxy: magicalane-server:4433, socks5_port: 1080, ca_path }
    origin.toml            # (none needed; origin is python3 http.server)
  up.sh                    # network + certs + images + containers
  down.sh                  # remove containers + network (keep images/certs)
  test.sh                  # assertion suite (exit non-zero on failure)
  status.sh                # show containers, netns isolation proof, recent logs
certs/  → gitignored (env/certs/)
```

### 2. Runtime image (`env/Containerfile`)

- `FROM docker.io/library/debian:bookworm-slim` (glibc — matches the host-built binary; avoids a musl target).
- `apt-get install`: `curl`, `python3`, `socat`, `iperf3`, `procps`, `iproute2`, `ca-certificates`.
- `COPY target/release/magicalane /usr/local/bin/`.
- One image, three roles — origin and tester reuse it (no nginx/python images to pull).

### 3. Certificates (`env/certs.sh`)

- Generates `env/certs/ca.pem`, `env/certs/server.pem` (SAN `CN=magicalane-server`, SAN entry `DNS:magicalane-server`), `env/certs/server.key` via openssl; writes `env/certs/fingerprint` for eyeballing.
- Mounted read-only: `server.pem`+`server.key` → server container, `ca.pem` → client container (`ca_path`).
- Deterministic dir under the checkout; `.gitignore` gains `env/certs/`.

### 4. Network topology (`env/up.sh`)

```
podman network create magicalane-net (bridge, internal DNS via aardvark)

  origin            (python3 -m http.server 80, workdir /srv/www with known fixtures)
  magicalane-server (magicalane --config configs/server.toml, UDP :4433)
  magicalane-client (magicalane --config configs/client.toml, TCP :1080 socks)
```

- No `-p/--publish` anywhere: nothing reachable from the host. Interaction is via `podman exec` only.
- Client config `proxy.host = "magicalane-server"` — resolved by aardvark-dns, matches cert SAN, satisfies rustls verification (the `to_socket_addrs().find(is_ipv4())` path in `src/quic/client.rs`).
- Idempotent: `up.sh` detects existing network/containers and recreates only what's missing/stale; rebuilds the image only when `target/release/magicalane` mtime is newer than the image.
- Wait-for-ready: poll inside the client container until TCP :1080 accepts (`socat`/curl retry loop), and until server's UDP :4433 appears in `ss -lun` (`iproute2` in image).

### 5. Verification suite (`env/test.sh`)

All checks run via `podman exec magicalane-client` (curl is present in the image):

1. **Happy path**: `curl -fsS --socks5-hostname 127.0.0.1:1080 http://origin/fixtures/hello.txt` → exact content match (verifies SOCKS5 handshake, remote DNS via proxy, QUIC tunnel, server-side connect).
2. **Origin identity**: fetch `http://origin/fixtures/hostname` (pre-generated container id/hostname fixture) → proves the connection egressed from the **server** container, not the client.
3. **Integrity/size**: fetch a ~10 MB random fixture, `sha256sum` matches the pre-generated digest.
4. **Concurrency**: 20 parallel curls, all succeed.
5. **Wrong password**: second client container (or restarted client with bad password config) → CONNECT fails with SOCKS5 reply (assert non-zero curl exit, no hang — bounded timeout).
6. **Unreachable destination**: `curl --max-time 5 --socks5-hostname … http://192.0.2.1:1/` (TEST-NET) → SOCKS5 error reply, not a hang.
7. **Isolation proof**: from the **host**, `curl` to the origin/client socks port must fail (nothing published), and `ss -tln` on host shows no :1080/:4433.
8. **Logs on failure**: `test.sh` traps errors and dumps `podman logs magicalane-server magicalane-client` tails.

### 6. Teardown (`env/down.sh`)

- `podman rm -f` the three containers, `podman network rm magicalane-net`.
- Keeps image + certs for fast re-up; `down.sh --purge` also removes the image and `env/certs/`.
- Exit state check: `podman ps -a --filter label=magicalane.env=true` is empty, network gone. (Containers are created with `--label magicalane.env=true` for exact ownership.)

### 7. Extensibility hooks (design-for, not built now)

- Transport experiments: new container role (e.g. a CDN-front or relay) joins `magicalane-net`; client config gains a second instance pointing at it.
- Loss/latency emulation: containers already carry `iproute2`; adding `--cap-add NET_ADMIN` to a role enables `tc netem` on its veth — isolated because rootless netavark gives each network its own netns.
- Perf sanity: `iperf3` origin-side + a socks-capable streamer (curl large fixture timings) recorded in `status.sh`.

### 8. Phase 2 — transparent proxy (tproxy) lab

Mirrors the production story for `TransparentProxyConfig { tcp_port, udp_port }` (`src/config.rs`, currently unused): a Linux box acting as gateway intercepts all LAN traffic transparently — no SOCKS5, no app-side proxy settings.

**Topology** — one new bridge network, client becomes dual-homed:

```
magicalane-lan (new internal bridge, no outside connectivity)
  app              (curl fixtures; default route via tproxy-client's lan IP; NO proxy env at all)
  tproxy-client    (dual-homed: magicalane-lan + magicalane-net; --cap-add NET_ADMIN;
                    --sysctl net.ipv4.ip_forward=1; rp_filter=0;
                    mangle/PREROUTING TPROXY -> tcp_port/udp_port;
                    policy routing: ip rule fwmark 1 lookup 100,
                                    ip route local 0.0.0.0/0 dev lo table 100)
magicalane-net (existing)
  tproxy-client (wan side)  magicalane-server  origin
```

**Rules inside tproxy-client's netns only** (script: `env/tproxy-rules.sh`, idempotent):

```sh
iptables -t mangle -A PREROUTING -i <lan-if> -p tcp -d <server-ip> -j RETURN      # 1. exclude QUIC tunnel
iptables -t mangle -A PREROUTING -i <lan-if> -p udp -d <server-ip> -j RETURN
iptables -t mangle -A PREROUTING -i <lan-if> -d <lan-gw>/32 -j RETURN            # 2. exclude aardvark DNS
iptables -t mangle -A PREROUTING -i <lan-if> -p tcp -j TPROXY --on-port <tcp_port> --tproxy-mark 1
iptables -t mangle -A PREROUTING -i <lan-if> -p udp -j TPROXY --on-port <udp_port> --tproxy-mark 1
ip rule add fwmark 1 lookup 100 && ip route add local 0.0.0.0/0 dev lo table 100
```

Exclusions 1–2 prevent the two classic loops: the client's own QUIC packets to `magicalane-server` must not be intercepted, and DNS to the aardvark gateway must keep working once `app`'s default route points at the client.

**Two-stage verification** (so the plumbing is provable before any Rust tproxy code exists):

1. **Plumbing (now)**: a `socat` listener with `ip-transparent` option stands in for the future listener on `tcp_port`. `podman exec app curl http://origin/fixtures/hello.txt` — with no proxy configuration whatsoever — must return the fixture. Proves: app→client routing, PREROUTING interception, fwmark local-delivery, and that the original destination survives.
2. **Feature (later)**: replace socat with magicalane built on `TransparentProxyConfig`; same curl assertions as `test.sh` (hostname fixture proving egress from `magicalane-server`, sha256 integrity). UDP equivalent once `udp_port` is implemented (python UDP echo fixture).

**Setup mechanics**: `app` gets its default route replaced post-start (`podman exec app ip route replace default via <lan-ip>`, needs `--cap-add NET_ADMIN` + `iproute2` on `app` too); tproxy-client's two interface IPs are discoverable via `podman inspect`. Brought up via `env/up.sh --profile tproxy` (plain up stays minimal); `down.sh` removes both networks and all labeled containers.

**Host isolation**: all iptables/nft rules, routes, and TPROXY state live in the tproxy-client container's netns. Host kernel modules (`xt_TPROXY`) are shared — loading them is harmless and autoloads on first rule use (verified). Rootful podman (`sudo podman`) is the documented fallback if a rootless quirk appears, and plain `sudo ip netns` + veth the last resort.

## Files touched

- [x] `env/Containerfile` (new)
- [x] `env/certs.sh` (new)
- [x] `env/configs/server.toml` (new)
- [x] `env/configs/client.toml` (new)
- [x] `env/configs/client-badpw.toml` (new)
- [x] `env/fixtures.sh` + `env/fixtures/hello.txt` (new)
- [x] `env/up.sh` (new; `--profile tproxy` brings up the lan + dual-homed client + app)
- [x] `env/down.sh` (new)
- [x] `env/test.sh` (new)
- [x] `env/status.sh` (new)
- [x] `env/tproxy-rules.sh` (new; applies/exempts/cleans mangle + policy routing inside tproxy-client)
- [x] `.gitignore` (env/certs/, env/.build/, env/fixtures/generated/)
- [x] `AGENTS.md` (documented the env workflow)
- [x] `docs/plans/2026-09-02-isolated-test-net.md` (this plan)

### Deviations discovered during implementation (env could not work without them)

The env immediately exposed two dormant bugs in the codebase, fixed in the same change set:

1. **`src/quic/server/mod.rs`, `src/quic/client.rs`**: UDP sockets created via socket2 were never
   set non-blocking before being handed to quinn's tokio driver. `UdpSocket::from_std` only
   `debug_assert`s non-blocking — compiled out in release builds — so the endpoint driver never
   woke on readable data. Fixed with `socket.set_nonblocking(true)?`.
2. **`third_party/quinn` (vendored 0.7.2 + `[patch.crates-io]`)**: quinn ≤ 0.8's Linux recv path
   (`decode_recv`) `ptr::read`s a std `SocketAddrV4` over `libc::sockaddr_storage`; the two are not
   layout-compatible on modern rustc, so every received source address was silently corrupted
   (e.g. `10.89.0.6:40726` decoded as `2.0.159.22:22794` — family/port bytes read as the IP, and
   the IP's first two octets read as the port). The server then replied to a garbage address and
   the handshake never completed. Fixed field-by-field decoding in the vendored copy. The proper
   long-term fix is a quinn ≥ 0.11 upgrade — tracked as follow-up work.

## Risks & tradeoffs

- **Rootless DNS**: podman 5.x resolves container names on user-defined networks via aardvark-dns. If it's missing on this Debian box, fallback is static `--ip` addresses + `--add-host` entries baked into `up.sh` (cert SAN/IP regeneration handled by `certs.sh` args). Will detect and branch on first run.
- **UDP buffer sysctls**: `src/quic/client.rs` calls `set_recv_buffer_size(...)?` and errors abort startup. Rootless containers can't exceed host `net.core.rmem_max`; Debian defaults are usually sufficient for the test workload — if not, mitigation is `podman run --sysctl net.core.rmem_max=...` (allowed for these keys in rootless) — will verify in acceptance run.
- **glibc/base-image pin**: host-built binary requires the image's glibc ≤ host's. `debian:bookworm-slim` on Debian 13 (trixie) host is safe (older glibc); noted in Containerfile comment.
- **Pollution scope**: podman rootless networking itself creates a netavark namespace/bridges on the host — transient, owned by the user, removed with `down.sh`; this is the accepted minimal footprint (vs. VMs).
- **Podman not available on GH Actions runners** (docker there): scripts stay POSIX-ish bash and use only `podman build/run/network/exec`; a CI port later can alias or swap the binary via `CONTAINER_ENGINE` env var — cheap to add now, done from the start (`CE="${CONTAINER_ENGINE:-podman}"`).
- **Rootless TPROXY feasibility (verified)**: on this host (Debian 13, kernel 6.12, rootless podman 5.4 + netavark), a `--cap-add NET_ADMIN` container successfully installed `iptables -t mangle ... -j TPROXY`, `ip rule fwmark`, and `ip route local` — kernel modules `xt_TPROXY`/`nft_tproxy` exist and autoload via the host. Remaining quirks to watch during impl: iptables must be the **nft** backend (Debian default; the `xt` legacy backend does not work in user namespaces), and `rp_filter` must be set to 0 on the client's lan interface (asymmetric transparent paths). Fallback ladder: rootless → `sudo podman` (still netns-isolated; netavark adds managed host-side rules for its bridge only) → `sudo ip netns` + veth (fully manual, documented in `down.sh --help`).
- **Interception loops**: the classic tproxy footgun — intercepting the proxy's own upstream (QUIC to `magicalane-server`) or the DNS gateway creates a loop/hang. Mitigated structurally by the RETURN exclusions in `env/tproxy-rules.sh` and asserted by a bounded-timeout test.

## Acceptance criteria

- [x] From a clean state (no `magicalane-net`, no labeled containers, `env/certs/` absent), `env/up.sh` succeeds end-to-end in one invocation and is idempotent on a second run.
- [x] `env/test.sh` passes all checks and exits 0; each check prints a PASS line. (T1–T9 + T8b: 10 checks)
- [x] While the env is up, `ss -tlnp` and `ss -ulnp` on the **host** show nothing bound on 1080/4433, and host `curl http://127.0.0.1:1080` fails.
- [x] `env/down.sh` leaves `podman ps -a --filter label=magicalane.env=true` empty and `podman network ls` without `magicalane-net`; re-running `down.sh` is a no-op success.
- [x] Changing a fixture (or breaking the client binary) flips `env/test.sh` to failure with server+client log tails printed — verified by tampering with `hello.txt` (FAIL: T1 content mismatch), then restoring (10/10 pass).
- [x] No files created outside the repo checkout during up/test/down (certs and volumes all under `env/`).
- [x] **tproxy profile**: after `env/up.sh --profile tproxy`, `podman exec app curl -fsS http://origin/fixtures/hello.txt` succeeds with no proxy configuration on `app` (socat stand-in listener), proving transparent interception end-to-end.
- [x] **tproxy isolation**: while the tproxy profile is up, the host's `nft list ruleset` / `iptables-save` contains no tproxy rules (checked via passwordless sudo in T9).
- [x] **tproxy teardown**: `env/down.sh` removes `magicalane-lan` and all tprofile containers; re-run is a no-op success.

### Implementation notes (deviations from the original design)

- The plain-UDP/forwarding return path between subnets requires a pinned route on the origin
  (`10.89.1.0/24 via <tproxy-client-wan-ip>`) because podman's shared rootless netns does not
  forward between container networks and rootless cannot enable `ip_forward` there. The
  tproxy-intercepted path itself needs no such route (interception terminates in the client netns).
- `rp_filter` sysctl writes are denied rootless; made non-fatal in `tproxy-rules.sh` (verified not
  to block this topology).
- Short DNS names require explicit `--network-alias` (podman DNS resolves container names only;
  unaliased short names leak to upstream DNS).
- `up.sh` does not restart already-running containers after a binary rebuild — documented in
  AGENTS.md: `down.sh` then `up.sh`.

## Open questions

1. **Engine choice** — rootless podman (proposed; already installed) vs. plain `ip netns` + veth via sudo (lighter, but root and more manual) vs. a VM (heaviest isolation). Defaulting to podman unless you object.
2. **Ports inside the env** — server QUIC on 4433, client SOCKS5 on 1080 (proposed defaults; everything is inside the net, so collisions with host services are impossible anyway).
3. **Fixture content** — is the built-in set (hello.txt, hostname, 10 MB random blob) enough, or do you want a specific set of destination services (e.g., a fake DNS responder, TLS origin) staged now?
4. **Scope of negative tests** — wrong-password + unreachable-destination proposed; also possible: expired-cert, ALPN mismatch. Keep minimal for now?
5. **tproxy profile in this task or follow-up** — the lab plumbing (dual-homed client, rules script, socat stand-in, tests) is now specified in the plan; build it as part of this task (default, ~1 extra script) or defer to when you start the Rust tproxy feature?
