# Transparent client: TPROXY + TUN modes with clean-exit network management

> Path: `docs/plans/2026-09-03-transparent-client.md`
> Status: draft for review — no implementation yet.

## Summary

Make the magicalane client able to transparently intercept **all local machine
traffic** (terminal, browser, desktop apps — TCP first, UDP later) and carry it
through the existing tunnel, in two interception modes: **TPROXY** (firewall
marks + policy routing, no userland TCP stack) and **TUN** (routes only, no
firewall changes, userland stack). The defining requirement is the **clean-exit
contract**: every network mutation exists only while the client runs; on any
exit path the host's iptables/routes/sysctls return to byte-identical state.

## Context

- `TransparentProxyConfig { tcp_port, udp_port }` (`src/config.rs`) is parsed
  but unused (`tproxy: _` in `src/main.rs`). No transparent listener exists.
- The env already proves the plumbing: `env/tproxy-rules.sh` + `env/bridge.py`
  (Python stand-in listener) demonstrated TPROXY interception end-to-end
  through the real client/transport/server, and that `getsockname()` on an
  `IP_TRANSPARENT`-accepted socket yields the original destination.
- Transports (`QuicConnector` / `KcpConnector` behind `Connector`) and the
  relay machinery are transport-agnostic; a transparent listener plugs in the
  same way socks5 does.
- Known gaps from the earlier discussion: no UDP relay (tunnel protocol is
  stream-oriented; SOCKS5 UDP ASSOCIATE unimplemented), IPv4-only transports,
  DNS strategy undefined.

## Goals

- Intercept local (workstation) and routed (gateway) TCP traffic transparently
  into the tunnel with zero application configuration.
- **Clean-exit contract** (see below) enforced and test-proven.
- TUN mode as a firewall-free alternative (TCP via userland stack, UDP natively).
- All of it verifiable in the existing podman env, including crash scenarios.

## Non-goals

- SOCKS5 UDP ASSOCIATE (may fall out of the UDP work, not required).
- Windows/macOS transparent modes.
- Per-app routing rules / split tunneling configuration language (v1 is
  all-or-nothing with fixed exclusions).

## The clean-exit contract

**Every** network mutation is (a) namespaced to magicalane, (b) applied
atomically, (c) removed by exact inverse, (d) covered on every exit path:

| aspect | rule |
|---|---|
| iptables | All logic lives in owned chains (`mgl-*`). Built-in chains receive exactly **one jump rule each**, inserted idempotently. Removal deletes the exact jump (match-based), then flushes owned chains only. **Never** `-F`/`-X` on built-ins. Apply via `iptables-restore --noflush` (atomic per table) — the docker/k8s mechanism. |
| policy routing | Own table id + own `ip rule` entries with fixed priority; removal by exact spec, never `ip rule flush`. |
| routes (TUN) | Tagged with a reserved `proto MAGICTUN` so `ip route del ... proto` is exact. Default-route override via metric, never replacing existing routes. |
| sysctls | Read-before-write, restore prior value on exit (e.g. `rp_filter` on `lo`). Prefer designs that need none. |
| resolv.conf | **Untouched in v1.** DNS is handled by intercepting udp/53 through the tunnel (or left direct — open question Q2). |
| exit paths | 1) SIGTERM/SIGINT hook → reverse-order teardown. 2) Crash → systemd `ExecStopPost=` runs the same idempotent cleanup script. 3) `kill -9` orphan → next start detects tombstone/lock + stale chains and adopts-cleans before applying. 4) TUN device self-destructs with the process fd; only its routes need cleanup. |
| failure apply | If any apply step fails, previously applied steps roll back in reverse before erroring out. Partial state is never left behind on a failed *start*. |

**Verification is part of the feature**: the env gains a residue test —
snapshot `iptables-save`, `ip rule`, `ip route show table all` before and after
each scenario (normal exit, SIGKILL, kill -9 + restart) and assert
byte-identical deltas of zero.

## Mode A — TPROXY (phase 1: TCP; phase 2: UDP)

### Listener (in-process, replaces bridge.py)

- `socket2` → bind `0.0.0.0:tcp_port` with `IP_TRANSPARENT`, tokio listener.
- On accept: `getsockname()` = original destination → wrap as
  `socks5::proto::Addr` → open relay via the configured `Connector`
  (quic or kcp) → reuse the `socks5::conn.rs` relay machinery minus the
  SOCKS5 handshake (a `Connecting` variant that starts at `OpenRemote`
  with the address taken from the socket).
- Socket buffer sizing identical to the existing endpoints.

### Workstation rules (local traffic)

```
iptables -t mangle -N mgl-output
iptables -t mangle -A OUTPUT -j mgl-output
#   in mgl-output (order matters):
#     -d <server_ip>/32 -j RETURN            # tunnel egress
#     -m owner --uid-owner <mgl-user> -j RETURN   # our own traffic (loop guard)
#     -d 127.0.0.0/8 -j RETURN               # loopback
#     -d 224.0.0.0/4 -j RETURN               # multicast
#     -p tcp -j MARK --set-mark 0x2a1
ip rule add fwmark 0x2a1 priority 41000 table 41
ip route add local 0.0.0.0/0 dev lo table 41
iptables -t mangle -A PREROUTING -i lo -p tcp -j TPROXY --on-port <tcp_port> --tproxy-mark 0x2a1
```

Loop prevention is double-layered (destination **and** uid) — uid excludes the
client's own sockets even if the server IP changes (roaming/DNS).

### Gateway rules (phase 1, already proven shape in env)

PREROUTING variant for traffic routed through the box (the `env/tproxy-rules.sh`
topology), same owned-chain structure and exclusions.

### Phase 2 — UDP

- Listener: UDP socket with `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`;
  per-datagram original dst from cmsg; per-5-tuple flow table with idle
  timeouts mapping to one tunnel stream per flow.
- Tunnel: datagram framing over the existing stream protocol
  (`[Addr][u16 len][payload]` chunks) — small, backward-compatible additive
  change; server side gains a UDP relay counterpart.
- **REJECT (not DROP) udp/443 while UDP is unimplemented** so browsers fall
  back to TCP immediately instead of timing out.

### DNS (phase 2)

Intercept udp/53 and dnat/relay through the tunnel (a UDP flow like any other)
once phase 2 lands; v1 leaves `127.0.0.0/8` excluded (systemd-resolved keeps
working, queries go direct — see open questions).

## Mode B — TUN (phase 3)

- `tun` crate device `mgl0`, routes only — **zero iptables state**:
  - exception route: `<server_ip> via <physical gw> proto MAGICTUN` (pinned
    before the default override, loop guard)
  - `default dev mgl0 metric 41000 proto MAGICTUN`
- Userland TCP stack (`smoltcp`, tun2socks-style): terminates TCP flows from
  the tun, converts each to a tunnel relay. UDP is native datagrams (no
  session semantics needed beyond flow timeouts) — TUN's structural advantage.
- Costs vs TPROXY: userland retransmission (a second TCP), CPU, ~ms latency;
  benefit: no firewall privileges beyond route adds, uniform TCP/UDP handling,
  some VPN-ish features become natural (per-route splitting later).
- Clean-exit: device vanishes with the process; routes removed by exact
  `proto MAGICTUN` match (both paths incl. crash recovery shared with mode A).

## Phasing

1. **Phase 1 — TCP TPROXY**: in-process listener + rule manager implementing
   the contract + workstation & gateway rule sets + env residue tests
   (graceful, SIGKILL, restart-adoption). Replaces bridge.py in the env.
2. **Phase 2 — UDP over TPROXY**: datagram framing + server UDP relay + udp/53
   interception; drop the udp/443 REJECT workaround.
3. **Phase 3 — TUN mode**: smoltcp integration, route manager (contract
   shared), UDP native.
4. **Phase 4 — IPv6**: v6 rules/addresses across both modes (decides the
   current silent-leak issue: v1 should at minimum detect v6 connectivity and
   warn loudly, or optionally blackhole AAAA to force v4).

Cross-cutting: the rule/route manager is one small module used by both modes;
it owns apply/rollback/adopt-cleanup and is the only code allowed to touch
host networking.

## Files touched (phase 1 sketch)

- [ ] `src/tproxy/mod.rs` — transparent TCP listener
- [ ] `src/tproxy/rules.rs` — transactional rule/route manager (owned chains,
      restore-blob apply, exact teardown, stale-state adoption)
- [ ] `src/config.rs` — activate `TransparentProxyConfig` (mode: off/tproxy/tun)
- [ ] `src/main.rs` — wire listener + manager lifecycle (signals → teardown)
- [ ] `env/tproxy-rules.sh` — superseded by in-process manager; becomes
      env-only test scaffolding (kill -9 / residue scenarios)
- [ ] `env/test.sh` — residue assertions + transparent-path checks without bridge.py

## Risks & tradeoffs

- **iptables vs nftables backend variance**: use the `iptables` binary (nft
  backend default) with restore-blobs; tested on Debian; nft-native later.
- **Root requirement**: TPROXY/TUN need CAP_NET_ADMIN; workstation deployment
  assumes a systemd unit with `AmbientCapabilities=CAP_NET_ADMIN` +
  `ExecStopPost` cleanup (also satisfies the contract's crash path).
- **UID loop guard requires running as a dedicated user** (or cgroup match);
  document the unit file; gateway mode (no local traffic) doesn't need it.
- **UDP session semantics** (phase 2) — flow timeout tuning vs NAT rebinding;
  bench in env under badnet profiles.
- **smoltcp** (phase 3) adds a dependency and its own risk profile; kept
  strictly behind the TUN mode feature.

## Open questions

1. DNS in v1: leave direct (loopback excluded — simplest, leaks metadata) vs
   block udp/53 outbound to force DoH/failure? (Recommend: leave direct v1,
   intercept in phase 2.)
2. IPv6 posture pre-phase-4: warn-only vs optional AAAA blackhole?
   (Recommend warn-only.)
3. Tun stack choice: smoltcp vs gVisor netstack (bigger, faster, Go-oriented
   bindings)? (Recommend smoltcp for footprint.)
4. Should gateway mode ship in phase 1 or is workstation mode alone enough
   for the first cut? (Env already tests gateway topology; product cost is
   small — recommend both.)
