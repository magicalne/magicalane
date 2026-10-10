# Interception plane internals (iptables + marks + DNS)

This is the map of how the magicalane client intercepts traffic — the
rule architecture, the packet journeys, the invariants that must never
break, and how to debug it. Written after the 2026-10 production
"reply-eat" outage so that the next person (or agent) reads this doc
instead of reverse-engineering the code.

Related: [deploy-gateway.md](deploy-gateway.md) (how this runs in an
LXC), `env/tests/040-reg-tproxy-reply-eat.sh` (the regression pin),
`AGENTS.md` (repo conventions).

## The three components

| Component | Where | What it does |
|---|---|---|
| Rule generation | `src/tproxy/rules.rs` (`apply`/`apply_v6`) | Builds + atomically installs the iptables blob (`iptables-restore --noflush`), sets policy routing, tears down on exit |
| TCP plane | `src/tproxy/mod.rs` (`bind`, `serve`, `original_dst`) | Transparent TCP listener; recovers the original destination (`SO_ORIGINAL_DST` for REDIRECT, `getsockname` for TPROXY) |
| UDP plane | `src/udp/mod.rs` (`bind_client`, flow tasks) | Transparent UDP listener; per-flow relays; DNS-over-tunnel via the magic address (`magic_addr()`) |
| DNS/fakeip | `src/dns/` (`mod.rs` listener, `fakeip.rs` map, `resolve.rs` resolver, `proto.rs` wire) | Answers device DNS locally with 198.18.0.0/15 tokens; resolves direct-path domains via `direct_dns` |
| Marked sockets | `src/connector.rs` (`SO_MARK_DIRECT = 0x2a2`, `set_socket_mark`, `udp_socket_marked`) | The gateway's OWN outbound sockets carry a mark so its own interception rules let them pass |

## Marks and policy routing (v4; v6 mirrors with `MGL6-*`)

```
MARK 0x2a1  "interception"  — packets routed to the transparent listeners
MARK 0x2a2  "direct socket" — the gateway's own outbound sockets

ip rule 100: fwmark 0x2a1 lookup 141
ip route (table 141): local default dev lo          ← tproxy delivery
ip route: local 198.18.0.0/15 dev lo                ← fake tokens routable
```

Constants live in `src/tproxy/rules.rs` (`MARK`, `TABLE`, chain names).

## The chains — and why their ORDER matters

### mangle `MGL-PRE` (PREROUTING: forwarded + inbound)

```
1. -m conntrack --ctdir REPLY -j RETURN        ← THE GUARD (see below)
2. -i lo -p udp --mark 0x2a1 -j TPROXY --on-port <udp_port>
3. -s <server_ip> -j RETURN                     ← keeps the tunnel alive
   -d <server_ip> -j RETURN
4. -p udp --dport 53 -j RETURN                  ← DNS goes via nat REDIRECT
   --dport <dns_port>, <socks_port> RETURN      ← our own listeners
5. ! -i lo -p tcp -j MARK 0x2a1 + TPROXY --on-port <tcp_port>
   ! -i lo -p udp -j MARK 0x2a1 + TPROXY --on-port <udp_port>
```

Rule 5 is the gateway-mode catch-all: everything arriving from the LAN
that isn't exempted above is intercepted. Rules 1–4 are what keep the
machine itself functional while standing in front of the firehose.

### mangle `MGL-OUT` (OUTPUT: locally generated)

```
1. --mark 0x2a2 RETURN        ← our direct sockets pass untouched
2. -d <server_ip> RETURN      ← tunnel socket
3. -d 127.0.0.0/8 RETURN
4. -p udp --dport 53 RETURN   ← resolver probes (belt & braces; they
   -p udp --sport <dns_port>/<udp_port> RETURN  are also marked)
5. -p udp -j MARK 0x2a1       ← other local UDP rides the interceptor
```

### nat `MGL-NAT` (OUTPUT) and `MGL-PRENAT` (PREROUTING)

```
MGL-NAT:    0x2a2 RETURN → server RETURN → 127/8+multicast RETURN
            → -p tcp REDIRECT --to-ports <tcp_port>
            → -p udp --dport 53 REDIRECT --to-ports <dns_port>
MGL-PRENAT: -p udp --dport 53 REDIRECT --to-ports <dns_port>
```

This is how DNS from devices (and from the gateway's own system
resolver) reaches the fakeip engine regardless of the configured
resolver address. **Gotcha**: nat REDIRECT rewrites the destination
port *before* `filter OUTPUT` evaluates — a filter rule matching
`--dport 53` will never see redirected traffic; match by uid or the
redirected port instead.

## Packet journeys

**LAN device, TCP to a foreign site** — device sends to its default
gw (us) → `MGL-PRE` rule 5 marks + TPROXYs → `serve()` recovers the
original dst → routing engine → tunnel → server resolves + connects.

**LAN device, DNS** — UDP :53 → `MGL-PRENAT` REDIRECT → fakeip engine
answers 198.18.x instantly (no upstream query) → device connects to
the token → intercepted like any TCP/UDP → `fakeip.rs` reverse-maps
the token to the domain → routing rules decide.

**Direct-path (e.g. China) domain** — token → reverse-map → `direct`
rule → `resolve.rs` probes `direct_dns` **with a 0x2a2-marked socket**
(rule exemptions keep the query and its answer out of our own
interception) → `connector.rs` connects the resolved IP from a marked
socket. This whole path dies if either the query or the *reply* gets
intercepted.

## The invariants (breaking these broke production)

1. **`--ctdir REPLY` guard is rule 1.** The catch-all matches by
   address/port only; without the guard it swallows the *answers* to
   connections this host initiated (resolver probe replies,
   direct-connect SYN-ACKs). Symptom signature: **tunneled sites work,
   everything direct times out** — the tunnel survives on its explicit
   `-s <server_ip>` exemption, which is exactly why the breakage looks
   "external". This shipped 2026-09, broke ~2026-09-23, diagnosed
   2026-10-10 after being misread as a router/ISP problem. Regression:
   `env/tests/040-reg-tproxy-reply-eat.sh`.
2. **Every new interception rule needs a reply-path exemption** — ask
   "does this rule match packets that are answers to our own sockets?"
   If yes, scope it (`--ctdir`, `-s`, owner match) or exempt.
3. **The tunnel server IPs must stay exempt in every chain** (both
   `-s` and `-d`): the QUIC/KCP/TCP-fallback sockets are our lifeline.
4. **Never relay DNS-over-TCP to a resolver that doesn't serve it** —
   LAN devices' TCP :53 fallback gets intercepted like any TCP; if the
   routing engine relays it "direct" to a home router that doesn't do
   TCP DNS, the 10s connect timeout × client retries becomes a
   permanent retry loop. Interim mitigation in the gateway container:
   `filter OUTPUT -p tcp -m owner --uid-owner <resolved-uid> -j
   REJECT`. Proper fix: answer TCP :53 locally (`serve_client_tcp`).

## Debugging (field-tested; what works and what lies)

- **`/proc/net/nf_conntrack`** (or `conntrack -L`) is ground truth for
  "did the answer come back": a flow with no `[UNREPLIED]` tag saw
  reverse traffic; the kernel can still eat it after PREROUTING.
- **`iptables -t mangle -L MGL-PRE -v -n`** counters show which rule
  class a packet took. Add a temporary `LOG` rule to trace one flow.
- **tcpdump must run where the packet is** — inside the container/VM
  that owns the netns. Capturing on an upstream/shared interface can
  silently miss frames (driver offload/macvlan quirks); an empty
  capture is not evidence until the capture setup is validated on
  known-good traffic. Rootless podman cannot read legacy tables at all
  (`exec -u 0` still lacks CAP_NET_ADMIN over the initial netns).
- **Shell UDP DNS probes (`/dev/udp`) are unreliable** — use a real
  stub (dig) or watch conntrack instead.
- **"No resolution"** in logs = `resolve.rs` exhausted
  cache→hosts→`direct_dns` probes→system fallback. Check the probe
  path first (marks, reply guard), not the upstream.
