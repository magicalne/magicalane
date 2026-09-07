# Deploying the client as a LAN gateway (LXC)

`scripts/gateway.sh` runs the magicalane client inside its own LXC
container (incus) with a dedicated LAN IP via macvlan, so all
interception risk (iptables, policy routes) stays inside the container
— the host is untouched except for a macvlan "shim" route (the host
itself can reach the container; other LAN hosts can by default).

```
[laptop] --\
[desktop]---- default gw + dns → [LXC: magicalane-gw .90] ---> tunnel ---> [server]
[nas]     --/
```

## One-time setup (host)

```sh
sudo apt-get install -y incus
sudo incus admin init --auto        # or preseed if no free subnet for incusbr0
```

(If `--auto` fails on subnet allocation, init with no managed network:
the gateway uses macvlan and does not need `incusbr0`. A preseed is in
the script's history; the essentials: dir storage pool + a root disk
device on the default profile — `create` adds it idempotently.)

## Lifecycle

```sh
scripts/gateway.sh create    # build + launch + deploy (idempotent)
scripts/gateway.sh verify    # temp server on the LAN + 4 end-to-end checks
scripts/gateway.sh config    # show /etc/magicalane/client.toml
scripts/gateway.sh start|stop|restart
scripts/gateway.sh status    # container, service, listeners, rule count
scripts/gateway.sh logs      # journalctl inside
scripts/gateway.sh shell     # bash inside
scripts/gateway.sh remove    # containers + shim torn down
```

Defaults (env-overridable): instance `magicalane-gw` at `192.168.2.90`
(macvlan on `enp9s0`, router `192.168.2.1`), temp verify server
`magicalane-gwtest` at `192.168.2.91`.

## Wiring your real server

1. `scripts/gateway.sh config` — edit `proxy.host/port/password`
2. Push the CA: `sudo incus file push ca.pem magicalane-gw/etc/magicalane/certs/ca.pem`
3. `scripts/gateway.sh restart`

## Pointing LAN devices at the gateway

- Default gateway → `192.168.2.90` (DHCP option 3 / static route)
- DNS → anything: hardcoded resolvers (8.8.8.8…) are intercepted and
  answered locally with fake IPs; pointing DNS at `192.168.2.90:53`
  also works (the PREROUTING REDIRECT covers dst-any udp/53)
- Or per-app only: SOCKS5/HTTP proxy `192.168.2.90:1080` (auth per
  `socks5_users` in the config)

## What `verify` proves (run before trusting it)

1. **Fake-IP DNS from a routed client** — a query aimed at 9.9.9.9,
   routed through the gateway, is intercepted and answered locally
   with a 198.18.0.0/15 token (no real query leaves the LAN)
2. **SOCKS5 through the tunnel to the internet** — HTTP 200 via
   gateway → temp server → real internet (egress = the server)
3. **Gateway rules installed** — MGL-PRE TPROXY rules present
   (forwarded traffic interception)
4. **Clean-exit contract** — stop: all firewall mutations revert;
   start: rules re-install

## Gateway-mode notes (single-NIC)

- Tunnel traffic is exempted **by source and destination address**
  (v4+v6): on a single-NIC gateway the server's responses share eth0
  with LAN traffic — without the exemption they would be TPROXY'd into
  the client's own interceptor (circular). Multi-homed hosts could
  instead scope rules to the LAN interface; the address exemption
  works for both topologies.
- Forwarded DNS goes through nat PREROUTING REDIRECT (destination-
  agnostic udp/53), which targets the interface address — hence the
  wildcard DNS-interceptor bind in gateway mode.
- `rp_filter` is set to 0 (best-effort): asymmetric transparent paths
  require loose reverse-path filtering.
- The container needs `iptables` installed (`create`/`verify` install
  it automatically) and NET_ADMIN (incus default capabilities suffice).
