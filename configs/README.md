# Magicalane example configs

Copy-paste starting points and feature demos. Every file here is
**parse-checked by `cargo test --test configs`** — if a code change
breaks a config, that test fails. Keep them valid.

| File | What it is |
|---|---|
| [`server.toml`](server.toml) | **Start here** — minimal QUIC server (copy me) |
| [`client.toml`](client.toml) | **Start here** — minimal QUIC client, SOCKS5 on 127.0.0.1:1080 |
| [`server-kcp.toml`](server-kcp.toml) | KCP+TLS server variant |
| [`client-full.toml`](client-full.toml) | Feature tour: transparent mode + fake-IP + split routing + geoip + multi-server groups + providers + inbound auth |
| [`client-tun.toml`](client-tun.toml) | TUN mode (userspace TCP/IP stack, no iptables; needs the `tun-mode` build) |

## Quick start

1. Generate a CA and a server certificate (SAN must match the
   hostname/IP clients dial):

   ```sh
   mkdir -p /etc/magicalane/certs && cd /etc/magicalane/certs
   openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
       -keyout ca.key -out ca.pem -subj "/CN=my magicalane CA"
   openssl req -newkey rsa:2048 -nodes \
       -keyout server.key -out server.csr -subj "/CN=my-server"
   printf 'subjectAltName=DNS:my-server,DNS:localhost,IP:203.0.113.10\n' > ext.cnf
   openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
       -out server.pem -days 825 -extfile ext.cnf
   ```

2. Copy `server.toml` to the server and `client.toml` to the client
   (adjust host/port/paths), then on each side:

   ```sh
   magicalane --config /etc/magicalane/server.toml   # server side
   magicalane --config /etc/magicalane/client.toml   # client side
   curl --socks5-hostname 127.0.0.1:1080 https://example.com
   ```

## TOML format note (important)

The `kind` value **must stay an inline table**:

```toml
kind = { Client = { ... } }      # ✅ works
```

```toml
[kind.Client]                    # ❌ rejected by the current parser
socks5_port = 1080
```

Nested arrays (`server = [ { ... } ]`, `rule = [ ... ]`) are fine
inside the inline table; multi-line inline tables are not — long
`kind` lines are normal. Top-level tables (`[dns]`, `[tuning.kcp]`,
`[tuning.quic]`) use normal header syntax.

## Feature flags

TUN mode requires a feature build:

```sh
cargo build --release --features tun-mode
```
