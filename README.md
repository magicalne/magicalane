# Magicalane - A QUIC based proxy

## Download

Checkout the recent releases.

## Run

Both sides read a TOML config via `--config`. The tunnel transport is `quic` (default) or `kcp`; KCP can additionally layer TLS (`tls = true`, default).

`server`:

```toml
password = "your-password"
bandwidth = 65536
verbose = true
kind = { Server = { port = 4433, ca = "server.pem", key = "server.key", protocol = "kcp", tls = true } }
```

`client`:

```toml
password = "your-password"
bandwidth = 65536
verbose = true
kind = { Client = { proxy = { host = "your.hostname", port = 4433, ca_path = "ca.pem", protocol = "kcp", tls = true }, socks5_port = 1080, tproxy = { tcp_port = 7895, udp_port = 7896 } } }
```

Then start each with `magicalane --config <file>`; the client serves SOCKS5 on `socks5_port`.
