# Magicalane - A QUIC based proxy

## Download

Checkout the recent releases.

## Run

```sh
chmod +x magicalane-linux
```

`client`:

```sh
./magicalane-linux client --socks-port <your_local_socks_port> --password <your_password> --server-host <your.hostname> --server-port <443_or_your_server_port>
```

`server`:

```
./magicalane-linux server --key <your_key.pem> --ca <your_ca.pem>  --port <443_or_your_server_port> --password <your_password>
```
