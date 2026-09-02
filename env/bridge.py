#!/usr/bin/env python3
"""Transparent-to-SOCKS5 bridge (tproxy stand-in).

Listens with IP_TRANSPARENT on TCP 7895. Packets TPROXY-redirected to this
port are accepted with their ORIGINAL destination visible via
getsockname(); the bridge forwards the flow through the local magicalane
socks5 server (127.0.0.1:1080).

This stands in for the future in-process `TransparentProxyConfig` listener:
it proves the full path app -> [transparent] -> socks5 -> transport -> server
without any proxy configuration on the app.

Linux only (IP_TRANSPARENT).
"""
import select
import socket
import sys
import threading

LISTEN_PORT = 7895
SOCKS_HOST, SOCKS_PORT = "127.0.0.1", 1080

try:
    IP_TRANSPARENT = socket.IP_TRANSPARENT
except AttributeError:
    IP_TRANSPARENT = 19  # Linux


def socks5_connect(dst_host: str, dst_port: int) -> socket.socket:
    s = socket.create_connection((SOCKS_HOST, SOCKS_PORT), timeout=10)
    s.settimeout(30)
    s.sendall(b"\x05\x01\x00")  # hello: no-auth
    resp = s.recv(2)
    if resp != b"\x05\x00":
        raise OSError(f"socks5 hello failed: {resp!r}")
    host = dst_host.encode("idna") if ":" not in dst_host else dst_host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + dst_port.to_bytes(2, "big")
    s.sendall(req)
    hdr = s.recv(4)
    if len(hdr) < 4 or hdr[1] != 0:
        raise OSError(f"socks5 connect failed: {hdr!r}")
    atyp = hdr[3]
    if atyp == 0x01:
        rest = s.recv(4 + 2)
    elif atyp == 0x03:
        n = s.recv(1)[0]
        rest = s.recv(n + 2)
    elif atyp == 0x04:
        rest = s.recv(16 + 2)
    else:
        raise OSError(f"bad atyp {atyp}")
    return s


def relay(a: socket.socket, b: socket.socket) -> None:
    pair = [(a, b), (b, a)]
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 120)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                other = b if s is a else a
                other.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def handle(c: socket.socket) -> None:
    try:
        dst = c.getsockname()  # original destination under TPROXY
        up = socks5_connect(dst[0], dst[1])
    except OSError as e:
        print(f"bridge: connect failed: {e}", file=sys.stderr, flush=True)
        try:
            c.close()
        except OSError:
            pass
        return
    c.settimeout(None)
    relay(c, up)


def main() -> None:
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.setsockopt(socket.IPPROTO_IP, IP_TRANSPARENT, 1)
    ls.bind(("0.0.0.0", LISTEN_PORT))
    ls.listen(128)
    print(f"bridge: transparent listener on :{LISTEN_PORT} -> socks5://{SOCKS_HOST}:{SOCKS_PORT}", flush=True)
    while True:
        c, _ = ls.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
