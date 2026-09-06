//! HTTP proxy inbound (mixed-port companion to SOCKS5).
//!
//! Handles `CONNECT host:port` (tunnel, then bidirectional relay) and
//! absolute-form requests (`GET http://host/path ...`) — the head is
//! forwarded verbatim upstream and the rest of the exchange streams
//! through untouched.

use std::io;

use bytes::BytesMut;
use log::{debug, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    connector::Connector,
    proxy::Proxy,
    socks5::proto::Addr,
};

const MAX_HEAD: usize = 16 * 1024;

/// Serve one HTTP-proxy connection to completion. `users`: when
/// non-empty, Proxy-Authorization (Basic) is required.
pub async fn handle<C, IO>(
    mut stream: TcpStream,
    mut connector: C,
    users: Vec<(String, String)>,
    bandwidth: usize,
) -> io::Result<()>
where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = BytesMut::new();
    // Read until end of the request head.
    loop {
        let mut tmp = vec![0u8; 2048];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "client closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > MAX_HEAD {
            break;
        }
    }
    let head = buf.split_to(buf.len()).freeze();
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.is_empty() || target.is_empty() {
        write_simple(&mut stream, 400, "Bad Request").await?;
        return Ok(());
    }

    // RFC 7235 Basic auth (base64 user:pass) when users are configured.
    if !users.is_empty() {
        let ok = text
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:"))
            .and_then(|l| l.split_once(' '))
            .map(|(_, v)| {
                let mut it = v.trim().splitn(2, ' ');
                let (scheme, b64) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
                if !scheme.eq_ignore_ascii_case("basic") {
                    return false;
                }
                use base64::Engine as _;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .ok()
                    .and_then(|v| String::from_utf8(v).ok())
                    .unwrap_or_default();
                let Some((u, p)) = decoded.split_once(':') else { return false };
                users.iter().any(|(uu, pp)| uu == u && pp == p)
            })
            .unwrap_or(false);
        if !ok {
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"magicalane\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            stream.flush().await?;
            return Ok(());
        }
    }

    if method == "CONNECT" {
        let addr = match parse_host_port(target, 443) {
            Some((host, port)) => Addr::DomainName(host.into_bytes(), port),
            None => {
                write_simple(&mut stream, 400, "Bad Request").await?;
                return Ok(());
            }
        };
        debug!("httpin: CONNECT {addr:?}");
        let remote = match connector.connect(addr.clone()).await {
            Ok(r) => r,
            Err(e) => {
                debug!("httpin: connect {addr:?} failed: {e}");
                write_simple(&mut stream, 502, "Bad Gateway").await?;
                return Ok(());
            }
        };
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        stream.flush().await?;
        let proxy = Proxy::new(stream, remote, bandwidth);
        let _ = std::pin::pin!(proxy).await;
        return Ok(());
    }

    // Absolute-form: http://host[:port]/path
    let (host, port) = match target.split_once("://") {
        Some((_, rest)) => {
            let authority = rest.split('/').next().unwrap_or("");
            let default = if target.starts_with("https://") { 443 } else { 80 };
            match parse_host_port(authority, default) {
                Some((h, p)) => (h, p),
                None => {
                    write_simple(&mut stream, 400, "Bad Request").await?;
                    return Ok(());
                }
            }
        }
        None => {
            // Origin-form needs a Host header.
            let host_header = text
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string());
            match host_header {
                Some(h) => (h, 80),
                None => {
                    write_simple(&mut stream, 400, "Bad Request").await?;
                    return Ok(());
                }
            }
        }
    };
    let addr = Addr::DomainName(host.into_bytes(), port);
    debug!("httpin: {method} -> {addr:?}");
    let mut remote = match connector.connect(addr).await {
        Ok(r) => r,
        Err(e) => {
            warn!("httpin: upstream connect failed: {e}");
            write_simple(&mut stream, 502, "Bad Gateway").await?;
            return Ok(());
        }
    };
    // Rewrite absolute-form to origin-form: upstreams expect
    // "GET /path HTTP/1.1", not "GET http://host/path HTTP/1.1".
    let path = match target.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        },
        None => target,
    };
    let version = parts.next().unwrap_or("HTTP/1.1");
    let new_line = format!("{method} {path} {version}\r\n");
    let mut out = new_line.into_bytes();
    // everything after the original request line
    if let Some(pos) = head.iter().position(|&b| b == b'\n') {
        out.extend_from_slice(&head[pos + 1..]);
    }
    remote.write_all(&out).await?;
    remote.flush().await?;
    let proxy = Proxy::new(stream, remote, bandwidth);
    let _ = std::pin::pin!(proxy).await;
    Ok(())
}

/// `host:port` / `host` (v6 `[..]:port`) -> (host, port); None on junk.
fn parse_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        let (host, port) = rest.split_once(']')?;
        let port = match port.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && !p.is_empty() => {
            let port = match p.parse() {
                Ok(p) => p,
                Err(_) => return None,
            };
            Some((h.to_string(), port))
        }
        _ => Some((s.to_string(), default_port)),
    }
}

async fn write_simple(stream: &mut TcpStream, code: u16, reason: &str) -> io::Result<()> {
    let body = format!("{code} {reason}\n");
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port_forms() {
        assert_eq!(parse_host_port("example.com:8080", 80), Some(("example.com".into(), 8080)));
        assert_eq!(parse_host_port("example.com", 80), Some(("example.com".into(), 80)));
        assert_eq!(
            parse_host_port("[2001:db8::1]:443", 80),
            Some(("2001:db8::1".into(), 443))
        );
        assert_eq!(parse_host_port("[2001:db8::2]", 80), Some(("2001:db8::2".into(), 80)));
        assert_eq!(parse_host_port("", 80), None);
        assert_eq!(parse_host_port("host:notaport", 80), None);
    }
}
