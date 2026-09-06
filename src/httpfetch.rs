//! Minimal HTTP(S) GET client for rule providers.
//!
//! Streams over ANY AsyncRead+AsyncWrite transport (tunnel or marked
//! direct socket); TLS via rustls + webpki roots for https URLs.
//! Supports Content-Length, chunked, and connection-close bodies.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::socks5::proto::Addr;

pub struct Url<'a> {
    pub tls: bool,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
}

pub fn parse_url(url: &str) -> io::Result<Url<'_>> {
    let (tls, rest) = match url.split_once("://") {
        Some(("http", r)) => (false, r),
        Some(("https", r)) => (true, r),
        _ => return Err(io::Error::other("provider url: only http/https")),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let Some((h, p)) = r.split_once(']') else {
            return Err(io::Error::other("provider url: bad v6 authority"));
        };
        let port = match p.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| io::Error::other("provider url: bad port"))?,
            None => default_port,
        };
        (h, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => {
                let port = p.parse().map_err(|_| io::Error::other("provider url: bad port"))?;
                (h, port)
            }
            _ => (authority, default_port),
        }
    };
    Ok(Url { tls, host, port, path })
}

pub fn url_addr(u: &Url<'_>) -> Addr {
    Addr::DomainName(u.host.as_bytes().to_vec(), u.port)
}

/// Perform a GET over an established stream; returns the body.
pub async fn fetch_over<S>(mut s: S, u: &Url<'_>) -> io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: magicalane\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        u.path, u.host
    );
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;

    let mut raw = Vec::with_capacity(64 * 1024);
    let mut tmp = [0u8; 8192];
    // Read at least the full head.
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&tmp[..n]);
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            // keep reading only if more body is expected (handled below)
            let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            if let Some(len) = content_length(&raw[..head_end]) {
                if raw.len() >= head_end + len {
                    break;
                }
            }
            // chunked / close-delimited: read to EOF
        }
    }
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| io::Error::other("provider fetch: truncated response"))?;
    let head_text = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let status = head_text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!("provider fetch: HTTP {status}")));
    }
    let chunked = head_text
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    let bounded = content_length(head_text.as_bytes()).is_some();
    let body = raw.split_off(head_end);
    if chunked {
        decode_chunked(body, &mut s).await
    } else if bounded {
        Ok(body)
    } else {
        // Close-delimited (Connection: close): keep draining.
        let mut out = body;
        loop {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        Ok(out)
    }
}

fn content_length(head: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(head);
    text.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
}

async fn decode_chunked<S>(mut body: Vec<u8>, s: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    // We always send `Connection: close`, so drain to EOF and decode
    // the complete buffer (no partial-chunk state machine needed).
    let mut tmp = [0u8; 8192];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0usize;
    while let Some(line_end) = body[pos..].windows(2).position(|w| w == b"\r\n") {
        let size_str = String::from_utf8_lossy(&body[pos..pos + line_end]);
        let size_str = size_str.split(';').next().unwrap_or("").trim().to_string();
        pos += line_end + 2;
        let Ok(size) = usize::from_str_radix(&size_str, 16) else {
            return Err(io::Error::other("provider fetch: bad chunk size"));
        };
        if size == 0 {
            break;
        }
        if pos + size > body.len() {
            return Err(io::Error::other("provider fetch: truncated chunk"));
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2; // data + CRLF
    }
    Ok(out)
}

/// TLS-wrap a stream for https URLs (webpki roots).
pub async fn tls_wrap<S>(s: S, host: &str) -> io::Result<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::other(e.to_string()))?;
    connector
        .connect(name, s)
        .await
        .map_err(|e| io::Error::other(e.to_string()))
}
