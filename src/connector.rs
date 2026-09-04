use std::io;

use futures::future::BoxFuture;
use log::{debug, warn};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::{
    quic::{self, stream::QuicStream},
    socks5::proto::Addr,
};

/// SO_MARK value stamped on direct-connector sockets so the mangle
/// chains can exclude our own outbound traffic from re-interception.
pub const SO_MARK_DIRECT: libc::c_int = 0x2A2;

pub trait Connector: Clone {
    type Connection: AsyncRead + AsyncWrite + Unpin;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>>;
}

#[derive(Clone)]
pub struct LocalConnector;

impl Connector for LocalConnector {
    type Connection = TcpStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        match a {
            Addr::SocketAddr(addr) => Box::pin(TcpStream::connect(addr)),
            Addr::DomainName(host, port) => {
                let addr = (String::from_utf8(host).unwrap(), port);
                Box::pin(TcpStream::connect(addr))
            }
        }
    }
}

/// Direct-route connector for the split-routing client: resolves the
/// domain LOCALLY (optional explicit resolver; system resolver by
/// default) and connects with a dual-stack socket stamped with
/// SO_MARK_DIRECT so the interception rules let it pass. The local
/// resolution is what gives direct-routed domains their correct
/// in-country CDN affinity.
#[derive(Clone)]
pub struct DirectConnector {
    /// Optional explicit upstream resolver for domain lookups.
    resolver: Option<std::net::SocketAddr>,
}

impl DirectConnector {
    pub fn new(resolver: Option<std::net::SocketAddr>) -> Self {
        Self { resolver }
    }

    /// Effective resolver: configured one, else the first nameserver in
    /// /etc/resolv.conf (the client's own resolver — real answers, and
    /// the rules exempt it from the fake-IP redirect).
    pub fn effective_resolver(&self) -> Option<std::net::SocketAddr> {
        self.resolver.or_else(system_resolver)
    }

    /// Resolve `host:port` locally via the marked DNS probe (search
    /// domains from resolv.conf applied, glibc-style: bare name first,
    /// then name+search suffix until an answer). NEVER falls back to
    /// plain getaddrinfo: an unmarked query would be answered by our
    /// own fake-IP layer and blackhole the direct path.
    pub async fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
        let resolver = self
            .effective_resolver()
            .ok_or_else(|| io::Error::other("direct: no resolver available"))?;
        resolve_via(host, resolver).await
    }
}

/// First nameserver from /etc/resolv.conf (the client's own resolver).
fn system_resolver() -> Option<std::net::SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("nameserver") else {
            continue;
        };
        if let Ok(addr) = rest.trim().parse::<std::net::IpAddr>() {
            return Some(std::net::SocketAddr::new(addr, 53));
        }
    }
    None
}

/// SO_MARK via raw setsockopt (avoids socket2's "all" feature).
fn set_socket_mark(socket: &socket2::Socket, mark: libc::c_int) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl Connector for DirectConnector {
    type Connection = TcpStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        let resolver = self.resolver;
        Box::pin(async move {
            match a {
                Addr::SocketAddr(addr) => connect_marked(&[addr]).await,
                Addr::DomainName(host, port) => {
                    let host = String::from_utf8_lossy(&host).into_owned();
                    let this = DirectConnector { resolver };
                    let addrs = this.resolve(&host, port).await?;
                    if addrs.is_empty() {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "no addresses"));
                    }
                    // Probe results carry port 0; stamp the real target port.
                    let addrs: Vec<_> = addrs
                        .into_iter()
                        .map(|a| std::net::SocketAddr::new(a.ip(), port))
                        .collect();
                    debug!("direct: {host}:{port} -> {addrs:?}");
                    connect_marked(&addrs).await
                }
            }
        })
    }
}

/// Connect to the first reachable address; socket carries SO_MARK_DIRECT.
async fn connect_marked(addrs: &[std::net::SocketAddr]) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses to try");
    for addr in addrs {
        match tcp_stream_marked(*addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// TcpStream::connect equivalent with SO_MARK set before connect(2).
/// Handles the EINPROGRESS dance for non-blocking connects.
async fn tcp_stream_marked(addr: std::net::SocketAddr) -> io::Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::time::Duration;
    let domain = match addr {
        std::net::SocketAddr::V4(_) => Domain::IPV4,
        std::net::SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if let Err(e) = set_socket_mark(&socket, SO_MARK_DIRECT) {
        warn!("direct: SO_MARK failed (routing may loop): {e}");
    }
    socket.set_nonblocking(true)?;
    socket.set_keepalive(true)?;
    match socket.connect(&addr.into()) {
        Ok(()) => Ok(TcpStream::from_std(socket.into())?),
        Err(e)
            if e.raw_os_error() == Some(libc::EINPROGRESS)
                || e.kind() == io::ErrorKind::WouldBlock =>
        {
            // EINPROGRESS: wait for the socket to become writable.
            let stream = TcpStream::from_std(socket.into())?;
            let stream = stream;
            tokio::time::timeout(Duration::from_secs(10), stream.writable())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct connect timeout"))??;
            if let Some(err) = stream.take_error()? {
                return Err(err);
            }
            Ok(stream)
        }
        Err(e) => Err(e),
    }
}

/// Search domains from /etc/resolv.conf ("search" or "domain" lines).
fn search_domains() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("search").or_else(|| line.strip_prefix("domain")) {
                for d in rest.split_whitespace() {
                    if !d.is_empty() {
                        out.push(d.trim_end_matches('.').to_string());
                    }
                }
            }
        }
    }
    out
}

/// Resolve `host` via an explicit UDP resolver: bare name first, then
/// search-domain candidates (glibc order). Probes are SO_MARK_DIRECT'd
/// so the interception rules pass them through to the real resolver.
async fn resolve_via(host: &str, resolver: std::net::SocketAddr) -> io::Result<Vec<std::net::SocketAddr>> {
    let host = host.trim_end_matches('.');
    let mut candidates = vec![host.to_string()];
    for suffix in search_domains() {
        candidates.push(format!("{host}.{suffix}"));
    }
    let mut last_err: Option<io::Error> = None;
    for name in candidates {
        match resolve_name_via(&name, resolver).await {
            Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
            Ok(_) => continue, // NODATA/NXDOMAIN: try next candidate
            Err(e) => last_err = Some(e), // timeouts etc: keep trying
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no resolution")))
}

async fn resolve_name_via(host: &str, resolver: std::net::SocketAddr) -> io::Result<Vec<std::net::SocketAddr>> {
    // Query A first; if empty, try AAAA. IDs are fixed (probe, not cache).
    let mut out = Vec::new();
    for qtype in [crate::dns::proto::QTYPE_A, crate::dns::proto::QTYPE_AAAA] {
        let bind: std::net::SocketAddr = match resolver {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        // Marked probe: exempt from the nat REDIRECT so it reaches the
        // real resolver instead of our fake-IP layer.
        let sock = udp_socket_marked(bind).await?;
        sock.connect(resolver).await?;
        let query = build_probe_query(host, qtype);
        sock.send(&query).await?;
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct_dns timeout"))??;
        collect_a_records(&buf[..n], qtype, &mut out);
        if !out.is_empty() {
            break;
        }
    }
    if out.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "resolver returned no addresses"));
    }
    Ok(out)
}

/// Marked UDP socket (SO_MARK_DIRECT) for direct-path DNS probes.
pub async fn udp_socket_marked(bind: std::net::SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match bind {
        std::net::SocketAddr::V4(_) => Domain::IPV4,
        std::net::SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = set_socket_mark(&socket, SO_MARK_DIRECT);
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

fn build_probe_query(host: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

/// Extract A/AAAA rdata from a response (skip name via pointer/labels).
fn collect_a_records(resp: &[u8], qtype: u16, out: &mut Vec<std::net::SocketAddr>) {
    let _ = qtype;
    if resp.len() < 12 {
        return;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    // Skip question section.
    let _pos = 12usize;
    let mut rest = resp;
    {
        let mut r = rest;
        // qname
        loop {
            let Some(&len) = r.first() else { return };
            if len == 0 {
                r = &r[1..];
                break;
            }
            if len & 0xC0 == 0xC0 {
                r = &r[2..];
                break;
            }
            if r.len() < 1 + len as usize {
                return;
            }
            r = &r[1 + len as usize..];
        }
        if r.len() < 4 {
            return;
        }
        rest = &r[4..];
    }
    let port = 0u16; // filled by caller semantics; we only collect ips
    for _ in 0..ancount {
        // answer name (pointer or labels)
        let mut r = rest;
        loop {
            let Some(&len) = r.first() else { return };
            if len & 0xC0 == 0xC0 {
                r = &r[2..];
                break;
            }
            if len == 0 {
                r = &r[1..];
                break;
            }
            if r.len() < 1 + len as usize {
                return;
            }
            r = &r[1 + len as usize..];
        }
        if r.len() < 10 {
            return;
        }
        let rtype = u16::from_be_bytes([r[0], r[1]]);
        let rdlen = u16::from_be_bytes([r[8], r[9]]) as usize;
        let rdata = &r[10..10 + rdlen.min(r.len().saturating_sub(10))];
        match rtype {
            1 if rdata.len() == 4 => {
                let ip = std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                out.push(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port));
            }
            28 if rdata.len() == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                out.push(std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)),
                    port,
                ));
            }
            _ => {}
        }
        rest = &r[10 + rdlen..];
    }
}

#[derive(Clone)]
pub struct QuicConnector {
    quic_client: quic::client::ClientActorHndler,
}

impl QuicConnector {
    pub fn new(quic_client: quic::client::ClientActorHndler) -> Self {
        Self { quic_client }
    }
}

impl Connector for QuicConnector {
    type Connection = QuicStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        let client = self.quic_client.clone();
        let stream = client.open_bi(a);
        Box::pin(stream)
    }
}
