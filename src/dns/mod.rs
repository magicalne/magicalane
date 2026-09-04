//! DNS module: interception + relay through the tunnel.
//!
//! Client side: a transparent UDP listener on `dns_port`; udp/53 packets
//! redirected by the rule manager land here. Each query is carried to the
//! server over a short-lived tunnel stream, resolved server-side against
//! the server's configured upstream, and the raw response is returned to
//! the original querier. No DNS leak: resolution happens at the server.
//!
//! Wire format on the tunnel stream (both directions):
//!   [u16 BE length][raw DNS message]

use std::os::unix::io::AsRawFd;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, BufMut, BytesMut};
use log::{debug, info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
    spawn,
    sync::Semaphore,
};

use crate::{
    connector::Connector,
    socks5::proto::Addr,
};

pub mod fakeip;
pub mod proto;

pub use fakeip::FakeIpMap;

/// AAAA-answer strategy for fakeip mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AaaaMode {
    /// Fake AAAA iff IPv6 interception is active (detected at startup).
    Auto,
    /// Always answer AAAA with fake v6 tokens.
    Fake,
    /// Always answer AAAA with NODATA (apps use the v4 token).
    Empty,
}

impl AaaaMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "fake" => Some(Self::Fake),
            "empty" => Some(Self::Empty),
            _ => None,
        }
    }
}

/// Magic address the dispatch connector recognizes on the server side.
pub const DNS_MAGIC_HOST: &[u8] = b"magicalane-dns";
pub const DNS_MAGIC_PORT: u16 = 53;

pub fn magic_addr() -> Addr {
    Addr::DomainName(DNS_MAGIC_HOST.to_vec(), DNS_MAGIC_PORT)
}

const MAX_DNS: usize = 4096;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound concurrent in-flight queries.
static INFLIGHT: Semaphore = Semaphore::const_new(256);

/// Bind the transparent DNS listener.
pub fn bind_client(port: u16) -> io::Result<std::sync::Arc<UdpSocket>> {
    const IP_TRANSPARENT: libc::c_int = 19;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_TRANSPARENT,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        warn!("dns: IP_TRANSPARENT failed: {}", io::Error::last_os_error());
    }
    // Bind to loopback: nat REDIRECT changes the destination to
    // 127.0.0.1:port, and the response must originate from 127.0.0.1
    // for conntrack to reverse-NAT it back to the original nameserver.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    socket.bind(&addr.into())?;
    let sock = std::sync::Arc::new(UdpSocket::from_std(socket.into())?);
    info!("dns interceptor listening on {addr}");
    Ok(sock)
}

/// v6 sibling: binds [::1] (ip6tables nat REDIRECT rewrites udp/53 dst
/// to ::1; the response must originate from ::1 for conntrack to
/// reverse-NAT it back to the original nameserver).
pub fn bind_client_v6(port: u16) -> io::Result<Arc<UdpSocket>> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port);
    socket.bind(&addr.into())?;
    let sock = Arc::new(UdpSocket::from_std(socket.into())?);
    info!("dns6 interceptor listening on {addr}");
    Ok(sock)
}

/// Serve DNS queries through the tunnel.
pub async fn serve_client<C, IO>(sock: std::sync::Arc<UdpSocket>, connector: C)
where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; 65536];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, from)) => {
                let query = buf[..n].to_vec();
                let connector = connector.clone();
                let sock = sock.clone();
                spawn(async move {
                    let _permit = INFLIGHT.acquire().await;
                    match query_once(connector, &query).await {
                        Ok(resp) => {
                            let _ = sock.send_to(&resp, from).await;
                        }
                        Err(err) => {
                            debug!("dns query from {from} failed: {err}");
                        }
                    }
                });
            }
            Err(err) => {
                warn!("dns recv error: {err}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

async fn query_once<C, IO>(mut connector: C, query: &[u8]) -> io::Result<Vec<u8>>
where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = tokio::time::timeout(QUERY_TIMEOUT, {
        let addr = magic_addr();
        async move { connector.connect(addr).await }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns connect timeout"))?
    .map_err(|e| io::Error::other(e.to_string()))?;

    let mut out = Vec::with_capacity(2 + query.len());
    out.put_u16(query.len() as u16);
    out.extend_from_slice(query);
    tokio::time::timeout(QUERY_TIMEOUT, stream.write_all(&out)).await??;
    tokio::time::timeout(QUERY_TIMEOUT, stream.flush()).await??;

    let mut hdr = [0u8; 2];
    tokio::time::timeout(QUERY_TIMEOUT, stream.read_exact(&mut hdr)).await??;
    let len = u16::from_be_bytes(hdr) as usize;
    if len > MAX_DNS {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "dns response too large"));
    }
    let mut resp = vec![0u8; len];
    tokio::time::timeout(QUERY_TIMEOUT, stream.read_exact(&mut resp)).await??;
    Ok(resp)
}

// ---------------------------------------------------------------- fakeip mode

/// Serve DNS in fakeip mode: every A query is answered LOCALLY with a
/// token from 198.18.0.0/15 (AAAA from fc00::/18 when enabled) — no DNS
/// query ever crosses the network for faked families. Queries we cannot
/// fake (MX/TXT/SRV/...) fall back to the tunnel relay so real answers
/// still arrive server-side.
pub async fn serve_client_fakeip<C, IO>(
    sock: Arc<UdpSocket>,
    map: Arc<FakeIpMap>,
    aaaa: AaaaMode,
    v6_intercept_active: bool,
    connector: C,
) where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; 65536];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, from)) => {
                let query = buf[..n].to_vec();
                let map = map.clone();
                let connector = connector.clone();
                let sock = sock.clone();
                spawn(async move {
                    let _permit = INFLIGHT.acquire().await;
                    let resp = answer_fakeip(map, aaaa, v6_intercept_active, connector, query).await;
                    if let Ok(resp) = resp {
                        let _ = sock.send_to(&resp, from).await;
                    } else if let Err(err) = resp {
                        debug!("fakeip query from {from} failed: {err}");
                    }
                });
            }
            Err(err) => {
                warn!("dns recv error: {err}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

/// Answer one query from the fake map; non-fakeable qtypes tunnel.
async fn answer_fakeip<C, IO>(
    map: Arc<FakeIpMap>,
    aaaa: AaaaMode,
    v6_intercept_active: bool,
    connector: C,
    query: Vec<u8>,
) -> io::Result<Vec<u8>>
where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Some(q) = proto::parse_query(&query) else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unparseable dns query"));
    };
    match q.qtype {
        proto::QTYPE_A => {
            let ip = map.assign_v4(&q.domain);
            debug!("fakeip A {} -> {ip}", q.domain);
            Ok(proto::build_a_response(&q, ip))
        }
        proto::QTYPE_AAAA => {
            let fake_v6 = match aaaa {
                AaaaMode::Fake => true,
                AaaaMode::Empty => false,
                AaaaMode::Auto => v6_intercept_active,
            };
            if fake_v6 {
                let ip = map.assign_v6(&q.domain);
                debug!("fakeip AAAA {} -> {ip}", q.domain);
                Ok(proto::build_aaaa_response(&q, ip))
            } else {
                // NODATA: app falls back to the A token.
                Ok(proto::build_empty_response(&q))
            }
        }
        proto::QTYPE_PTR => Ok(proto::build_nxdomain(&q)),
        _ => {
            // MX/TXT/SRV/… need real answers: relay through the tunnel.
            debug!("fakeip passthrough qtype {} {}", q.qtype, q.domain);
            query_once(connector, &query).await
        }
    }
}

// ---------------------------------------------------------------- server side

/// First nameserver in /etc/resolv.conf (fallback: 127.0.0.1).
fn upstream() -> SocketAddr {
    let default = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return default;
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            let ip = rest.trim();
            if let Ok(addr) = ip.parse::<IpAddr>() {
                return SocketAddr::new(addr, 53);
            }
        }
    }
    default
}

/// Server-side DNS relay: a "connection" the dispatch connector hands to
/// the relay machinery. Reads u16-framed queries from the tunnel, resolves
/// them against the local upstream, and makes responses readable.
pub struct DnsRelayStream {
    /// Framed query bytes accumulated from the tunnel (write side).
    wbuf: BytesMut,
    /// Response bytes ready for the relay to read.
    rbuf: BytesMut,
    /// In-flight upstream exchange (query sent, awaiting response).
    pending: Option<tokio::task::JoinHandle<io::Result<Vec<u8>>>>,
    upstream: SocketAddr,
}

impl DnsRelayStream {
    pub fn new() -> Self {
        Self {
            wbuf: BytesMut::new(),
            rbuf: BytesMut::new(),
            pending: None,
            upstream: upstream(),
        }
    }

    fn start_exchange(&mut self, query: &[u8]) {
        let upstream = self.upstream;
        let query = query.to_vec();
        self.pending = Some(spawn(async move {
            let sock = UdpSocket::bind(("0.0.0.0", 0)).await?;
            sock.connect(upstream).await?;
            sock.send(&query).await?;
            let mut buf = vec![0u8; 65536];
            let n = tokio::time::timeout(QUERY_TIMEOUT, sock.recv(&mut buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns upstream timeout"))??;
            buf.truncate(n);
            Ok(buf)
        }));
    }
}

impl Default for DnsRelayStream {
    fn default() -> Self {
        Self::new()
    }
}

impl tokio::io::AsyncRead for DnsRelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.rbuf.has_remaining() {
                let n = self.rbuf.remaining().min(buf.remaining());
                let data = self.rbuf.split_to(n);
                buf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            match self.pending.as_mut() {
                Some(handle) => {
                    // JoinHandle is Unpin; poll in place so it stays stored.
                    let ready =
                        std::future::Future::poll(std::pin::Pin::new(handle), cx);
                    match ready {
                        std::task::Poll::Ready(Ok(Ok(resp))) => {
                            self.pending = None;
                            self.rbuf.put_u16(resp.len() as u16);
                            self.rbuf.extend_from_slice(&resp);
                        }
                        std::task::Poll::Ready(Ok(Err(err))) => {
                            self.pending = None;
                            return Poll::Ready(Err(err));
                        }
                        std::task::Poll::Ready(Err(err)) => {
                            self.pending = None;
                            return Poll::Ready(Err(io::Error::other(err)));
                        }
                        std::task::Poll::Pending => return Poll::Pending,
                    }
                }
                None => return Poll::Pending,
            }
        }
    }
}

impl tokio::io::AsyncWrite for DnsRelayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.wbuf.extend_from_slice(buf);
        // complete frames -> upstream exchanges
        while this.wbuf.len() >= 2 {
            let len = u16::from_be_bytes([this.wbuf[0], this.wbuf[1]]) as usize;
            if this.wbuf.len() < 2 + len {
                break;
            }
            let mut frame = this.wbuf.split_to(2 + len);
            frame.advance(2);
            if this.pending.is_none() {
                this.start_exchange(&frame);
            } else {
                // queries are one-per-stream in practice; drop extras
                log::debug!("dns: extra query on stream ignored");
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
