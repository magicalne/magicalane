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

/// Server-side connector to real destinations. With a resolver, domain
/// destinations resolve through the layered engine (cache -> hosts ->
/// racing `[dns] upstream`); without one, the system resolver is used.
#[derive(Clone, Default)]
pub struct LocalConnector {
    resolver: Option<std::sync::Arc<crate::dns::resolve::Resolver>>,
}

impl LocalConnector {
    pub fn new(resolver: std::sync::Arc<crate::dns::resolve::Resolver>) -> Self {
        Self { resolver: Some(resolver) }
    }
}

impl Connector for LocalConnector {
    type Connection = TcpStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            match a {
                Addr::SocketAddr(addr) => TcpStream::connect(addr).await,
                Addr::DomainName(host, port) => {
                    let host = String::from_utf8_lossy(&host).into_owned();
                    match resolver {
                        Some(r) => {
                            let addrs = r.resolve(&host, port).await?;
                            connect_first(&addrs).await
                        }
                        None => TcpStream::connect((host.as_str(), port)).await,
                    }
                }
            }
        })
    }
}

/// Try addresses in order; first success wins.
async fn connect_first(addrs: &[std::net::SocketAddr]) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses");
    for a in addrs {
        match TcpStream::connect(a).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Direct-route connector for the split-routing client: resolves the
/// domain LOCALLY (optional explicit resolver; system resolver by
/// default) and connects with a dual-stack socket stamped with
/// SO_MARK_DIRECT so the interception rules let it pass. The local
/// resolution is what gives direct-routed domains their correct
/// in-country CDN affinity.
#[derive(Clone)]
pub struct DirectConnector {
    /// Layered resolver: cache -> /etc/hosts -> racing upstream probes.
    /// Upstream sockets are SO_MARK'd so interception rules pass them.
    resolver: std::sync::Arc<crate::dns::resolve::Resolver>,
}

impl DirectConnector {
    /// `resolver`: configured list (single value or racing list); None
    /// uses every nameserver in /etc/resolv.conf.
    pub fn new(resolver: Option<Vec<std::net::SocketAddr>>) -> Self {
        let list = match resolver {
            Some(l) if !l.is_empty() => l,
            _ => crate::dns::resolve::nameservers(),
        };
        Self {
            resolver: std::sync::Arc::new(crate::dns::resolve::Resolver::new(list, None)),
        }
    }

    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
        self.resolver.resolve(host, port).await
    }
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
        let resolver = self.resolver.clone();
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
