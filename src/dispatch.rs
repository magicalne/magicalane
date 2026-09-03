//! Server-side connection dispatch: tunnels reach special in-band
//! destinations (magic hostnames) that must not be resolved and connected
//! like normal targets, but handled by built-in services:
//!
//!   magicalane-dns:53   -> DNS module upstream relay (src/dns)
//!   magicalane-udp:1    -> UDP datagram relay (src/udp; framed flows)
//!
//! Everything else goes to the underlying connector (LocalConnector).

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    connector::{Connector, LocalConnector},
    dns::DnsRelayStream,
    socks5::proto::Addr,
    udp::UdpFramedStream,
};

/// Connection types the server can relay to.
pub enum Remote {
    Tcp(tokio::net::TcpStream),
    Dns(DnsRelayStream),
    Udp(UdpFramedStream),
}

impl AsyncRead for Remote {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Remote::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Remote::Dns(s) => Pin::new(s).poll_read(cx, buf),
            Remote::Udp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Remote {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, io::Error>> {
        match self.get_mut() {
            Remote::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Remote::Dns(s) => Pin::new(s).poll_write(cx, buf),
            Remote::Udp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        match self.get_mut() {
            Remote::Tcp(s) => Pin::new(s).poll_flush(cx),
            Remote::Dns(s) => Pin::new(s).poll_flush(cx),
            Remote::Udp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        match self.get_mut() {
            Remote::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Remote::Dns(s) => Pin::new(s).poll_shutdown(cx),
            Remote::Udp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Wraps the local connector and intercepts magic destinations.
#[derive(Clone)]
pub struct DispatchConnector {
    local: LocalConnector,
}

impl DispatchConnector {
    pub fn new() -> Self {
        Self {
            local: LocalConnector,
        }
    }
}

impl Default for DispatchConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl Connector for DispatchConnector {
    type Connection = Remote;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        match a {
            Addr::DomainName(ref host, _) if host.as_slice() == crate::dns::DNS_MAGIC_HOST => {
                Box::pin(async { Ok(Remote::Dns(DnsRelayStream::new())) })
            }
            Addr::DomainName(ref host, _) if host.as_slice() == crate::udp::UDP_MAGIC_HOST => {
                Box::pin(async { Ok(Remote::Udp(UdpFramedStream::new())) })
            }
            _ => {
                let mut local = self.local.clone();
                Box::pin(async move {
                    local.connect(a).await.map(Remote::Tcp)
                })
            }
        }
    }
}
