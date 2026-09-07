//! Client side of the TCP+TLS transport: one TLS connection per proxy
//! connection, authenticated with the shared password.

use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::future::BoxFuture;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

use crate::{
    connector::Connector,
    error::Result,
    load_private_cert,
    socks5::proto::Addr,
};

use super::ALPN_TCP;

/// A client-side transport stream: TLS-wrapped or plain TCP.
pub enum TcpTunnelStream {
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Plain(TcpStream),
}

impl AsyncRead for TcpTunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TcpTunnelStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            TcpTunnelStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TcpTunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, io::Error>> {
        match self.get_mut() {
            TcpTunnelStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            TcpTunnelStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        match self.get_mut() {
            TcpTunnelStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            TcpTunnelStream::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        match self.get_mut() {
            TcpTunnelStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            TcpTunnelStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub struct TcpConnector {
    remote: SocketAddr,
    server_name: String,
    tls: bool,
    tls_connector: Option<Arc<tokio_rustls::TlsConnector>>,
    passwd: Vec<u8>,
}

impl TcpConnector {
    /// Resolve `host` eagerly (startup, before interception rules exist)
    /// so runtime connects never need DNS — same contract as
    /// `KcpConnector::new`.
    pub fn new(
        host: &str,
        port: u16,
        cert_path: Option<PathBuf>,
        passwd: Vec<u8>,
        tls: bool,
    ) -> Result<Self> {
        use std::net::ToSocketAddrs;
        let mut addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
        // Prefer v4 first for determinism with the resolved server_ip
        // exceptions (quinn resolves v6-first; both families are exempted
        // anyway, but keep the primary consistent).
        addrs.sort_by_key(|a| !a.is_ipv4());
        let remote = *addrs
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
        let tls_connector = if tls {
            let mut roots = rustls::RootCertStore::empty();
            if let Some(path) = &cert_path {
                for cert in load_private_cert(path)? {
                    roots.add(cert)?;
                }
            }
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = ALPN_TCP.iter().map(|p| p.to_vec()).collect();
            let connector: tokio_rustls::TlsConnector = Arc::new(cfg).into();
            Some(Arc::new(connector))
        } else {
            None
        };
        Ok(Self {
            remote,
            server_name: host.to_string(),
            tls,
            tls_connector,
            passwd,
        })
    }
}

impl Clone for TcpConnector {
    fn clone(&self) -> Self {
        Self {
            remote: self.remote,
            server_name: self.server_name.clone(),
            tls: self.tls,
            tls_connector: self.tls_connector.clone(),
            passwd: self.passwd.clone(),
        }
    }
}

/// Total bound for one full connect (TCP + TLS + auth + target): a dead
/// or filtering middlebox must fail fast so health probes and failover
/// groups react instead of hanging relays.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

impl Connector for TcpConnector {
    type Connection = TcpTunnelStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        let remote = self.remote;
        let server_name = self.server_name.clone();
        let tls = self.tls;
        let tls_connector = self.tls_connector.clone();
        let passwd = self.passwd.clone();
        Box::pin(async move {
            tokio::time::timeout(CONNECT_TIMEOUT, async {
                let tcp = TcpStream::connect(remote).await?;
                tcp.set_nodelay(true).ok();
                let mut io = if tls {
                    let connector = tls_connector
                        .ok_or_else(|| io::Error::other("missing tls config"))?;
                    let dns_name = rustls::pki_types::ServerName::try_from(server_name.clone())
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad sni"))?;
                    TcpTunnelStream::Tls(Box::new(connector.connect(dns_name, tcp).await?))
                } else {
                    TcpTunnelStream::Plain(tcp)
                };
                // [len u8][password] -> status byte
                if passwd.len() > 255 {
                    return Err(io::Error::other("password too long"));
                }
                let mut hello = Vec::with_capacity(1 + passwd.len());
                hello.push(passwd.len() as u8);
                hello.extend_from_slice(&passwd);
                io.write_all(&hello).await?;
                io.flush().await?;
                let mut flag = [0u8; 1];
                io.read_exact(&mut flag).await?;
                if flag[0] != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "wrong password",
                    ));
                }
                // target Addr -> status byte
                let mut addr_buf = BytesMut::new();
                a.encode(&mut addr_buf);
                io.write_all(&addr_buf).await?;
                io.flush().await?;
                io.read_exact(&mut flag).await?;
                if flag[0] != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "remote refused",
                    ));
                }
                let io: TcpTunnelStream = io;
                Ok(io)
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp transport handshake timeout"))?
        })
    }
}
