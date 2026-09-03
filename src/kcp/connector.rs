use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
};

use bytes::BytesMut;
use futures::future::BoxFuture;
use log::trace;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    spawn,
    sync::mpsc,
};

use crate::{
    config::KcpTuning,
    connector::Connector,
    error::Result,
    kcp::session::{self, KcpStream},
    socks5::proto::Addr,
};

use rand::Rng;

use super::ALPN_KCP;

/// Client-side KCP transport connector: one KCP conversation (with TLS)
/// per relay request.
#[derive(Clone)]
pub struct KcpConnector {
    remote: SocketAddr,
    server_name: String,
    tls: Option<Arc<tokio_rustls::TlsConnector>>,
    passwd: Vec<u8>,
    tuning: KcpTuning,
}

impl KcpConnector {
    pub fn new(
        server_name: String,
        port: u16,
        ca_path: Option<PathBuf>,
        passwd: Vec<u8>,
        tls: bool,
        tuning: Option<KcpTuning>,
    ) -> Result<Self> {
        let remote = (server_name.as_str(), port)
            .to_socket_addrs()?
            .find(|a| a.is_ipv4())
            .ok_or(crate::error::Error::UnknownRemoteHost)?;
        let connector = if tls {
            let mut roots = rustls::RootCertStore::empty();
            if let Some(path) = &ca_path {
                for cert in crate::load_private_cert(path)? {
                    roots.add(cert)?;
                }
            }
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = ALPN_KCP.iter().map(|p| p.to_vec()).collect();
            Some(Arc::new(tokio_rustls::TlsConnector::from(Arc::new(cfg))))
        } else {
            None
        };
        Ok(Self {
            remote,
            server_name,
            tls: connector,
            passwd,
            tuning: tuning.unwrap_or_default(),
        })
    }
}

impl Connector for KcpConnector {
    type Connection = EitherKcpStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        let remote = self.remote;
        let server_name = self.server_name.clone();
        let tls = self.tls.clone();
        let passwd = self.passwd.clone();
        let tuning = self.tuning.clone();
        Box::pin(async move {
            connect_kcp(remote, server_name, tls, &passwd, &a, &tuning)
                .await
                .map_err(|e| io::Error::other(e.to_string()))
        })
    }
}

/// TLS-wrapped or plain KCP client stream.
pub enum EitherKcpStream {
    Tls(Box<tokio_rustls::client::TlsStream<KcpStream>>),
    Plain(KcpStream),
}

impl AsyncRead for EitherKcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            EitherKcpStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            EitherKcpStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for EitherKcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, io::Error>> {
        match self.get_mut() {
            EitherKcpStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            EitherKcpStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), io::Error>> {
        match self.get_mut() {
            EitherKcpStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            EitherKcpStream::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), io::Error>> {
        match self.get_mut() {
            EitherKcpStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            EitherKcpStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Establish one KCP+TLS session and perform the proxy handshake:
/// `[len][password]` -> flag, `[Addr]` -> flag; then the caller owns the relay.
async fn connect_kcp(
    remote: SocketAddr,
    server_name: String,
    tls: Option<Arc<tokio_rustls::TlsConnector>>,
    passwd: &[u8],
    addr: &Addr,
    tuning: &KcpTuning,
) -> Result<EitherKcpStream> {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = Arc::new(UdpSocket::from_std(std_socket)?);

    let conv: u32 = { rand::thread_rng().gen_range(1, u32::MAX) };
    let shared = Arc::new(session::Shared::new(conv, tuning));
    let (tx, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(256);

    // Receiver: only accept datagrams from the server.
    let sock = socket.clone();
    spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if from != remote {
                continue;
            }
            if tx.send((from, buf[..n].to_vec())).await.is_err() {
                break;
            }
        }
    });

    let stream = KcpStream::new(shared.clone());
    spawn(session::drive_session(shared, socket, remote, rx, || {}));

    // The TLS ClientHello itself creates the session on the server.
    let mut io = match tls {
        Some(connector) => {
            let name = rustls_pki_types::ServerName::try_from(server_name.clone())?;
            let tls = Box::new(connector.connect(name, stream).await?);
            EitherKcpStream::Tls(tls)
        }
        None => EitherKcpStream::Plain(stream),
    };

    // Authentication: [len u8][password] -> flag.
    let mut hello = Vec::with_capacity(1 + passwd.len());
    hello.push(passwd.len() as u8);
    hello.extend_from_slice(passwd);
    io.write_all(&hello).await?;
    io.flush().await?;
    let mut flag = [0u8; 1];
    io.read_exact(&mut flag).await?;
    if flag[0] != 0 {
        return Err(crate::error::Error::WrongPassword);
    }
    trace!("kcp password accepted");

    // Request the relay.
    let mut addr_buf = BytesMut::new();
    addr.encode(&mut addr_buf);
    io.write_all(&addr_buf).await?;
    io.flush().await?;
    let mut flag = [0u8; 1];
    io.read_exact(&mut flag).await?;
    if flag[0] != 0 {
        return Err(crate::error::Error::OpenRemoteAddrError);
    }
    trace!("kcp relay accepted");
    Ok(io)
}
