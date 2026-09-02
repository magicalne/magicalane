use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
};

use kcp::KCP_OVERHEAD;
use log::{debug, info, trace};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    spawn,
    sync::mpsc,
};

use crate::{
    connector::Connector, error::Result, load_private_cert, load_private_key,
    quic::server::stream::Stream,
};

use super::{
    ALPN_KCP,
    session::{self, KcpStream},
};

type Route = Arc<StdMutex<HashMap<u32, mpsc::Sender<(SocketAddr, Vec<u8>)>>>>;

/// Either a TLS-wrapped or a plain KCP session stream.
enum SessionIo {
    Tls(Box<tokio_rustls::server::TlsStream<KcpStream>>),
    Plain(KcpStream),
}

impl AsyncRead for SessionIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // All variants are Unpin.
        match self.get_mut() {
            SessionIo::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            SessionIo::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SessionIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        match self.get_mut() {
            SessionIo::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            SessionIo::Plain(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            SessionIo::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            SessionIo::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            SessionIo::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            SessionIo::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// KCP transport server: one UDP socket, sessions dispatched by conv id.
pub struct Server<C> {
    connector: C,
    tls: Option<tokio_rustls::TlsAcceptor>,
    passwd: Vec<u8>,
    bandwidth: usize,
    socket: Arc<UdpSocket>,
    routes: Route,
}

impl<C> Server<C> {
    /// `tls = false` disables the TLS layer (plaintext KCP, e.g. for
    /// debugging or packet capture); password authentication still applies.
    pub fn new(
        connector: C,
        key_cert: (PathBuf, PathBuf),
        port: u16,
        passwd: String,
        bandwidth: usize,
        tls: bool,
    ) -> Result<Self> {
        let acceptor = if tls {
            let (key, cert) = key_cert;
            info!("kcp tls key: {:?}, cert: {:?}", &key, &cert);
            let key = load_private_key(key.as_path())?;
            let chain = load_private_cert(cert.as_path())?;
            let mut cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)?;
            cfg.alpn_protocols = ALPN_KCP.iter().map(|p| p.to_vec()).collect();
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
        } else {
            None
        };
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        info!("KCP server bind: {:?}", &addr);
        socket.bind(&addr.into())?;
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket.into())?);
        Ok(Self {
            connector,
            tls: acceptor,
            passwd: passwd.into_bytes(),
            bandwidth,
            socket,
            routes: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    /// The bound UDP address (port is 0-assigned when configured with port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl<C, IO> Server<C>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
    C: Connector<Connection = IO> + Send + 'static,
{
    pub async fn run(&mut self) -> Result<()> {
        let socket = self.socket.clone();
        let routes = self.routes.clone();
        let acceptor = self.tls.clone();
        let connector = self.connector.clone();
        let passwd = self.passwd.clone();
        let bandwidth = self.bandwidth;

        // Dispatch datagrams by conv to session tasks, creating sessions lazily.
        spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if n < KCP_OVERHEAD {
                            continue;
                        }
                        let conv = kcp::get_conv(&buf[..n]);
                        let sender = routes.lock().unwrap().get(&conv).cloned();
                        match sender {
                            Some(tx) => {
                                if tx.try_send((from, buf[..n].to_vec())).is_err() {
                                    routes.lock().unwrap().remove(&conv);
                                }
                            }
                            None => {
                                let (tx, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(256);
                                routes.lock().unwrap().insert(conv, tx);
                                let shared = Arc::new(session::Shared::new(conv));
                                let stream = KcpStream::new(shared.clone());
                                let sock = socket.clone();
                                let rts = routes.clone();
                                spawn(session::drive_session(shared, sock, from, rx, move || {
                                    rts.lock().unwrap().remove(&conv);
                                }));
                                let acc = acceptor.clone();
                                let con = connector.clone();
                                let pw = passwd.clone();
                                spawn(handle_session(stream, acc, con, pw, bandwidth));
                            }
                        }
                    }
                    Err(err) => {
                        debug!("kcp listener recv error: {:?}", err);
                    }
                }
            }
        });
        futures::future::pending::<()>().await;
        Ok(())
    }
}

async fn handle_session<IO, C>(
    stream: KcpStream,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    connector: C,
    passwd: Vec<u8>,
    bandwidth: usize,
) where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
    C: Connector<Connection = IO> + Send + 'static,
{
    static HS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let _ = HS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut io = match acceptor {
        Some(acceptor) => match acceptor.accept(stream).await {
            Ok(tls) => SessionIo::Tls(Box::new(tls)),
            Err(err) => {
                trace!("kcp tls accept error: {:?}", err);
                return;
            }
        },
        None => SessionIo::Plain(stream),
    };
    // Authentication: [len u8][password]
    let plen = match io.read_u8().await {
        Ok(n) => n as usize,
        Err(err) => {
            trace!("kcp auth read error: {:?}", err);
            return;
        }
    };
    let mut got = vec![0u8; plen];
    if io.read_exact(&mut got).await.is_err() {
        return;
    }
    let ok = got == passwd;
    if let Err(err) = io.write_all(&[if ok { 0 } else { 1 }]).await {
        trace!("kcp auth write error: {:?}", err);
        return;
    }
    if !ok {
        debug!("kcp wrong password");
        return;
    }
    trace!("kcp password accepted");
    // Reuse the generic relay machine: reads Addr, connects, replies flag.
    let stream = Stream::new(io, connector, bandwidth);
    if let Err(err) = stream.await {
        trace!("kcp relay error: {:?}", err);
    }
}
