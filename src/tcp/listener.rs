//! Server side of the TCP+TLS transport: accept TLS (or plain) TCP
//! connections, authenticate, then reuse the generic relay machine.

use std::{path::PathBuf, sync::Arc, time::Duration};

use log::{debug, info, trace};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};

use crate::{
    connector::Connector,
    error::Result,
    load_private_cert, load_private_key,
    quic::server::stream::Stream,
};

use super::ALPN_TCP;

/// Bound for the whole pre-relay handshake (TLS + password + target):
/// protects against slowloris-style stalled clients.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Server<C> {
    connector: C,
    acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    passwd: Vec<u8>,
    bandwidth: usize,
    port: u16,
}

impl<C> Server<C> {
    /// `tls = false` disables the TLS layer (plaintext TCP, e.g. for
    /// debugging); password authentication still applies.
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
            info!("tcp-transport tls key: {:?}, cert: {:?}", &key, &cert);
            let key = load_private_key(key.as_path())?;
            let chain = load_private_cert(cert.as_path())?;
            let mut cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)?;
            cfg.alpn_protocols = ALPN_TCP.iter().map(|p| p.to_vec()).collect();
            let acceptor: tokio_rustls::TlsAcceptor = Arc::new(cfg).into();
            Some(Arc::new(acceptor))
        } else {
            None
        };
        Ok(Self {
            connector,
            acceptor,
            passwd: passwd.into_bytes(),
            bandwidth,
            port,
        })
    }

    pub async fn run(self) -> Result<()>
    where
        C: Connector + Clone + Send + 'static,
        C::Connection: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let port = self.port;
        let listener = TcpListener::bind(format!("[::]:{port}")).await?;
        info!("tcp-transport server listening on [::]:{port}");
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(err) => {
                    debug!("tcp-transport accept error: {err}");
                    continue;
                }
            };
            tcp.set_nodelay(true).ok();
            let connector = self.connector.clone();
            let acceptor = self.acceptor.clone();
            let passwd = self.passwd.clone();
            let bandwidth = self.bandwidth;
            tokio::spawn(async move {
                if let Err(err) =
                    handle_conn(tcp, acceptor, connector, passwd, bandwidth).await
                {
                    trace!("tcp-transport {peer} error: {err}");
                }
            });
        }
    }
}

async fn handle_conn<C>(
    tcp: tokio::net::TcpStream,
    acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    connector: C,
    passwd: Vec<u8>,
    bandwidth: usize,
) -> std::io::Result<()>
where
    C: Connector + Clone + Send + 'static,
    C::Connection: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        if let Some(acceptor) = acceptor {
            let tls = acceptor.accept(tcp).await?;
            auth_and_relay(tls, connector, passwd, bandwidth).await
        } else {
            auth_and_relay(tcp, connector, passwd, bandwidth).await
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake timeout"))?
}

async fn auth_and_relay<IO, C>(mut io: IO, connector: C, passwd: Vec<u8>, bandwidth: usize) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Connector + Clone + Send + 'static,
    C::Connection: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // [len u8][password] -> status byte
    let plen = io.read_u8().await? as usize;
    if plen > 255 || plen == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad auth length",
        ));
    }
    let mut got = vec![0u8; plen];
    io.read_exact(&mut got).await?;
    let ok = got == passwd;
    io.write_all(&[if ok { 0 } else { 1 }]).await?;
    io.flush().await?;
    if !ok {
        debug!("tcp-transport wrong password");
        return Ok(());
    }
    // Reuse the generic relay machine: reads Addr, connects, replies flag.
    let stream = Stream::new(io, connector, bandwidth);
    stream.await.map_err(|e| std::io::Error::other(e.to_string()))
}
