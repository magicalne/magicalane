use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
};

use log::trace;
use rustls_pki_types::CertificateDer;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Mutex;

use crate::{
    error::{Error, Result},
    quic::{SOCKET_RECV_BUF_SIZE, SOCKET_SEND_BUF_SIZE, stream},
    socks5::proto::Addr,
};

/// Handle used by the socks5 server to open relay streams over QUIC.
///
/// Maintains a single shared QUIC connection; the first bi-stream of a
/// connection performs the password handshake, every subsequent one is a
/// relay stream (see `quic/stream.rs`).
#[derive(Clone)]
pub struct ClientActorHndler {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    endpoint: quinn::Endpoint,
    remote_addr: SocketAddr,
    server_name: String,
    passwd: Vec<u8>,
    conn: Mutex<Option<quinn::Connection>>,
}

impl ClientActorHndler {
    pub async fn new(
        server_name: String,
        port: u16,
        cert_path: Option<PathBuf>,
        passwd: Vec<u8>,
    ) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(path) = &cert_path {
            let certs: Vec<CertificateDer> = crate::load_private_cert(path)?;
            for cert in certs {
                roots.add(cert)?;
            }
        }
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_config.alpn_protocols = crate::ALPN_QUIC.iter().map(|p| p.to_vec()).collect();
        let quinn_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
        ));

        let remote_addr = (server_name.as_str(), port)
            .to_socket_addrs()?
            .find(|add| add.is_ipv4())
            .ok_or(Error::UnknownRemoteHost)?;
        trace!(
            "Connect remote: {:?}, server name: {:?}",
            &remote_addr, &server_name
        );

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.bind(&bind.into())?;
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(SOCKET_RECV_BUF_SIZE)?;
        socket.set_send_buffer_size(SOCKET_SEND_BUF_SIZE)?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket.into(),
            quinn::default_runtime().unwrap(),
        )?;
        endpoint.set_default_client_config(quinn_config);

        Ok(Self {
            inner: Arc::new(ClientInner {
                endpoint,
                remote_addr,
                server_name,
                passwd,
                conn: Mutex::new(None),
            }),
        })
    }

    /// Open a new relay stream to `addr`, (re)connecting and authenticating as needed.
    /// Consumes `self` (a cheap handle) so the returned future is 'static.
    pub async fn open_bi(self, addr: Addr) -> io::Result<super::stream::QuicStream> {
        self.inner.open_relay(addr).await
    }
}

impl ClientInner {
    async fn get_conn(&self) -> Result<quinn::Connection> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let conn = self
            .endpoint
            .connect(self.remote_addr, &self.server_name)?
            .await?;
        stream::authenticate(&conn, &self.passwd).await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn open_relay_attempt(
        &self,
        addr: &Addr,
    ) -> crate::error::Result<super::stream::QuicStream> {
        let conn = self.get_conn().await?;
        stream::open_relay_stream(&conn, addr).await
    }

    async fn open_relay(&self, addr: Addr) -> io::Result<super::stream::QuicStream> {
        match self.open_relay_attempt(&addr).await {
            Ok(s) => Ok(s),
            // Connection may have died between check and use - retry once on a fresh one.
            Err(_) => {
                self.conn.lock().await.take();
                self.open_relay_attempt(&addr)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))
            }
        }
    }
}

/// Kept for API compatibility with previous versions.
pub fn read_cert(path: &std::path::Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}
