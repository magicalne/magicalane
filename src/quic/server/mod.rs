use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use log::info;
use pin_project::pin_project;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    spawn,
};

use crate::connector::Connector;
use crate::{
    ALPN_QUIC,
    error::Result,
    load_private_cert, load_private_key,
    quic::{SOCKET_RECV_BUF_SIZE, SOCKET_SEND_BUF_SIZE, server::conn::Connection},
};

pub mod conn;
pub mod stream;

#[pin_project]
pub struct Server<C> {
    connector: C,
    passwd: Vec<u8>,
    endpoint: quinn::Endpoint,
    bandwidth: usize,
}

impl<C> Server<C> {
    pub fn new(
        connector: C,
        key_cert: (PathBuf, PathBuf),
        port: u16,
        passwd: String,
        bandwidth: usize,
    ) -> Result<Self> {
        let (key, cert) = key_cert;
        info!("key path: {:?}", &key);
        info!("cert path: {:?}", &cert);
        let key = load_private_key(key.as_path())?;
        let cert_chain = load_private_cert(cert.as_path())?;
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        server_config.alpn_protocols = ALPN_QUIC.iter().map(|p| p.to_vec()).collect();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?,
        ));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        info!("Server bind: {:?}", &addr);
        socket.bind(&addr.into())?;
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(SOCKET_RECV_BUF_SIZE)?;
        socket.set_send_buffer_size(SOCKET_SEND_BUF_SIZE)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket.into(),
            quinn::default_runtime().unwrap(),
        )?;
        let passwd = passwd.into_bytes();
        Ok(Self {
            connector,
            passwd,
            endpoint,
            bandwidth,
        })
    }
}

impl<C, IO> Server<C>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
    C: Connector<Connection = IO> + Send + 'static,
{
    pub async fn run(&mut self) -> Result<()> {
        while let Some(incoming) = self.endpoint.accept().await {
            let connector = self.connector.clone();
            let passwd = self.passwd.clone();
            let bandwidth = self.bandwidth;
            spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        trace_accept(&conn);
                        let mut c = Connection::new(conn, connector, passwd, bandwidth);
                        if let Err(err) = c.accept().await {
                            log::trace!("Quic connection error: {:?}", err);
                        }
                    }
                    Err(err) => {
                        log::trace!("Connection error: {:?}", err);
                    }
                }
            });
        }
        Ok(())
    }
}

fn trace_accept(conn: &quinn::Connection) {
    log::trace!("Accept connection from remote: {:?}", conn.remote_address());
}
