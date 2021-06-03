pub(crate) mod conn;
pub(crate) mod stream;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    u16,
};

use futures::StreamExt;
use quinn::{Endpoint, NewConnection, ServerConfig};
use socket2::{Domain, Protocol, Socket, Type};
use socks5lib::Connector;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    spawn,
};
use tracing::{info, trace};

use crate::{
    error::Result,
    load_private_cert, load_private_key,
    quic::{server::conn::Connection, SOCKET_RECV_BUF_SIZE, SOCKET_SEND_BUF_SIZE},
    ALPN_QUIC,
};

#[pin_project::pin_project]
pub struct Server<C> {
    connector: C,
    passwd: Vec<u8>,
    #[pin]
    incoming: quinn::Incoming,
}

impl<C> Server<C> {
    pub fn new(
        connector: C,
        key_cert: (PathBuf, PathBuf),
        port: u16,
        passwd: String,
    ) -> Result<Self> {
        let server_config = ServerConfig::default();
        let mut server_config = quinn::ServerConfigBuilder::new(server_config);
        server_config.enable_keylog();
        let (key, cert) = key_cert;
        info!("key path: {:?}", &key);
        info!("cert path: {:?}", &cert);
        let key = load_private_key(key.as_path())?;
        let cert_chain = load_private_cert(cert.as_path())?;
        server_config.certificate(cert_chain, key)?;
        server_config.protocols(ALPN_QUIC);
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.listen(server_config.build());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let addr = addr.into();
        info!("Server bind: {:?}", &addr);
        socket.bind(&addr)?;
        socket.set_recv_buffer_size(SOCKET_RECV_BUF_SIZE)?;
        socket.set_send_buffer_size(SOCKET_SEND_BUF_SIZE)?;
        let udp = socket.into();
        let (_, incoming) = endpoint_builder.with_socket(udp)?;
        let passwd = passwd.into_bytes();
        Ok(Self {
            connector,
            passwd,
            incoming,
        })
    }
}

impl<C, IO> Server<C>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
    C: Connector<Connection = IO> + Send + 'static,
{
    pub async fn run(&mut self) -> Result<()> {
        while let Some(connecting) = self.incoming.next().await {
            trace!(
                "Accept connection from remote: {:?}",
                &connecting.remote_address()
            );
            match connecting.await {
                Ok(NewConnection { bi_streams, .. }) => {
                    let mut conn =
                        Connection::new(bi_streams, self.connector.clone(), self.passwd.clone());
                    spawn(async move {
                        if let Err(err) = conn.accept().await {
                            trace!("Quic connection error: {:?}", err);
                        }
                    });
                }
                Err(err) => {
                    trace!("Connection error: {:?}", err);
                }
            }
        }
        Ok(())
    }
}
