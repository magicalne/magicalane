use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use bytes::Bytes;
use futures::StreamExt;
use quinn::{
    crypto::rustls::TlsSession,
    generic::{Connecting, NewConnection},
    Endpoint, ServerConfig,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{ALPN_QUIC, error::Result, generate_key_and_cert_der, load_private_cert, load_private_key, quic::quic_quinn::Connection, stream::QuinnBidiStream};

pub struct QuinnServer {
    key_cert: Option<(PathBuf, PathBuf)>,
    port: u16,
}

impl QuinnServer {
    pub fn new(key_cert: Option<(PathBuf, PathBuf)>, port: u16) -> Self {
        Self { key_cert, port }
    }

    pub async fn run(self) -> crate::error::Result<()> {
        let mut endpoint_builder = Endpoint::builder();
        let server_config = ServerConfig::default();
        let mut server_config = quinn::ServerConfigBuilder::new(server_config);
        let (key, cert) = self.key_cert.unwrap_or(generate_key_and_cert_der()?);
        let key = load_private_key(key)?;
        let cert_chain = load_private_cert(cert)?;
        server_config.certificate(cert_chain, key)?;
        server_config.protocols(ALPN_QUIC);
        endpoint_builder.listen(server_config.build());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), self.port);
        let (endpoint, mut incoming) = endpoint_builder.bind(&addr)?;
        while let Some(conn) = incoming.next().await {
            tokio::spawn(async move { Self::accept_connection(conn).await });
        }
        Ok(())
    }

    async fn accept_connection(conn: Connecting<TlsSession>) -> Result<()> {
        let conn = conn.await?;
        let NewConnection {
            connection,
            uni_streams,
            mut bi_streams,
            datagrams,
            ..
        } = conn;
        // One quic connection matches one proxy(tcp/udp) connection.
        while let Some(Ok((send, recv))) = bi_streams.next().await {
            let bidi = QuinnBidiStream::new(send, recv);
        }
        Ok(())
    }
}
