use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    rc::Rc,
    sync::Arc,
};

use futures::{ready, Future, StreamExt};
use quinn::{
    crypto::rustls::TlsSession,
    generic::{Connecting, Incoming, NewConnection},
    Endpoint, ServerConfig,
};
use tracing::error;

use crate::{
    error::{Error, Result},
    generate_key_and_cert_der, load_private_cert, load_private_key,
    quic::quic_quinn::QuinnServer,
    stream::{ProxyStreamPair, QuinnBidiStream},
    ALPN_QUIC,
};

pub struct Server {
    quinn_server: QuinnServer,
}

impl Server {
    pub async fn new(
        key_cert: Option<(PathBuf, PathBuf)>,
        port: u16,
        password: String,
    ) -> Result<Self> {
        let quinn_server = QuinnServer::new(key_cert, port, password).await?;
        Ok(Self { quinn_server })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some(conn) = self.quinn_server.next().await {
            match conn {
                Ok(mut conn) => {
                    tokio::spawn(async move {
                        if let Ok(()) = conn.validate_password().await {
                            //init proxy stream
                        }
                    });
                }
                Err(err) => {
                    error!("Connection error: {:?}", err);
                }
            }
        }
        Ok(())
    }
}
