use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use futures::{StreamExt, TryStreamExt};
use quinn::{Endpoint, ServerConfig};
use tracing::trace;

use crate::{
    error::{Error, Result},
    generate_key_and_cert_der, load_private_cert, load_private_key,
    stream::Transfer,
    ALPN_QUIC,
};

use super::stream::StreamActorHandler;

pub struct QuinnServer {
    incoming: quinn::Incoming,
    password: Vec<u8>,
}

impl QuinnServer {
    pub async fn new(
        key_cert: Option<(PathBuf, PathBuf)>,
        port: u16,
        password: String,
    ) -> Result<Self> {
        let mut endpoint_builder = Endpoint::builder();
        let server_config = ServerConfig::default();
        let mut server_config = quinn::ServerConfigBuilder::new(server_config);
        server_config.enable_keylog();
        let (key, cert) = key_cert.unwrap_or(generate_key_and_cert_der()?);
        let key = load_private_key(key.as_path())?;
        let cert_chain = load_private_cert(cert.as_path())?;
        server_config.certificate(cert_chain, key)?;
        server_config.protocols(ALPN_QUIC);
        endpoint_builder.listen(server_config.build());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let (_, incoming) = endpoint_builder.bind(&addr)?;
        trace!("Quic server bind: {:?}", &addr);
        let password = password.into_bytes();
        Ok(Self { password, incoming })
    }

    pub async fn run(&mut self) -> Result<()> {
        let stream = StreamActorHandler::new(Some(self.password.clone()));
        while let Some(connecting) = self.incoming.next().await {
            trace!("connecting from remote: {:?}", &connecting.remote_address());
            let mut stream = stream.clone();
            match connecting.await {
                Ok(quinn::generic::NewConnection { mut bi_streams, .. }) => {
                    tokio::spawn(async move {
                        if let Some((send, recv)) = bi_streams.try_next().await? {
                            stream.validate_passwd(send, recv).await?;
                        }
                        while let Some((send, recv)) = bi_streams.try_next().await? {
                            let (send, recv, tcp) = stream.open_remote(send, recv).await?;
                            let mut transfer = Transfer::new(send, recv, tcp);
                            tokio::spawn(async move {
                                let _ = transfer.copy().await;
                            });
                        }
                        Ok::<(), Error>(())
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
