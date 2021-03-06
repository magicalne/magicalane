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

use crate::{
    error::{Error, Result},
    generate_key_and_cert_der, load_private_cert, load_private_key,
    stream::{ProxyStreamPair, QuinnBidiStream},
    ALPN_QUIC,
};

pub struct Server {
    password: String,
    incoming: Incoming<TlsSession>,
}

impl Server {
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
        Ok(Self { password, incoming })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some(connecting) = self.incoming.next().await {
            let pwd = self.password.clone();
            tokio::spawn(async move {
                if let Ok(mut bi_stream) = connecting
                    .await
                    .map_err(Error::QuinnConnectionError)
                    .map(|conn| {
                        let NewConnection { bi_streams, .. } = conn;
                        bi_streams
                    })
                {
                    let pwd = pwd.clone();
                    while let Some(Ok((send, recv))) = bi_stream.next().await {
                        let pwd = pwd.clone();
                        let bidi = QuinnBidiStream::new(send, recv);
                        let proxy = ProxyStreamPair::proxy_out(bidi, pwd).await;
                        dbg!("connected");
                        if let Ok(proxy) = proxy {
                            match proxy.await {
                                Ok(_) => {}
                                Err(_) => break
                            }
                        }
                    }
                }
            });
        }
        Ok(())
    }
}
