use std::fs;
use tokio::io;
use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, Bytes};
use futures::{Stream, task::Poll};
use futures_core::ready;
use tracing::{debug, error, info, info_span};
use quinn::{ClientConfig, Connecting};
use std::net::{SocketAddr, ToSocketAddrs};
use futures_core::Future;
use crate::error::MagicalaneError;
use std::pin::Pin;
use crate::transport::quic_quinn;

pub struct QuicClient {
    host: String,
    remote: SocketAddr,
    config: ClientConfig
}

impl QuicClient {
    pub fn new(server_host: String, server_port: u16, local: bool) -> Result<Self> {
        let remote =  (server_host.as_str(), server_port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(crate::ALPN_QUIC);
        client_config.enable_keylog();
        if local {
            let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
            info!("cert dir: {:?}", &dirs);
            match fs::read(dirs.data_local_dir().join("cert.der")) {
                Ok(cert) => {
                    client_config.add_certificate_authority(quinn::Certificate::from_der(&cert)?)?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                    info!("local server certificate not found");
                }
                Err(e) => {
                    error!("failed to open local server certificate: {}", e);
                }
            }
        }
        let config = client_config.build();
        Ok(QuicClient {
            host: server_host,
            remote,
            config
        })
    }

    pub fn req(&self) -> Result<RequestConnecting> {
        let config = self.config.clone();
        let remote = self.remote.clone();
        let mut endpoint = quinn::Endpoint::builder();
        endpoint.default_client_config(config);
        debug!("quic client config finished.");
        let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;
        debug!("client bind local endpoint");
        let connecting = endpoint.connect(&remote, self.host.as_str())?;
        Ok(RequestConnecting {
            connecting
        })
    }
}

pub struct RequestConnecting {
    connecting: Connecting
}

impl std::future::Future for RequestConnecting {
    type Output = Result<(), MagicalaneError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.connecting).poll(cx)) {
            Ok(conn) => {
                let connection = quic_quinn::Connection::new(conn);
            },
            Err(err) => {
                error!("Connection error: {:?}", err);
            }
        }
        Poll::Ready(Ok(()))
    }
}
