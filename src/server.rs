use std::{
    fs, io,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use anyhow::{anyhow, bail, Context as context1, Result};
use futures_util::future::try_join;
use futures_util::TryFutureExt;
use quinn::{Endpoint, Incoming};
use quinn::generic::ServerConfig;
use quinn_proto::{CertificateChain, PrivateKey};
use quinn_proto::crypto::rustls::TlsSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::stream::StreamExt;
use tracing::{debug, error, info, info_span};
use tracing_futures::Instrument;

use crate::ALPN_QUIC;
use crate::error::MagicalaneError;
use crate::protocol::{Kind, Protocol};
use futures_core::Future;
use futures::task::{Context, Poll};
use bytes::BytesMut;
use std::pin::Pin;

pub struct Server {
    config: MLEServerConfig,
    endpoint: Endpoint,
    incoming: Incoming,
}

impl Server {
    pub async fn run(&mut self) -> Result<()> {
        while let Some(conn) = self.incoming.next().await {
            debug!("connection incoming");
            tokio::spawn(
                handle_connection(conn).unwrap_or_else(move |e| {
                    error!("connection failed: {reason}", reason = e.to_string())
                }),
            );
        }
        Ok(())
    }
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    debug!("connecting...");
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .authentication_data()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");
        // Each stream initiated by the client constitutes a new request.
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            tokio::spawn(
                proxy(stream)
                    .unwrap_or_else(move |e| error!("failed: {reason}", reason = e.to_string()))
                    .instrument(info_span!("request")),
            );
        }
        Ok(())
    }
        .instrument(span)
        .await?;
    Ok(())
}

async fn proxy(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let n = recv
        .read_buf(&mut buf)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    debug!("read: {:?} bytes, buf: {:?}", n, &buf[..n]);
    let protocol = Protocol::parse(&buf)?;
    debug!("receive protocol: {:?}", &protocol);
    //TODO check pwd
    let uri = format!("{}:{}", &protocol.host?, protocol.port);
    debug!("send request to remote: {:?}, len: {:?}", &uri, uri.len());
    let mut socket = uri.to_socket_addrs()?;
    if let Some(addr) = socket.next() {
        debug!("remote address: {:?}", &addr);
        match protocol.kind {
            Ok(Kind::TCP) => {
                let mut server = TcpStream::connect(addr).await?;
                debug!("connect to remote TCP");
                let (mut server_rd, mut server_wr) = server.split();
                if let Some(payload) = protocol.payload {
                    let _ = server_wr.write_all(&payload).await?;
                    debug!("send payload to remote");
                }

                let client_to_server = tokio::io::copy(&mut recv, &mut server_wr);
                let server_to_client = tokio::io::copy(&mut server_rd, &mut send);
                let amounts = try_join(client_to_server, server_to_client).await;
                match amounts {
                    Ok((from_client, from_server)) => {
                        info!(
                            "server wrote {} bytes and received {} bytes",
                            from_client, from_server
                        );
                    }
                    Err(e) => {
                        error!("tunnel error: {}", e);
                    }
                };
            }
            Ok(Kind::UDP) => {
                unimplemented!()
            }
            _ => {}
        }
    }
    info!("complete");
    Ok(())
}
//
// struct ProxyTunnelConnecting<I1, O1, I2, O2>
//     where I1: AsyncReadExt,
//           O1: AsyncWriteExt,
//           I2: AsyncReadExt,
//           O2: AsyncWriteExt,
// {
//     i1: I1,
//     o1: O1,
//     i2: I2,
//     o2: O2,
// }
//
// impl <I1, O1, I2, O2> Future for ProxyTunnelConnecting<I1, O1, I2, O2>
//     where I1: AsyncReadExt,
//           O1: AsyncWriteExt,
//           I2: AsyncReadExt,
//           O2: AsyncWriteExt,
// {
//     type Output = u64;
//
//     fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         unimplemented!()
//     }
// }

pub struct MLEServerConfig {
    port: u16,
    password: String,
    quinn_server_conf: ServerConfig<TlsSession>,
}

impl MLEServerConfig {
    pub fn new(port: u16, password: String, cert: Option<PathBuf>, key: Option<PathBuf>)
               -> Result<Self> {
        let quinn_server_conf = config(cert, key)?;
        Ok(MLEServerConfig {
            port,
            password,
            quinn_server_conf,
        })
    }

    pub fn server(self) -> Result<Server> {
        let mut endpoint = quinn::Endpoint::builder();
        let config = self.quinn_server_conf.clone();
        endpoint.listen(config);

        let port = self.port;
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        let (endpoint, incoming) = endpoint.bind(&socket)?;
        info!("listening on {}", endpoint.local_addr()?);

        Ok(Server {
            config: self,
            endpoint,
            incoming,
        })
    }
}

fn config(cert: Option<PathBuf>, key: Option<PathBuf>) -> Result<ServerConfig<TlsSession>> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.stream_window_uni(0);
    let mut server_config = quinn::ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(ALPN_QUIC);
    // server_config.enable_keylog();
    // server_config.use_stateless_retry(true);
    if let (Some(key_path), Some(cert_path)) = (key, cert) {
        let key = load_private_key(key_path);
        let cert_chain = load_private_cert(cert_path);
        server_config.certificate(cert_chain?, key?)?;
    } else {
        let (cert, key) = generate_key_and_cert()?;
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert = quinn::Certificate::from_der(&cert)?;
        server_config.certificate(quinn::CertificateChain::from_certs(vec![cert]), key)?;
    }
    Ok(server_config.build())
}

fn generate_key_and_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    info!("Create private key and cert.");
    let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            info!("generating self-signed certificate");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der().unwrap();
            fs::create_dir_all(&path).context("failed to create certificate directory")?;
            fs::write(&cert_path, &cert).context("failed to write certificate")?;
            fs::write(&key_path, &key).context("failed to write private key")?;
            (cert, key)
        }
        Err(e) => {
            bail!("failed to read certificate: {}", e);
        }
    };
    Ok((cert, key))
}

fn load_private_key(key_path: PathBuf) -> Result<PrivateKey> {
    info!("Loading private key.");
    let key = fs::read(&key_path).context("failed to read private key")?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        quinn::PrivateKey::from_der(&key)?
    } else {
        quinn::PrivateKey::from_pem(&key)?
    };
    Ok(key)
}

fn load_private_cert(cert_path: PathBuf) -> Result<CertificateChain> {
    info!("Loading private cert.");
    let cert_chain = fs::read(&cert_path).context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        quinn::CertificateChain::from_certs(quinn::Certificate::from_der(&cert_chain))
    } else {
        quinn::CertificateChain::from_pem(&cert_chain)?
    };
    Ok(cert_chain)
}
