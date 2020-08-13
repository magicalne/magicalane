use std::{fs, io};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result, Error};
use bytes::{Buf, Bytes};
use futures::{Stream, task::Poll};
use futures_core::ready;
use pin_project::pin_project;
use quinn::{Endpoint, Incoming, ReadError};
use quinn::generic::NewConnection;
use quinn_proto::ConnectionError;
use quinn_proto::crypto::rustls::TlsSession;
use quinn_proto::crypto::Session;
use quinn_proto::generic::ServerConfig;
use tracing::{debug, error, info, info_span};

use crate::error::MagicalaneError;
use crate::transport::{
    quic::{BidiStream, Connection, RecvStream, SendStream},
    quic_quinn::{self, SendStreamError},
};
use crate::protocol::{Protocol, Kind};
use tokio::net::TcpStream;
use mio::net::UdpSocket;

pub struct QuicServer {
    endpoint: Endpoint,
    incoming: Incoming,
}

impl QuicServer {
    pub fn new(port: u16, ca_path: Option<PathBuf>, key_path: Option<PathBuf>) -> Result<Self> {
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.stream_window_uni(0);
        let mut server_config = quinn::ServerConfig::default();
        server_config.transport = Arc::new(transport_config);
        let mut server_config = quinn::ServerConfigBuilder::new(server_config);
        server_config.protocols(super::super::ALPN_QUIC);
        if let (Some(key_path), Some(cert_path)) = (&key_path, &ca_path) {
            let key = fs::read(key_path).context("failed to read private key")?;
            let key = if key_path.extension().map_or(false, |x| x == "der") {
                quinn::PrivateKey::from_der(&key)?
            } else {
                quinn::PrivateKey::from_pem(&key)?
            };
            let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
            let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
                quinn::CertificateChain::from_certs(quinn::Certificate::from_der(&cert_chain))
            } else {
                quinn::CertificateChain::from_pem(&cert_chain)?
            };
            server_config.certificate(cert_chain, key)?;
        } else {
            let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
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
            let key = quinn::PrivateKey::from_der(&key)?;
            let cert = quinn::Certificate::from_der(&cert)?;
            server_config.certificate(quinn::CertificateChain::from_certs(vec![cert]), key)?;
        }
        let config = server_config.build();
        let mut endpoint = quinn::Endpoint::builder();
        endpoint.listen(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let socket = SocketAddr::new(ip, port);
        println!("Server start on: {:?}", &socket);
        let (endpoint, incoming) = endpoint.bind(&socket)?;
        Ok(QuicServer {
            endpoint,
            incoming,
        })
    }
}

impl Future for QuicServer {
    type Output = Result<(), MagicalaneError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Some(mut conn) = ready!(Pin::new(&mut self.incoming).poll_next(cx)) {
                match ready!(Pin::new(&mut conn).poll(cx)) {
                    Ok(conn) => {
                        let connection = quic_quinn::Connection::new(conn);
                        tokio::spawn(ProxyTask::new(connection));
                    },
                    Err(err) => {
                        error!("Connection error: {:?}", err);
                    }
                }
            } else {
                return Poll::Ready(Ok(()))
            }
        }
    }
}


#[pin_project]
struct ProxyTask {
    #[pin]
    state: TaskState
}

impl ProxyTask {
    fn new(conn: quic_quinn::Connection<TlsSession>) -> Self {
        ProxyTask {
            state: TaskState::Connecting {
                quic_conn: conn
            }
        }
    }

}

impl Future for ProxyTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        loop {
            dbg!("connection");
            match me.state.as_mut().project() {
                StateProj::Connecting { mut quic_conn } => {
                    match ready!(Pin::new(&mut quic_conn).poll_accept_bidi_stream(cx)) {
                        Ok(Some(bi_stream)) => {
                            let (mut send, mut recv):
                                (quic_quinn::SendStream<Bytes, TlsSession>,
                                 quic_quinn::RecvStream<TlsSession>) = bi_stream.split();
                            match ready!(recv.poll_data(cx)) {
                                Ok(Some(buf)) => {
                                    debug!("incoming from proxy: {:?}", &buf);
                                    if send.send_data(buf.clone()).is_ok() {
                                        match ready!(send.poll_finish(cx)) {
                                            Ok(_) => {
                                                me.state.set(TaskState::Connected {
                                                    quic_recv: recv,
                                                    quic_send: send,
                                                });
                                            }
                                            Err(err) => {
                                                error!("Quic send error: {:?}", err);
                                                ()
                                            }
                                        }
                                    }
                                }
                                Ok(None) => (),
                                Err(err) => {
                                    error!("connection error: {:?}", err);
                                    ()
                                }
                            }
                        },
                        Ok(None) => (),
                        Err(_) => ()
                    }
                },
                StateProj::Connected { quic_send: _, quic_recv: _ } => {}
            }
        }
    }
}

#[pin_project(project = StateProj)]
enum TaskState {
    Connecting {
        #[pin]
        quic_conn: quic_quinn::Connection<TlsSession>
    },
    Connected {
        quic_send: quic_quinn::SendStream<Bytes, TlsSession>,
        quic_recv: quic_quinn::RecvStream<TlsSession>,
    },
}