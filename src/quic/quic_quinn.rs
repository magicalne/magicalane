use std::{
    borrow::Cow,
    fs,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    usize,
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{ready, FutureExt, Stream, StreamExt};
use quinn::{
    crypto::{rustls::TlsSession, Session},
    generic::ServerConfig,
    Endpoint, NewConnection, RecvStream, SendStream, VarInt,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tracing::{error, trace};

use crate::{
    error::{Error, Result},
    generate_key_and_cert_der, load_private_cert, load_private_key,
    socks::protocol::Addr,
    stream::Transfer,
    ALPN_QUIC,
};

const PASSWORD_VALIDATE_RESPONSE: [u8; 1] = [0];

#[pin_project::pin_project]
pub struct QuinnStream {
    #[pin]
    send: SendStream,
    #[pin]
    recv: RecvStream,
}

impl QuinnStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuinnStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().recv.poll_read(cx, buf)
    }
}

impl AsyncWrite for QuinnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().send.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().send.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().send.poll_shutdown(cx)
    }
}

pub struct Connection {
    connection: quinn::generic::Connection<TlsSession>,
    password: String,
}

impl Connection {
    pub fn new(conn: quinn::generic::Connection<TlsSession>, password: String) -> Self {
        Self {
            connection: conn,
            password,
        }
    }

    pub async fn validate_password(&mut self) -> Result<()> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let mut buf = BytesMut::new();
        match recv.read(&mut buf).await? {
            Some(n) => {
                trace!(
                    "Recv {:?} bytes from client: {:?}.",
                    n,
                    self.connection.remote_address()
                );
                if let Some(len) = buf.get(0) {
                    let len = *len as usize;
                    if len != buf.len() + 1 {
                        return Err(Error::ParsePasswordFail);
                    } else {
                        let buf = &buf[1..1 + len];
                        if len != self.password.len() || buf != self.password.as_bytes() {
                            Err(Error::WrongPassword)
                        } else {
                            trace!("Password is validate.");
                            send.write_all(&PASSWORD_VALIDATE_RESPONSE).await?;
                            send.finish().await?;
                            Ok(())
                        }
                    }
                } else {
                    Err(Error::ParsePasswordFail)
                }
            }
            None => Err(Error::NotConnectedError),
        }
    }

    pub async fn open_remote(&mut self) -> Result<Transfer> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let mut buf = BytesMut::with_capacity(128);
        let remote = match recv.read(&mut buf).await? {
            Some(n) => match Addr::decode(&buf[..n])? {
                Addr::SocketAddr(ip) => Some(TcpStream::connect(ip).await),
                Addr::DomainName(domain, port) => {
                    let domain = std::str::from_utf8(&domain)?;
                    let socket = (domain, port);
                    Some(TcpStream::connect(socket).await)
                }
            },
            None => None,
        };
        match remote {
            Some(remote) => {
                buf.clear();
                match remote {
                    Ok(remote) => {
                        buf.put_u8(0);
                        send.write_all(&buf[0..1]).await?;
                        let transfer = Transfer::new(send, recv, remote);
                        Ok(transfer)
                    }
                    Err(err) => {
                        buf.put_u8(0);
                        send.write_all(&buf[0..1]).await?;
                        trace!("Failed to open remote: {:?}", &err);
                        Err(Error::IoError(err))
                    }
                }
            }
            None => Err(Error::NotConnectedError),
        }
    }
}

impl Stream for Connection {
    type Item = Result<(SendStream, RecvStream)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.connection.open_bi().poll_unpin(cx)) {
            Ok((send, recv)) => Poll::Ready(Some(Ok((send, recv)))),
            Err(err) => Poll::Ready(Some(Err(Error::QuinnConnectionError(err)))),
        }
    }
}

pub struct QuicQuinnClient {
    conn: quinn::generic::Connection<TlsSession>,
    buf: BytesMut,
}

impl QuicQuinnClient {
    pub async fn new(host: &str, port: u16, cert_path: Option<&str>) -> Result<Self> {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(ALPN_QUIC);
        client_config.enable_keylog();
        // let dirs = directories_next::ProjectDirs::from("org", "tls", "examples").unwrap();
        //"/home/magicalne/.local/share/examples/cert.der"
        cert_path
            .map(|path| {
                fs::read(path)
                    .map(|cert| quinn::Certificate::from_der(&cert))
                    .map(|cert| match cert {
                        Ok(cert) => {
                            if let Err(err) = client_config.add_certificate_authority(cert) {
                                error!("Client add cert failed: {:?}.", err);
                            }
                        }
                        Err(err) => {
                            error!("Client parse cert error: {:?}.", err);
                        }
                    })
            })
            .map(|r| {
                r.map_err(|err| {
                    error!("Client config cert with error: {:?}.", err);
                })
            });
        let config = client_config.build();
        let remote = (host, port)
            .to_socket_addrs()?
            .find(|add| add.is_ipv4())
            .ok_or(Error::UnknownRemoteHost)?;
        trace!("Connect remote: {:?}", &remote);
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.default_client_config(config);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // Bind this endpoint to a UDP socket on the given client address.
        let (endpoint, incoming) = endpoint_builder.bind(&addr)?;
        trace!("Client bind endpoint");

        // Connect to the server passing in the server name which is supposed to be in the server certificate.
        let connection = endpoint.connect(&remote, host)?.await?;
        let NewConnection { connection, .. } = connection;
        Ok(Self {
            conn: connection,
            buf: BytesMut::with_capacity(128),
        })
    }

    pub async fn send_passwd(&mut self, password: &str) -> Result<()> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        let mut buf = &mut self.buf;
        buf.put_u8(password.len() as u8);
        buf.put_slice(password.as_bytes());
        send.write_all(&buf[0..password.len() + 1]).await?;
        trace!("Sent password validation request.");
        match recv.read(&mut buf).await? {
            Some(n) => {
                trace!("Password validate successfully. n: {:?}", n);
                Ok(())
            }
            None => {
                trace!("Close connection due to wrong password.");
                Err(Error::WrongPassword)
            }
        }
    }

    pub async fn open_remote(&mut self, buf: &[u8]) -> Result<(SendStream, RecvStream)> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        send.write_all(buf).await?;
        trace!("Sent open remote request.");
        match recv.read(&mut self.buf).await? {
            Some(1) => {
                trace!("Open remote successfully.");
                Ok((send, recv))
            }
            Some(n) => {
                trace!("Cannot open remote: {:?}", &self.buf[..n]);
                Err(Error::OpenRemoteAddrError)
            }
            None => {
                trace!("Connection is closed.");
                Err(Error::NotConnectedError)
            }
        }
    }
}

pub struct QuinnServer {
    incoming: quinn::generic::Incoming<TlsSession>,
    password: String,
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
        Ok(Self { password, incoming })
    }
}

impl Stream for QuinnServer {
    type Item = Result<Connection>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.incoming).poll_next_unpin(cx)) {
            Some(mut c) => match ready!(c.poll_unpin(cx)) {
                Ok(quinn::generic::NewConnection { connection, .. }) => {
                    Poll::Ready(Some(Ok(Connection::new(connection, self.password.clone()))))
                }
                Err(err) => Poll::Ready(Some(Err(Error::QuinnConnectionError(err)))),
            },
            None => Poll::Ready(None),
        }
    }
}
