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
    Endpoint, NewConnection, VarInt,
};
use tokio::io::AsyncRead;
use tracing::{error, trace};

use crate::{
    error::{Error, Result},
    generate_key_and_cert_der, load_private_cert, load_private_key, ALPN_QUIC,
};

pub struct SendStream<B: Buf, S: Session> {
    stream: quinn::generic::SendStream<S>,
    writing: Option<B>,
}

impl<B: Buf, S: Session> SendStream<B, S> {
    fn new(stream: quinn::generic::SendStream<S>) -> SendStream<B, S> {
        Self {
            stream,
            writing: None,
        }
    }
}

impl<B: Buf, S: Session> super::SendStream<B> for SendStream<B, S> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(ref mut data) = self.writing {
            ready!(self.stream.write_all(data.chunk()).poll_unpin(cx))?;
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data(&mut self, data: B) -> Result<()> {
        if self.writing.is_some() {
            return Err(Error::SendStreamNotReadyError);
        }
        self.writing = Some(data);
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.stream
            .finish()
            .poll_unpin(cx)
            .map_err(Error::QuinnWriteError)
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::MAX));
    }

    fn id(&self) -> u64 {
        self.stream.id().0
    }
}

pub struct RecvStream<S: Session> {
    buf: BytesMut,
    stream: quinn::generic::RecvStream<S>,
}

impl<S: Session> RecvStream<S> {
    fn new(stream: quinn::generic::RecvStream<S>) -> Self {
        Self {
            buf: BytesMut::new(),
            stream,
        }
    }
}

const READ_BUF_SIZE: usize = 1024 * 4;

impl<S: Session> super::RecvStream for RecvStream<S> {
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<usize>>> {
        self.buf.resize(READ_BUF_SIZE, 0);
        match self.stream.read(&mut self.buf).poll_unpin(cx) {
            Poll::Ready(Ok(op)) => Poll::Ready(Ok(op)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Error::QuinnReadError(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        todo!()
    }
}

pub struct BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    send: SendStream<B, S>,
    recv: RecvStream<S>,
}

impl<B, S> BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    pub fn new(send: quinn::generic::SendStream<S>, recv: quinn::generic::RecvStream<S>) -> Self {
        Self {
            send: SendStream::new(send),
            recv: RecvStream::new(recv),
        }
    }
}

impl<B, S> super::SendStream<B> for BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.send.poll_ready(cx)
    }

    fn send_data(&mut self, data: B) -> Result<()> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn id(&self) -> u64 {
        self.send.id()
    }
}

impl<B, S> super::RecvStream for BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<usize>>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }
}

impl<B, S> super::BidiStream<B> for BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    type SendStream = SendStream<B, S>;
    type RecvStream = RecvStream<S>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

const PASSWORD_VALIDATE_RESPONSE: [u8; 1] = [0];

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

}

pub struct QuicQuinnClient<'a> {
    host: &'a str,
    port: u16,
    cert_path: Option<&'a str>,
}

impl<'a> QuicQuinnClient<'a> {
    pub fn new(host: &'a str, port: u16, cert_path: Option<&'a str>) -> Self {
        Self {
            host,
            port,
            cert_path,
        }
    }

    pub async fn connect(
        &mut self,
        password: &str,
    ) -> Result<quinn::generic::Connection<TlsSession>> {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(ALPN_QUIC);
        client_config.enable_keylog();
        // let dirs = directories_next::ProjectDirs::from("org", "tls", "examples").unwrap();
        //"/home/magicalne/.local/share/examples/cert.der"
        self.cert_path
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
        let remote = (self.host, self.port)
            .to_socket_addrs()?
            .find(|add| add.is_ipv4())
            .ok_or(Error::UnknownRemoteHost)?;
        trace!("Connect remote: {:?}", &remote);
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.default_client_config(config);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // Bind this endpoint to a UDP socket on the given client address.
        let (endpoint, incoming) = endpoint_builder.bind(&addr)?;
        trace!("Client bind endpoint: {:?}", &endpoint);
        trace!("Client bind incoming: {:?}", &incoming);

        // Connect to the server passing in the server name which is supposed to be in the server certificate.
        let connection = endpoint.connect(&remote, self.host)?.await?;
        let NewConnection { connection, .. } = connection;
        validate_password(&connection, password).await?;
        Ok(connection)
    }
}

async fn validate_password(
    conn: &quinn::generic::Connection<TlsSession>,
    password: &str,
) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut buf = BytesMut::new();
    buf.put_u8(password.len() as u8);
    buf.put_slice(password.as_bytes());
    send.write_all(&buf).await?;
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
