use std::{
    fs,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::Path,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{ready, FutureExt, StreamExt};
use quinn::{
    crypto::{rustls::TlsSession, Session},
    Endpoint, NewConnection, VarInt,
};
use tokio::io::AsyncRead;
use tracing::{error, trace};

use crate::{
    error::{Error, Result},
    ALPN_QUIC,
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

pub struct Connection<B: Buf, S: Session> {
    connection: quinn::generic::NewConnection<S>,
    _phantom_data: PhantomData<B>,
}

impl<B, S> Connection<B, S>
where
    B: Buf,
    S: Session,
{
    pub fn new(conn: quinn::generic::NewConnection<S>) -> Self {
        Self {
            connection: conn,
            _phantom_data: PhantomData,
        }
    }
}

impl<B, S> super::Connection<B> for Connection<B, S>
where
    B: Buf,
    S: Session,
{
    type SendStream = SendStream<B, S>;

    type RecvStream = RecvStream<S>;

    type BidiStream = BidiStream<B, S>;

    fn poll_accept_bidi_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream>> {
        match ready!(self.connection.bi_streams.poll_next_unpin(cx)) {
            Some(Ok((send, recv))) => Poll::Ready(Ok(BidiStream::new(send, recv))),
            Some(Err(err)) => Poll::Ready(Err(Error::QuinnConnectionError(err))),
            None => Poll::Pending,
        }
    }

    fn poll_accept_recv_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>>> {
        todo!()
    }

    fn poll_open_bidi_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream>> {
        let mut open = self.connection.connection.open_bi();
        match ready!(open.poll_unpin(cx)) {
            Ok((send, recv)) => Poll::Ready(Ok(BidiStream::new(send, recv))),
            Err(err) => Poll::Ready(Err(Error::QuinnConnectionError(err))),
        }
    }

    fn poll_open_send_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::SendStream>>> {
        todo!()
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

    pub async fn connect(&mut self) -> Result<quinn::generic::Connection<TlsSession>> {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(ALPN_QUIC);
        client_config.enable_keylog();
        // let dirs = directories_next::ProjectDirs::from("org", "tls", "examples").unwrap();
        //"/home/magicalne/.local/share/examples/cert.der"
        let a = self.cert_path.map(|path| {
            fs::read(path)
                .map(|cert| quinn::Certificate::from_der(&cert))
                .map(|cert| {
                    match cert {
                        Ok(cert) => {
                            if let Err(err) = client_config.add_certificate_authority(cert) {
                                error!("Client add cert failed: {:?}.", err);
                            }
                        }
                        Err(err) => {
                            error!("Client parse cert error: {:?}.", err);
                        }
                    }
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
        Ok(connection)
    }
}
