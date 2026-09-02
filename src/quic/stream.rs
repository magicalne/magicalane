use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use log::trace;
use pin_project::pin_project;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    error::{Error, Result},
    socks5::proto::Addr,
};

const CORRECT_PASSWORD_RESPONSE: u8 = 0;
const SEND_ADDR_SUCCESS_RESPONSE: u8 = 0;

/// A bidirectional relay stream over a QUIC connection.
#[pin_project]
pub struct QuicStream {
    #[pin]
    recv: RecvStream,
    #[pin]
    send: SendStream,
}

impl QuicStream {
    pub fn new(recv: RecvStream, send: SendStream) -> Self {
        Self { recv, send }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().recv.poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        // quinn::SendStream also has an inherent poll_write with its native
        // error type; call the tokio trait impl explicitly.
        <SendStream as AsyncWrite>::poll_write(self.project().send, cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        <SendStream as AsyncWrite>::poll_flush(self.project().send, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        <SendStream as AsyncWrite>::poll_shutdown(self.project().send, cx)
    }
}

/// Authenticate a fresh connection using its first bi-stream, mirroring the
/// server-side `Connection::accept` flow: the first stream carries only the
/// password and is dropped after the server replies.
pub(crate) async fn authenticate(conn: &quinn::Connection, passwd: &[u8]) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut buf = Vec::with_capacity(1 + passwd.len());
    buf.push(passwd.len() as u8);
    buf.extend_from_slice(passwd);
    send.write_all(&buf).await?;
    send.flush().await?;
    let mut flag = [0u8; 1];
    recv.read_exact(&mut flag).await?;
    if flag[0] != CORRECT_PASSWORD_RESPONSE {
        return Err(Error::WrongPassword);
    }
    trace!("password accepted");
    Ok(())
}

/// Open a relay stream to `addr` on an authenticated connection.
///
/// Wire protocol per relay bi-stream:
///   client -> server: [Addr encoding]
///   server -> client: [flag u8]
///   ... raw relay ...
pub(crate) async fn open_relay_stream(conn: &quinn::Connection, addr: &Addr) -> Result<QuicStream> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut addr_buf = BytesMut::new();
    addr.encode(&mut addr_buf);
    send.write_all(&addr_buf).await?;
    send.flush().await?;

    let mut flag = [0u8; 1];
    recv.read_exact(&mut flag).await?;
    if flag[0] != SEND_ADDR_SUCCESS_RESPONSE {
        return Err(Error::OpenRemoteAddrError);
    }
    trace!("relay accepted");
    Ok(QuicStream::new(recv, send))
}
