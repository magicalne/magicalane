use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{future::poll_fn, ready, FutureExt};
use quinn::{
    crypto::Session,
    generic::{RecvStream as QuinnRecvStream, SendStream as QuinnSendStream},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{
        unix::SocketAddr, TcpStream as TokioTcpStream, ToSocketAddrs, UdpSocket as TokioUdpSocket,
    },
};

use crate::{
    error::{Error, Result},
    protocol::{Kind, Protocol},
};

pub trait SendStream {
    fn poll_send(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<()>>;
}

pub trait RecvStream {
    fn poll_recv(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>>>;
}

pub struct QuinnBidiStream<S: Session> {
    send_stream: QuinnSendStream<S>,
    recv_stream: QuinnRecvStream<S>,
}

impl<S: Session> QuinnBidiStream<S> {
    pub fn new(send_stream: QuinnSendStream<S>, recv_stream: QuinnRecvStream<S>) -> Self {
        Self {
            send_stream,
            recv_stream,
        }
    }
}

impl<S: Session> SendStream for QuinnBidiStream<S> {
    fn poll_send(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<()>> {
        match ready!(self.send_stream.write_all(buf).poll_unpin(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(Error::QuinnWriteError(err))),
        }
    }
}

impl<S: Session> RecvStream for QuinnBidiStream<S> {
    fn poll_recv(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>>> {
        match ready!(self.recv_stream.read(buf).poll_unpin(cx)) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(err) => Poll::Ready(Err(Error::QuinnReadError(err))),
        }
    }
}

#[pin_project::pin_project]
pub struct TcpStream {
    #[pin]
    inner: TokioTcpStream,
}

impl TcpStream {
    pub async fn connect(host: &str, port: u16) -> Result<Self> {
        let addr = (host, port);
        let inner = TokioTcpStream::connect(addr).await?;
        Ok(Self { inner })
    }
}

impl SendStream for TcpStream {
    fn poll_send(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<()>> {
        match ready!(self.project().inner.poll_write(cx, buf)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(Error::IoError(err))),
        }
    }
}

impl RecvStream for TcpStream {
    fn poll_recv(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>>> {
        let mut buf = ReadBuf::new(buf);
        match ready!(self.project().inner.poll_read(cx, &mut buf)) {
            Ok(()) => Poll::Ready(Ok(Some(buf.capacity()))),
            Err(e) => Poll::Ready(Err(Error::IoError(e))),
        }
    }
}

pub struct UdpSocket {
    inner: TokioUdpSocket,
}

impl UdpSocket {
    pub async fn connect(host: &str, port: u16) -> Result<Self> {
        let addr = "[::]:0";
        let inner = TokioUdpSocket::bind(addr).await?;
        let addr = (host, port);
        inner.connect(addr).await?;
        Ok(Self { inner })
    }
}

impl SendStream for UdpSocket {
    fn poll_send(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<()>> {
        match ready!(self.inner.poll_send(cx, buf)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(Error::IoError(e))),
        }
    }
}

impl RecvStream for UdpSocket {
    fn poll_recv(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>>> {
        let mut buf = ReadBuf::new(buf);
        match ready!(self.inner.poll_recv(cx, &mut buf)) {
            Ok(_) => Poll::Ready(Ok(Some(buf.capacity()))),
            Err(e) => Poll::Ready(Err(Error::IoError(e))),
        }
    }
}

pub struct ProxyStream<T> {
    src: T,
    dst: T,
}

impl<T: SendStream + RecvStream> ProxyStream<T> {
    pub fn new(src: T, dst: T) -> Self {
        Self {
            src, dst
        }
    }
}
