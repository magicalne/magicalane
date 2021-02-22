use std::{pin::Pin, task::{Context, Poll}, future::Future};

use bytes::Buf;
use futures::{FutureExt, ready};
use quinn::{
    crypto::Session,
    generic::{RecvStream as QuinnRecvStream, SendStream as QuinnSendStream},
};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, net::TcpStream as TokioTcpStream};

use crate::error::{Error, Result};

pub trait SendStream {
    fn poll_send(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<()>>;
}

pub trait RecvStream {
    fn poll_recv(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<Option<usize>>>;
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
        match self.send_stream.write_all(buf).poll_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Error::QuinnWriteError(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: Session> RecvStream for QuinnBidiStream<S> {
    fn poll_recv(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<Option<usize>>> {
        match self.recv_stream.read(buf).poll_unpin(cx) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Error::QuinnReadError(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[pin_project::pin_project]
pub struct TcpStream {

    #[pin]
    inner: TokioTcpStream
}

impl TcpStream {

    pub fn new(tcp: TokioTcpStream) -> Self {
        Self {
            inner: tcp
        }
    }
}

impl SendStream for TcpStream {
    fn poll_send(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<()>> {
        match ready!(self.project().inner.poll_write(cx, buf)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(Error::IoError(err)))
        }
    }
}

impl RecvStream for TcpStream {
    fn poll_recv(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<Option<usize>>> {
        let mut buf = ReadBuf::new(buf);
        match ready!(self.project().inner.poll_read(cx, &mut buf)) {
            Ok(()) => Poll::Ready(Ok(Some(buf.capacity()))),
            Err(e) => Poll::Ready(Err(Error::IoError(e)))
        }
    }
}
