use std::{cell::RefCell, future::Future, marker::Unpin, pin::Pin, rc::Rc, sync::Arc, task::{Context, Poll}};

use bytes::BytesMut;
use futures::{future::poll_fn, ready, FutureExt};
use quinn::{crypto::{Session, rustls::TlsSession}, generic::{RecvStream as QuinnRecvStream, SendStream as QuinnSendStream}};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket},
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

    pub async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.send_stream.write_all(buf).await?;
        Ok(())
    }

    pub async fn write_finish(&mut self) -> Result<()> {
        Ok(self.send_stream.finish().await?)
    }


    pub async fn read_all(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        Ok(self.recv_stream.read(buf).await?)
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

pub trait ProxyStream: SendStream + RecvStream {}
impl<T> ProxyStream for T where T: SendStream + RecvStream {}

pub struct ProxyStreamPair<T> {
    src: T,
    dst: StreamType,
    src_buf: BytesMut,
    dst_buf: BytesMut,
}

enum StreamType {
    Tcp(TcpStream),
    Udp(UdpSocket),
    Quic(QuinnBidiStream<TlsSession>)
}

impl SendStream for StreamType {
    fn poll_send(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<()>> {
        match self.get_mut() {
            StreamType::Tcp(s) => Pin::new(s).poll_send(cx, buf),
            StreamType::Udp(s) => Pin::new(s).poll_send(cx, buf),
            StreamType::Quic(s) => Pin::new(s).poll_send(cx, buf),
        }
    }
}

impl RecvStream for StreamType {
    fn poll_recv(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>>> {
        match self.get_mut() {
            StreamType::Tcp(s) => Pin::new(s).poll_recv(cx, buf),
            StreamType::Udp(s) => Pin::new(s).poll_recv(cx, buf),
            StreamType::Quic(s) => Pin::new(s).poll_recv(cx, buf),
        }
    }
}

impl<T: SendStream + RecvStream + Unpin> ProxyStreamPair<T> {
    pub async fn proxy_out(mut bidi: T, pwd: String) -> Result<Self> {
        let mut buf = BytesMut::with_capacity(1024);
        let dst_buf = BytesMut::with_capacity(1024);
        if let Some(n) = poll_fn(|cx| Pin::new(&mut bidi).poll_recv(cx, &mut buf)).await? {
            dbg!(n);
            let protocol = Protocol::parse(&buf)?;
            if pwd.as_str() == protocol.password {
                match &protocol.kind {
                    Kind::TCP => Ok(Self {
                        src: bidi,
                        dst: StreamType::Tcp(
                            TcpStream::connect(&protocol.host, protocol.port).await?,
                        ),
                        src_buf: buf,
                        dst_buf,
                    }),
                    Kind::UDP => Ok(Self {
                        src: bidi,
                        dst: StreamType::Udp(
                            UdpSocket::connect(&protocol.host, protocol.port).await?,
                        ),
                        src_buf: buf,
                        dst_buf,
                    }),
                    Kind::Error => Err(Error::WrongProtocol),
                }
            } else {
                Err(Error::WrongPassword)
            }
        } else {
            Err(Error::NotConnectedError)
        }
    }

    pub async fn proxy_in(src: T, mut dst: QuinnBidiStream<TlsSession>, buf: &[u8]) -> Result<Self> {
        let src_buf = BytesMut::with_capacity(1024);
        let dst_buf = BytesMut::with_capacity(1024);
        poll_fn(|cx| Pin::new(&mut dst).poll_send(cx, &buf)).await?;
        Ok(Self {
            src,
            dst: StreamType::Quic(dst),
            src_buf,
            dst_buf
        })
        
    }

    pub fn poll_src_to_dst(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize>> {
        if self.src_buf.is_empty() {
            ready!(Pin::new(&mut self.src).poll_recv(cx, &mut self.src_buf))?;
        }
        if !self.src_buf.is_empty() {
            match ready!(Pin::new(&mut self.dst).poll_send(cx, &self.src_buf)) {
                Ok(()) => {
                    let n = self.src_buf.len();
                    self.src_buf.clear();
                    Poll::Ready(Ok(n))
                }
                Err(err) => Poll::Ready(Err(err)),
            }
        } else {
            Poll::Pending
        }
    }

    pub fn poll_src_from_dst(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize>> {
        if self.dst_buf.is_empty() {
            ready!(Pin::new(&mut self.dst).poll_recv(cx, &mut self.dst_buf))?;
        }
        if !self.dst_buf.is_empty() {
            match ready!(Pin::new(&mut self.src).poll_send(cx, &self.dst_buf)) {
                Ok(()) => {
                    let n = self.dst_buf.len();
                    self.dst_buf.clear();
                    Poll::Ready(Ok(n))
                }
                Err(err) => Poll::Ready(Err(err)),
            }
        } else {
            Poll::Pending
        }
    }
}

impl<T: SendStream + RecvStream + Unpin> Future for ProxyStreamPair<T> {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let p1 = self.poll_src_to_dst(cx);
        let p2 = self.poll_src_from_dst(cx);
        match (p1, p2) {
            (Poll::Ready(Err(err)), _) => Poll::Ready(Err(err)),
            (_, Poll::Ready(Err(err))) => Poll::Ready(Err(err)),
            (Poll::Ready(Ok(0)), Poll::Ready(Ok(_))) => Poll::Ready(Ok(())),
            (Poll::Ready(Ok(_)), Poll::Ready(Ok(0))) => Poll::Ready(Ok(())),
            (Poll::Ready(Ok(_)), Poll::Ready(Ok(_))) => Poll::Pending,
            (Poll::Ready(Ok(_)), Poll::Pending) => Poll::Pending,
            (Poll::Pending, Poll::Ready(Ok(_))) => Poll::Pending,
            (Poll::Pending, Poll::Pending) => Poll::Pending,
        }
    }
}
