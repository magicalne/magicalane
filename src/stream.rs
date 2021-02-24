use std::{
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
    u128,
};

use bytes::BytesMut;
use futures::{future::poll_fn, ready, FutureExt};
use quinn::{
    crypto::Session,
    generic::{RecvStream as QuinnRecvStream, SendStream as QuinnSendStream},
};
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
    buf: BytesMut,
    dst: StreamType,
}

enum StreamType {
    Tcp(TcpStream),
    Udp(UdpSocket),
}



impl<T: SendStream + RecvStream + Unpin> ProxyStreamPair<T> {
    pub async fn init_proxy(mut bidi: T, pwd: &str) -> Result<Self> {
        let mut buf = BytesMut::with_capacity(1024);
        if let Some(n) = poll_fn(|cx| Pin::new(&mut bidi).poll_recv(cx, &mut buf)).await? {
            let protocol = Protocol::parse(&buf)?;
            if pwd == protocol.password {
                match &protocol.kind {
                    Kind::TCP => Ok(Self {
                        src: bidi,
                        dst: StreamType::Tcp(TcpStream::connect(&protocol.host, protocol.port).await?),
                        // dst: Box::new(TcpStream::connect(&protocol.host, protocol.port).await?),
                        buf,
                    }),
                    Kind::UDP => Ok(Self {
                        src: bidi,
                        dst: StreamType::Udp(UdpSocket::connect(&protocol.host, protocol.port).await?),
                        // dst: Box::new(UdpSocket::connect(&protocol.host, protocol.port).await?),
                        buf,
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

    // pub fn poll_src_to_dst(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize>> {
    //     if self.buf.len() > 0 {//send left buf
    //         match ready!(&self.dst..poll_send(cx, &self.buf)) {
    //             Ok(_) => {}
    //             Err(_) => {}
    //         }
    //     }
    //     match ready!(Pin::new(&mut self.src).poll_recv(cx, &mut self.buf)) {
    //         Some(n) => {

    //         },
    //         None => {}
    //     }
    //     todo!()
    // }
}
