use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    error::Result,
    socks::protocol::{Rep, Reply, Request},
};
use bytes::BytesMut;
use futures::{ready, Future};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};

use super::protocol::VERSION_METHOD_MESSAGE;
pub struct SocksServer {
    tcp: TcpListener,
}

impl SocksServer {
    pub async fn new(port: Option<u16>) -> Result<Self> {
        let port = port.unwrap_or(1080);
        let addr = ("0.0.0.0", port);
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self { tcp })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Ok((stream, _)) = self.tcp.accept().await {
            tokio::spawn(async {
                let stream = SocksStream::new(stream);
            });
        }
        Ok(())
    }
}

enum SocksState {
    NegotiationRead,
    NegotiationWrite,
    SubNegotiationRead,
    SubNegotiationWrite,
    Processing,
    ReplyOnError,
}

#[pin_project::pin_project]
struct SocksStream {
    #[pin]
    stream: TcpStream,
    state: SocksState,
    recv_buf: BytesMut,
    send_buf: BytesMut,
}

impl SocksStream {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: SocksState::NegotiationRead,
            recv_buf: BytesMut::with_capacity(1024),
            send_buf: BytesMut::with_capacity(1024),
        }
    }

    fn poll_negotiation_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let mut me = self.project();
        let mut buf = ReadBuf::new(&mut me.recv_buf);
        match ready!(me.stream.poll_read(cx, &mut buf)) {
            Ok(_) => {
                me.send_buf.copy_from_slice(&VERSION_METHOD_MESSAGE);
                *me.state = SocksState::NegotiationWrite;
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_negotiation_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let me = self.project();
        match ready!(me.stream.poll_write(cx, me.send_buf)) {
            Ok(_) => {
                let n = me.send_buf.len();
                me.send_buf.clear();
                *me.state = SocksState::SubNegotiationRead;
                Poll::Ready(Ok(n))
            }
            Err(_) => {
                *me.state = SocksState::ReplyOnError;
                Poll::Ready(Ok(0))
            }
        }
    }

    fn poll_sub_negotiation_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let mut me = self.project();
        let mut buf = ReadBuf::new(&mut me.recv_buf);
        match ready!(me.stream.poll_read(cx, &mut buf)) {
            Ok(_) => {
                if let Ok(req) = Request::new(me.recv_buf) {
                    let reply = Reply::v5(Rep::Suceeded, req.addr, req.port);
                    let buf = reply.encode();
                    me.send_buf.copy_from_slice(&buf);
                    *me.state = SocksState::SubNegotiationWrite;
                    Poll::Ready(Ok(()))
                } else {
                    *me.state = SocksState::ReplyOnError;
                    Poll::Ready(Ok(()))
                }
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_sub_negotiation_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let me = self.project();
        match ready!(me.stream.poll_write(cx, me.send_buf)) {
            Ok(_) => {
                let n = me.send_buf.len();
                me.send_buf.clear();
                *me.state = SocksState::Processing;
                Poll::Ready(Ok(n))
            }
            Err(_) => {
                *me.state = SocksState::ReplyOnError;
                Poll::Ready(Ok(0))
            }
        }
    }

}

impl Future for SocksStream {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = Pin::new(&mut *self);
        match me.state {
            SocksState::NegotiationRead => {
                let _ = ready!(me.poll_negotiation_read(cx));
                Poll::Pending
            }
            SocksState::NegotiationWrite => {
                let _ = me.poll_negotiation_write(cx);
                Poll::Pending
            }
            SocksState::SubNegotiationRead => {
                let _ = me.poll_sub_negotiation_read(cx);
                Poll::Pending
            }
            SocksState::SubNegotiationWrite => {
                let _= me.poll_sub_negotiation_write(cx);
                Poll::Pending
            }
            SocksState::Processing => {
                todo!()
            }
            SocksState::ReplyOnError => {
                let _ = ready!(self.project().stream.poll_shutdown(cx));
                Poll::Ready(Ok(()))
            }
        }
    }
}
