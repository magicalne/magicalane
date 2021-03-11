use std::{pin::Pin, task::{Context, Poll}, vec};

use crate::{
    error::Result,
    socks::protocol::{Rep, Reply, Request},
};
use futures::{ready, Future};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, trace};

use super::protocol::VERSION_METHOD_MESSAGE;
pub struct SocksServer {
    tcp: TcpListener,
}

impl SocksServer {
    pub async fn new(port: Option<u16>) -> Result<Self> {
        let port = port.unwrap_or(1080);
        let addr = ("0.0.0.0", port);
        let tcp = TcpListener::bind(addr).await?;
        info!("Socks server bind local port: {:?}", port);
        Ok(Self { tcp })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Ok((stream, from)) = self.tcp.accept().await {
            trace!("Accept new stream from : {:?}", from);
            tokio::spawn(async {
                let stream = SocksStream::new(stream);
                let _ = stream.await;
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
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
    buf: Box<[u8]>,
    index: usize,
}

impl SocksStream {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: SocksState::NegotiationRead,
            buf: vec![0; 4096].into_boxed_slice(),
            index: 0,
        }
    }

    async fn read(&mut self) -> Result<()> {
        let mut buf = vec![0; 1024];
        let m = self.stream.read(&mut buf).await?;
        trace!("read: {:?}, buf: {:?}", m, &buf);
        Ok(())
    }

    fn poll_negotiation_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let mut me = self.project();
        let mut buf = ReadBuf::new(&mut me.buf);
        match ready!(me.stream.poll_read(cx, &mut buf)) {
            Ok(_) => {
                let buf = buf.filled();
                let len = buf.len();
                trace!("Negotiation read buf: {:?}, {:?}", len, &buf);
                me.buf[0..VERSION_METHOD_MESSAGE.len()].copy_from_slice(&VERSION_METHOD_MESSAGE[..]);
                *me.index = VERSION_METHOD_MESSAGE.len();
                *me.state = SocksState::NegotiationWrite;
                trace!("Update state to {:?}", me.state);
                Poll::Ready(Ok(()))
            }
            Err(err) => {
                error!("Negotiation read failed: {:?}", err);
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_negotiation_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let me = self.project();
        let buf = &me.buf[0..*me.index];
        match ready!(me.stream.poll_write(cx, buf)) {
            Ok(_) => {
                trace!("Negotiation write: {:?}, {:?}", buf.len(), buf);
                *me.state = SocksState::SubNegotiationRead;
                trace!("Update state to {:?}", me.state);
                Poll::Ready(Ok(buf.len()))
            }
            Err(err) => {
                *me.state = SocksState::ReplyOnError;
                error!("Negotiation write failed: {:?}", err);
                Poll::Ready(Ok(0))
            }
        }
    }

    fn poll_sub_negotiation_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let mut me = self.project();
        let mut buf = ReadBuf::new(&mut me.buf);
        match ready!(me.stream.poll_read(cx, &mut buf)) {
            Ok(_) => {
                let buf = buf.filled();
                let len = buf.len();
                trace!("Sub negotiation read buf: {:?}, {:?}", len, &buf);
                if let Ok(req) = Request::new(buf) {
                    trace!("Read request: {:?}", &req);
                    let reply = Reply::v5(Rep::Suceeded, req.addr, req.port);
                    let buf = reply.encode();
                    me.buf[0..buf.len()].copy_from_slice(&buf);
                    *me.index = buf.len();
                    *me.state = SocksState::SubNegotiationWrite;
                    trace!("Update state to {:?}", me.state);
                    Poll::Ready(Ok(()))
                } else {
                    trace!("Parse request failed: {:?}", &buf);
                    *me.state = SocksState::ReplyOnError;
                    Poll::Ready(Ok(()))
                }
            }
            Err(err) => {
                *me.state = SocksState::ReplyOnError;
                error!("Sub negotiation read failed: {:?}", err);
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_sub_negotiation_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        let me = self.project();
        let buf = &me.buf[..*me.index];
        match ready!(me.stream.poll_write(cx, buf)) {
            Ok(_) => {
                trace!("Sub negotiation write: {:?}", buf);
                let n = *me.index;
                *me.state = SocksState::Processing;
                trace!("Update state to {:?}", me.state);
                Poll::Ready(Ok(n))
            }
            Err(err) => {
                *me.state = SocksState::ReplyOnError;
                error!("Sub negotiation write failed: {:?}", err);
                Poll::Ready(Ok(0))
            }
        }
    }
}

impl Future for SocksStream {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let me = Pin::new(&mut *self);
            match me.state {
                SocksState::NegotiationRead => {
                    let _ = ready!(me.poll_negotiation_read(cx));
                }
                SocksState::NegotiationWrite => {
                    let _ = ready!(me.poll_negotiation_write(cx));
                }
                SocksState::SubNegotiationRead => {
                    let _ = ready!(me.poll_sub_negotiation_read(cx));
                }
                SocksState::SubNegotiationWrite => {
                    let _ = ready!(me.poll_sub_negotiation_write(cx));
                }
                SocksState::Processing => {
                }
                SocksState::ReplyOnError => {
                    let _ = ready!(self.project().stream.poll_shutdown(cx));
                    trace!("Stop");
                    return Poll::Ready(Ok(()));
                }
            };
        }
    }
}
