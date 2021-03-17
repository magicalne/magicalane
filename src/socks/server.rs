use std::{pin::Pin, sync::Arc, task::{Context, Poll}, vec};

use crate::{
    error::{Error, Result},
    quic::quic_quinn::QuicQuinnClient,
    socks::protocol::{
        Rep, Reply, Request, get_remote_addr_buf
    },
};
use futures::{future::poll_fn, ready, Future};
use quinn::{crypto::rustls::TlsSession, generic::Connection};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf, ReadHalf}, net::{TcpListener, TcpStream}};
use tracing::{debug, error, info, trace};

use super::protocol::VERSION_METHOD_MESSAGE;
pub struct SocksServer {
    tcp: TcpListener,
    conn: Arc<Connection<TlsSession>>
}

impl SocksServer {
    pub async fn new(
        socks_port: Option<u16>,
        proxy_host: &str,
        proxy_port: u16,
        cert_path: Option<&str>,
        passwd: String
    ) -> Result<Self> {
        let mut quic = QuicQuinnClient::new(proxy_host, proxy_port, cert_path);
        let conn = quic.connect(&passwd).await?;

        let port = socks_port.unwrap_or(1080);
        let addr = ("0.0.0.0", port);
        let tcp = TcpListener::bind(addr).await?;
        info!("Socks server bind local port: {:?}", port);
        Ok(Self { tcp, conn: Arc::new(conn) })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Ok((stream, from)) = self.tcp.accept().await {
            trace!("Accept new stream from : {:?}", from);
            let conn = self.conn.clone();
            tokio::spawn(async move {
                let socks_stream = SocksStream::new(stream);
                let _ = socks_stream.await;
                match conn.open_bi().await {
                    Ok((send, recv)) => {

                    }
                    Err(err) => {

                    }
                }
                
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
    remote_addr: Option<Vec<u8>>
}

impl SocksStream {

    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: SocksState::NegotiationRead,
            buf: vec![0; 4096].into_boxed_slice(),
            index: 0,
            remote_addr: None
        }
    }

    fn get_stream(self) -> TcpStream {
        self.stream
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
                me.buf[0..VERSION_METHOD_MESSAGE.len()]
                    .copy_from_slice(&VERSION_METHOD_MESSAGE[..]);
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
                    let remote_addr = get_remote_addr_buf(&req.addr, req.port);
                    *me.remote_addr = Some(remote_addr);
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
        // let me = self.project();
        loop {
            // let me = Pin::new(&mut *self);
            match self.state {
                SocksState::NegotiationRead => {
                    let _ = ready!(self.as_mut().poll_negotiation_read(cx));
                }
                SocksState::NegotiationWrite => {
                    let _ = ready!(self.as_mut().poll_negotiation_write(cx));
                }
                SocksState::SubNegotiationRead => {
                    let _ = ready!(self.as_mut().poll_sub_negotiation_read(cx));
                }
                SocksState::SubNegotiationWrite => {
                    let _ = ready!(self.as_mut().poll_sub_negotiation_write(cx));
                }
                SocksState::Processing => {
                    return Poll::Ready(Ok(()))
                }
                SocksState::ReplyOnError => {
                    let _ = ready!(self.as_mut().project().stream.poll_shutdown(cx));
                    trace!("Stop");
                    return Poll::Ready(Err(Error::SocksStreamProcessFailed));
                }
            };
        }
    }
}
