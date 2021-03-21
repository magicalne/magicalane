use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    vec,
};

use crate::{
    error::{Error, Result},
    stream::Transfer,
    quic::quic_quinn::QuicQuinnClient,
    socks::protocol::{Rep, Reply, Request},
};
use bytes::BytesMut;
use futures::{future::poll_fn, ready, Future};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tracing::{debug, error, info, trace};

use super::protocol::{Addr, VERSION_METHOD_MESSAGE};
pub struct SocksServer {
    tcp: TcpListener,
    quic_client: Arc<Mutex<QuicQuinnClient>>,
}

impl SocksServer {
    pub async fn new(
        socks_port: Option<u16>,
        proxy_host: &str,
        proxy_port: u16,
        cert_path: Option<&str>,
        passwd: String,
    ) -> Result<Self> {
        let mut quic = QuicQuinnClient::new(proxy_host, proxy_port, cert_path).await?;
        quic.send_passwd(&passwd).await?;

        let port = socks_port.unwrap_or(1080);
        let addr = ("0.0.0.0", port);
        let tcp = TcpListener::bind(addr).await?;
        info!("Socks server bind local port: {:?}", port);
        Ok(Self {
            tcp,
            quic_client: Arc::new(Mutex::new(quic)),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Ok((stream, from)) = self.tcp.accept().await {
            trace!("Accept new stream from : {:?}", from);
            let quic = Arc::clone(&self.quic_client);
            tokio::spawn(async move {
                let mut quic = quic.lock().await;
                let mut socks_stream = SocksStream::new(stream);
                if let Ok(remote_addr) = socks_stream.negotiation().await {
                    let mut buf = BytesMut::new();
                    remote_addr.encode(&mut buf);
                    if let Ok((send, recv)) = quic.open_remote(&buf).await {
                        let mut transfer = Transfer::new(send, recv, socks_stream.stream());
                        let _ = transfer.copy().await;
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
    remote_addr: Option<Addr>,
}

impl SocksStream {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: SocksState::NegotiationRead,
            buf: vec![0; 4096].into_boxed_slice(),
            index: 0,
            remote_addr: None,
        }
    }

    pub fn stream(self) -> TcpStream {
        self.stream
    }

    pub async fn negotiation(&mut self) -> Result<Addr> {
        let read = self.stream.read(&mut self.buf).await?;
        trace!("Negotiation read buf: {:?}, {:?}", read, &self.buf[..read]);
        self.buf[0..VERSION_METHOD_MESSAGE.len()].copy_from_slice(&VERSION_METHOD_MESSAGE[..]);
        let i = VERSION_METHOD_MESSAGE.len();
        self.stream.write_all(&self.buf[..i]).await?;
        trace!("Negotiation write: {:?}, {:?}", i, &self.buf[..i]);

        let n = self.stream.read(&mut self.buf).await?;
        trace!("Sub negotiation read buf: {:?}, {:?}", n, &self.buf[..n]);
        let req = Request::new(&self.buf[..n])?;
        let reply = Reply::v5(Rep::Suceeded, &req.addr);
        let buf = reply.encode();
        self.buf[0..buf.len()].copy_from_slice(&buf);
        self.stream.write_all(&buf).await?;
        trace!("Sub negotiation write buf: {:?}", &buf.len());
        Ok(req.addr)
    }
}
