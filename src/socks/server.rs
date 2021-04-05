use std::{borrow::BorrowMut, path::PathBuf, sync::Arc, u8, vec};

use crate::{
    error::Result,
    quic::quic_quinn::{QuicQuinnClient, QuinnClientActor, QuinnClientHandle},
    socks::protocol::{Rep, Reply, Request},
    stream::Transfer,
};
use bytes::BytesMut;
use futures::future::try_join;
use quinn::{RecvStream, SendStream};
use tokio::{
    io::{copy, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot, Mutex},
};
use tracing::{debug, error, info, trace};

use super::protocol::{Addr, VERSION_METHOD_MESSAGE};
pub struct SocksServer {
    tcp: TcpListener,
    // quic_client: Arc<Mutex<QuicQuinnClient>>,
    socks: ActorSocksHandle,
    quinn: QuinnClientHandle,
    proxy: ActorProxyHandle,
}

impl SocksServer {
    pub async fn new(
        socks_port: Option<u16>,
        proxy_host: &str,
        proxy_port: u16,
        cert_path: Option<PathBuf>,
        passwd: String,
    ) -> Result<Self> {
        let port = socks_port.unwrap_or(1080);
        let addr = ("0.0.0.0", port);
        let tcp = TcpListener::bind(addr).await?;
        info!("Socks server bind local port: {:?}", port);

        let socks = ActorSocksHandle::new().await?;
        let server_name = proxy_host.to_string();
        let capacity = passwd.len();
        let mut password = Vec::with_capacity(capacity);
        password.push(capacity as u8);
        password.append(&mut passwd.into_bytes());
        let quinn = QuinnClientHandle::new(server_name, proxy_port, cert_path, password).await?;
        let proxy = ActorProxyHandle::default();
        Ok(Self {
            tcp,
            // quic_client: Arc::new(Mutex::new(quic)),
            socks,
            quinn,
            proxy,
        })
    }

    // pub async fn run(&mut self) -> Result<()> {
    //     while let Ok((stream, from)) = self.tcp.accept().await {
    //         trace!("Accept new stream from : {:?}", from);
    //         let quic = Arc::clone(&self.quic_client);
    //         tokio::spawn(async move {
    //             let mut quic = quic.lock().await;
    //             let mut socks_stream = SocksStream::new(stream);
    //             if let Ok(remote_addr) = socks_stream.negotiation().await {
    //                 let mut buf = BytesMut::new();
    //                 remote_addr.encode(&mut buf);
    //                 if let Ok((send, recv)) = quic.open_remote(&buf).await {
    //                     let mut transfer = Transfer::new(send, recv, socks_stream.stream());
    //                     let _ = transfer.copy().await;
    //                 }
    //             }
    //         });
    //     }
    //     Ok(())
    // }

    pub async fn start(&mut self) -> Result<()> {
        while let Ok((stream, from)) = self.tcp.accept().await {
            let trans = Transport::TCP { stream };
            let addr = self
                .socks
                .negotiation(trans, self.quinn.clone(), self.proxy.clone())
                .await?;
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

pub struct ProxyMessage {
    trans: Transport,
    recv: RecvStream,
    send: SendStream,
}

impl ProxyMessage {
    pub fn new(trans: Transport, recv: RecvStream, send: SendStream) -> Self {
        Self { trans, recv, send }
    }
}

pub struct ActorProxy {
    receiver: mpsc::Receiver<ProxyMessage>,
}

impl ActorProxy {
    pub fn new(receiver: mpsc::Receiver<ProxyMessage>) -> Self {
        Self { receiver }
    }

    pub async fn handle(&mut self, msg: ProxyMessage) {
        let ProxyMessage {
            trans,
            mut recv,
            mut send,
        } = msg;
        match trans {
            Transport::TCP { mut stream } => {
                tokio::spawn(async move {
                    trace!("Start to proxy...");
                    let (mut r, mut s) = stream.split();
                    let c1 = copy(&mut r, &mut send);
                    let c2 = copy(&mut recv, &mut s);
                    match try_join(c1, c2).await {
                        Ok((i, o)) => {
                            trace!("Transport i: {:?} bytes, o: {:?} bytes", i, o);
                        }
                        Err(err) => {
                            error!("Proxy error: {:?}", err);
                        }
                    }
                });
            }
            Transport::UDP { stream } => {
                todo!()
            }
        }
    }
}

#[derive(Clone)]
pub struct ActorProxyHandle {
    sender: mpsc::Sender<ProxyMessage>,
}

impl ActorProxyHandle {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(200);
        let actor = ActorProxy::new(receiver);
        tokio::spawn(run_proxy_actor(actor));
        Self { sender }
    }

    pub async fn proxy(&self, trans: Transport, recv: RecvStream, send: SendStream) {
        let msg = ProxyMessage::new(trans, recv, send);
        let _ = self.sender.send(msg).await;
    }
}

impl Default for ActorProxyHandle {
    fn default() -> Self {
        Self::new()
    }
}

async fn run_proxy_actor(mut actor: ActorProxy) {
    while let Some(recv) = actor.receiver.recv().await {
        actor.handle(recv).await;
    }
}

pub enum Transport {
    TCP { stream: TcpStream },
    UDP { stream: UdpSocket },
}

pub struct TransportMessage {
    trans: Transport,
    quinn: QuinnClientHandle,
    proxy: ActorProxyHandle,
}

impl TransportMessage {
    pub fn new(trans: Transport, quinn: QuinnClientHandle, proxy: ActorProxyHandle) -> Self {
        Self {
            trans,
            quinn,
            proxy,
        }
    }
}

pub struct ActorSocks {
    receiver: mpsc::Receiver<TransportMessage>,
}

impl ActorSocks {
    pub fn new(receiver: mpsc::Receiver<TransportMessage>) -> Self {
        Self { receiver }
    }

    pub async fn handle(&mut self, msg: TransportMessage) {
        let mut trans = msg.trans;
        let quinn = msg.quinn;
        let proxy = msg.proxy;
        match self.negotiation(&mut trans).await {
            Ok(addr) => {
                let mut buf = BytesMut::new();
                addr.encode(&mut buf);
                if let Ok((send, recv)) = quinn.open_remote(buf.to_vec()).await {
                    proxy.proxy(trans, recv, send).await;
                }
            }
            Err(err) => {}
        }

        // let _ = msg.respond_to.send(addr);
    }

    async fn negotiation(&mut self, trans: &mut Transport) -> Result<Addr> {
        match *trans {
            Transport::TCP { ref mut stream } => self.tcp_negotiation(stream).await,
            Transport::UDP { ref mut stream } => todo!(),
        }
    }

    async fn tcp_negotiation(&mut self, stream: &mut TcpStream) -> Result<Addr> {
        let mut buf = vec![0; 512];
        let read = stream.read(&mut buf).await?;
        trace!("Negotiation read buf: {:?}, {:?}", read, &buf[..read]);
        buf[0..VERSION_METHOD_MESSAGE.len()].copy_from_slice(&VERSION_METHOD_MESSAGE[..]);
        let i = VERSION_METHOD_MESSAGE.len();
        stream.write_all(&buf[..i]).await?;
        trace!("Negotiation write: {:?}, {:?}", i, &buf[..i]);

        let n = stream.read(&mut buf).await?;
        trace!("Sub negotiation read buf: {:?}, {:?}", n, &buf[..n]);
        let req = Request::new(&buf[..n])?;
        let reply = Reply::v5(Rep::Suceeded, &req.addr);
        let reply_buf = reply.encode();
        buf[0..reply_buf.len()].copy_from_slice(&reply_buf);
        let buf = &buf[0..reply_buf.len()];
        stream.write_all(buf).await?;
        trace!("Sub negotiation buf: {:?}", buf);
        trace!("Sub negotiation write buf: {:?}", buf.len());
        Ok(req.addr)
    }
}

#[derive(Clone)]
pub struct ActorSocksHandle {
    sender: mpsc::Sender<TransportMessage>,
}

impl ActorSocksHandle {
    pub async fn new() -> Result<Self> {
        let (sender, receiver) = mpsc::channel(200);
        let actor = ActorSocks::new(receiver);
        tokio::spawn(run_socks_actor(actor));
        Ok(Self { sender })
    }

    pub async fn negotiation(
        &self,
        trans: Transport,
        quinn: QuinnClientHandle,
        proxy: ActorProxyHandle,
    ) -> Result<()> {
        let msg = TransportMessage::new(trans, quinn, proxy);
        let _ = self.sender.send(msg).await;
        Ok(())
    }
}

pub async fn run_socks_actor(mut actor_socks: ActorSocks) {
    while let Some(recv) = actor_socks.receiver.recv().await {
        actor_socks.handle(recv).await;
    }
}
