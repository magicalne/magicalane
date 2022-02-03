use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::AsyncWriteExt;
use log::trace;
use quinn::{RecvStream, SendStream};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{mpsc, oneshot},
};

use crate::{
    error::{Error, Result},
    socks5::proto::Addr,
};

const CORRECT_PASSWORD_RESPONSE: u8 = 0;
const SEND_ADDR_SUCCESS_RESPONSE: u8 = 0;

#[derive(Debug)]
enum Message {
    SendPassword {
        send: SendStream,
        recv: RecvStream,
        sender: oneshot::Sender<Result<()>>,
    },
    SendAddr {
        send: SendStream,
        recv: RecvStream,
        addr: Vec<u8>,
        sender: oneshot::Sender<Result<()>>,
    },
    HandlePasswordValid {
        send: SendStream,
        recv: RecvStream,
        sender: oneshot::Sender<Result<()>>,
    },
    HandleOpenRemote {
        send: SendStream,
        recv: RecvStream,
        sender: oneshot::Sender<Result<(SendStream, RecvStream, TcpStream)>>,
    },
}

impl Message {
    fn send_passwd_req(
        send: SendStream,
        recv: RecvStream,
        sender: oneshot::Sender<Result<()>>,
    ) -> Self {
        Self::SendPassword { send, recv, sender }
    }

    fn send_addr_req(
        send: SendStream,
        recv: RecvStream,
        addr: Vec<u8>,
        sender: oneshot::Sender<Result<()>>,
    ) -> Self {
        Self::SendAddr {
            send,
            recv,
            addr,
            sender,
        }
    }

    fn handle_passwd_req(
        send: SendStream,
        recv: RecvStream,
        sender: oneshot::Sender<Result<()>>,
    ) -> Self {
        Self::HandlePasswordValid { send, recv, sender }
    }

    fn handle_open_remote_req(
        send: SendStream,
        recv: RecvStream,
        sender: oneshot::Sender<Result<(SendStream, RecvStream, TcpStream)>>,
    ) -> Self {
        Self::HandleOpenRemote { send, recv, sender }
    }
}
pub struct StreamActor {
    receiver: mpsc::Receiver<Message>,
    passwd: Vec<u8>,
}

impl StreamActor {
    fn new(receiver: mpsc::Receiver<Message>, passwd: Vec<u8>) -> Self {
        Self { receiver, passwd }
    }

    async fn handle(&mut self, msg: Message) {
        trace!("Accept message: {:?}", &msg);
        match msg {
            Message::SendPassword { send, recv, sender } => {
                let res = self.send_passwd(send, recv).await;
                let _ = sender.send(res);
            }
            Message::SendAddr {
                send,
                recv,
                addr,
                sender,
            } => {
                let res = self.send_addr(send, recv, addr).await;
                let _ = sender.send(res);
            }
            Message::HandlePasswordValid { send, recv, sender } => {
                let res = self.validate_passwd(send, recv).await;
                let _ = sender.send(res);
            }
            Message::HandleOpenRemote { send, recv, sender } => {
                let res = self.open_remote(send, recv).await;
                let _ = sender.send(res);
            }
        }
    }

    async fn send_passwd(&mut self, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        trace!("Send password: {:?}", &self.passwd);
        let mut buf = vec![self.passwd.len() as u8];
        buf.extend_from_slice(&self.passwd);
        send.write_all(&buf).await?;
        trace!("Send password successfully.");
        send.flush().await?;
        let mut buf = [0u8; 1];
        recv.read_exact(&mut buf).await?;
        if buf[0] == CORRECT_PASSWORD_RESPONSE {
            Ok(())
        } else {
            Err(Error::WrongPassword)
        }
    }

    async fn send_addr(
        &mut self,
        mut send: SendStream,
        mut recv: RecvStream,
        addr: Vec<u8>,
    ) -> Result<()> {
        send.write_all(&addr).await?;
        send.flush().await?;
        let mut buf = [0u8; 1];
        recv.read_exact(&mut buf).await?;
        if buf[0] == SEND_ADDR_SUCCESS_RESPONSE {
            Ok(())
        } else {
            Err(Error::OpenRemoteAddrError)
        }
    }

    async fn validate_passwd(&mut self, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        let mut buf = vec![0; 128];
        if let Some(n) = recv.read(&mut buf).await? {
            if buf[..n] == self.passwd {
                let buf = [0u8; 1];
                send.write_all(&buf).await?;
            } else {
                let buf = [1u8; 1];
                send.write_all(&buf).await?;
            }
        }
        Ok(())
    }

    async fn open_remote(
        &mut self,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<(SendStream, RecvStream, TcpStream)> {
        let mut buf = vec![0; 1024];
        match recv.read(&mut buf).await? {
            Some(n) => {
                let addr = Addr::new(&buf[..n])?;
                let tcp_stream = match addr {
                    Addr::SocketAddr(ip) => TcpStream::connect(ip).await?,
                    Addr::DomainName(domain, port) => {
                        let domain = std::str::from_utf8(&domain)?;
                        let socket = (domain, port);
                        TcpStream::connect(socket).await?
                    }
                };
                let buf = [0u8; 1];
                send.write_all(&buf).await?;
                Ok((send, recv, tcp_stream))
            }
            None => Err(Error::EmptyRemoteAddrError),
        }
    }
}

async fn run_stream_actor(mut actor: StreamActor) {
    trace!("StreamActor is running...");
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle(msg).await;
    }
}

#[derive(Clone)]
pub struct StreamActorHandler {
    sender: mpsc::Sender<Message>,
}

impl StreamActorHandler {
    pub fn new(passwd: Vec<u8>) -> Self {
        let (sender, receiver) = mpsc::channel(200);
        let actor = StreamActor::new(receiver, passwd);
        tokio::spawn(run_stream_actor(actor));
        Self { sender }
    }

    pub async fn send_passwd(&mut self, send: SendStream, recv: RecvStream) -> Result<()> {
        let (sender, respond_to) = oneshot::channel();
        let msg = Message::send_passwd_req(send, recv, sender);
        let _ = self.sender.send(msg).await;
        respond_to.await?
    }

    pub async fn send_addr(
        &mut self,
        send: SendStream,
        recv: RecvStream,
        addr: Addr,
    ) -> Result<()> {
        let (sender, respond_to) = oneshot::channel();
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        let addr = buf.to_vec();
        let msg = Message::send_addr_req(send, recv, addr, sender);
        let _ = self.sender.send(msg).await;
        respond_to.await?
    }

    pub async fn validate_passwd(&mut self, send: SendStream, recv: RecvStream) -> Result<()> {
        let (sender, respond_to) = oneshot::channel();
        let msg = Message::handle_passwd_req(send, recv, sender);
        let _ = self.sender.send(msg).await;
        respond_to.await?
    }

    pub async fn open_remote(
        &mut self,
        send: SendStream,
        recv: RecvStream,
    ) -> Result<(SendStream, RecvStream, TcpStream)> {
        let (sender, respond_to) = oneshot::channel();
        let msg = Message::handle_open_remote_req(send, recv, sender);
        let _ = self.sender.send(msg).await;
        respond_to.await?
    }
}

#[pin_project::pin_project]
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
        let me = self.project();
        me.recv.poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        self.project().send.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        self.project().send.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        self.project().send.poll_shutdown(cx)
    }
}
