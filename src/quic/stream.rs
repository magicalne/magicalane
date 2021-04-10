use futures::AsyncWriteExt;
use quinn::{RecvStream, SendStream};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
};

use crate::{
    error::{Error, Result},
    socks::protocol::Addr,
};

const CORRECT_PASSWORD_RESPONSE: u8 = 0;

enum Message {
    SendPassword {
        send: SendStream,
        recv: RecvStream,
        passwd: Vec<u8>,
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
        passwd: Vec<u8>,
        sender: oneshot::Sender<Result<()>>,
    ) -> Self {
        Self::SendPassword {
            send,
            recv,
            passwd,
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
    passwd: Option<Vec<u8>>,
}

impl StreamActor {
    fn new(receiver: mpsc::Receiver<Message>, passwd: Option<Vec<u8>>) -> Self {
        Self { receiver, passwd }
    }

    async fn handle(&mut self, msg: Message) {
        match msg {
            Message::SendPassword {
                send,
                recv,
                passwd,
                sender,
            } => {
                let res = self.send_passwd(send, recv, passwd).await;
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

    async fn send_passwd(
        &mut self,
        mut send: SendStream,
        mut recv: RecvStream,
        passwd: Vec<u8>,
    ) -> Result<()> {
        send.write_all(&passwd).await?;
        send.flush().await?;
        let mut buf = [0u8; 1];
        recv.read_exact(&mut buf).await?;
        if buf[0] == CORRECT_PASSWORD_RESPONSE {
            Ok(())
        } else {
            Err(Error::WrongPassword)
        }
    }

    async fn validate_passwd(&mut self, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        let mut buf = vec![0; 128];
        if let Some(n) = recv.read(&mut buf).await? {
            match self.passwd.as_ref() {
                Some(pwd) => {
                    if &buf[..n] == pwd {
                        let buf = [0u8; 1];
                        send.write_all(&buf).await?;
                    } else {
                        let buf = [1u8; 1];
                        send.write_all(&buf).await?;
                    }
                }
                None => {
                    let buf = [1u8; 1];
                    send.write_all(&buf).await?;
                }
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
                let addr = Addr::decode(&buf[..n])?;
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
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle(msg).await;
    }
}

#[derive(Clone)]
pub struct StreamActorHandler {
    sender: mpsc::Sender<Message>,
}

impl StreamActorHandler {
    pub fn new(passwd: Option<Vec<u8>>) -> Self {
        let (sender, receiver) = mpsc::channel(200);
        let actor = StreamActor::new(receiver, passwd);
        tokio::spawn(run_stream_actor(actor));
        Self { sender }
    }

    pub async fn send_passwd(
        &mut self,
        send: SendStream,
        recv: RecvStream,
        passwd: Vec<u8>,
    ) -> Result<()> {
        let (sender, respond_to) = oneshot::channel();
        let msg = Message::send_passwd_req(send, recv, passwd, sender);
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
