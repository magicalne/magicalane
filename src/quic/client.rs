use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    u8,
};

use crate::socks5::proto::Addr;
use bytes::BytesMut;
use futures::{future::poll_fn, AsyncWrite};
use log::{error, trace};
use quinn::{Connection, Endpoint, NewConnection, RecvStream, SendStream};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::{mpsc, oneshot};
use tokio_util::io::{poll_read_buf, poll_write_buf};

use crate::{
    error::{Error, Result},
    quic::{SOCKET_RECV_BUF_SIZE, SOCKET_SEND_BUF_SIZE},
    ALPN_QUIC,
};

use super::stream::{QuicStream, StreamActorHandler};

pub struct Client {
    remote_addr: SocketAddr,
    endpoint: Endpoint,
    server_name: String,
}

impl Client {
    pub async fn new(server_name: String, port: u16, cert_path: Option<PathBuf>) -> Result<Self> {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(ALPN_QUIC);
        client_config.enable_keylog();
        cert_path
            .map(|path| {
                // This is for self-signed.
                fs::read(path)
                    .map(|cert| quinn::Certificate::from_pem(&cert))
                    .map(|cert| match cert {
                        Ok(cert) => {
                            trace!("Add cert: {:?}", &cert);
                            if let Err(err) = client_config.add_certificate_authority(cert) {
                                error!("Client add cert failed: {:?}.", err);
                            }
                        }
                        Err(err) => {
                            error!("Client parse cert error: {:?}.", err);
                        }
                    })
            })
            .map(|r| {
                r.map_err(|err| {
                    error!("Client config cert with error: {:?}.", err);
                })
            });
        let config = client_config.build();
        let remote_addr = (server_name.as_str(), port)
            .to_socket_addrs()?
            .find(|add| add.is_ipv4())
            .ok_or(Error::UnknownRemoteHost)?;
        trace!(
            "Connect remote: {:?}, server name: {:?}",
            &remote_addr,
            &server_name
        );
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.default_client_config(config);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        // Bind this endpoint to a UDP socket on the given client address.
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let addr = addr.into();
        socket.bind(&addr)?;
        socket.set_recv_buffer_size(SOCKET_RECV_BUF_SIZE)?;
        socket.set_send_buffer_size(SOCKET_SEND_BUF_SIZE)?;
        let udp = socket.into();
        let (endpoint, _) = endpoint_builder.with_socket(udp)?;
        trace!("Client bind: {:?}", &addr);

        Ok(Self {
            remote_addr,
            endpoint,
            server_name,
        })
    }

    pub async fn open_conn(&mut self) -> Result<Connection> {
        let connection = self
            .endpoint
            .connect(&self.remote_addr, &self.server_name)?
            .await?;
        let NewConnection { connection, .. } = connection;
        Ok(connection)
    }
}

struct ClientActor {
    client: Client,
    receiver: mpsc::Receiver<Message>,
    stream_handler: StreamActorHandler,
    conn: Option<Connection>,
    buf: BytesMut,
}

impl ClientActor {
    fn new(client: Client, receiver: mpsc::Receiver<Message>, passwd: Vec<u8>) -> Self {
        let stream_handler = StreamActorHandler::new(passwd);
        Self {
            client,
            receiver,
            stream_handler,
            conn: None,
            buf: BytesMut::new(),
        }
    }

    async fn handle(&mut self, msg: Message) {
        match msg {
            Message::OpenStream {
                sender,
                remote_addr,
            } => loop {
                if self.conn.is_none() {
                    // Open a new connection.
                    match self.client.open_conn().await {
                        Ok(conn) => {
                            if let Ok((send, recv)) = conn.open_bi().await {
                                match self.stream_handler.send_passwd(send, recv).await {
                                    Ok(_) => {
                                        self.conn = Some(conn);
                                    }
                                    Err(err) => {
                                        trace!("Send password failed: {:?}", err);
                                        return;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            trace!("Cannot connect to quic server: {:?}", err);
                            let _ = sender.send(Err(err));
                            return;
                        }
                    }
                }
                let conn = self.conn.as_mut().unwrap();
                match conn.open_bi().await {
                    Ok((mut send, mut recv)) => {
                        self.buf.clear();
                        remote_addr.encode(&mut self.buf);
                        if let Err(err) =
                            poll_fn(|cx| poll_write_buf(Pin::new(&mut send), cx, &mut self.buf))
                                .await
                        {
                            trace!("Write failed: {:?}", err);
                            self.conn = None;
                            continue;
                        }
                        if let Err(err) = poll_fn(|cx| Pin::new(&mut send).poll_flush(cx)).await {
                            trace!("Flush failed: {:?}", err);
                            self.conn = None;
                            continue;
                        }
                        self.buf.clear();
                        if let Err(err) =
                            poll_fn(|cx| poll_read_buf(Pin::new(&mut recv), cx, &mut self.buf))
                                .await
                        {
                            trace!("Read failed: {:?}", err);
                            self.conn = None;
                            continue;
                        }
                        let _ = match self.buf[0] {
                            0 => sender.send(Ok((send, recv))),
                            _ => sender.send(Err(Error::OpenRemoteError)),
                        };
                        return;
                    }
                    Err(err) => {
                        trace!("Open stream failed: {:?}", err);
                        self.conn = None;
                    }
                }
            },
        }
    }
}

enum Message {
    OpenStream {
        remote_addr: Addr,
        sender: oneshot::Sender<Result<(SendStream, RecvStream)>>,
    },
}

#[derive(Clone)]
pub struct ClientActorHndler {
    sender: mpsc::Sender<Message>,
}

impl ClientActorHndler {
    pub async fn new(
        server_name: String,
        port: u16,
        cert_path: Option<PathBuf>,
        passwd: Vec<u8>,
    ) -> Result<Self> {
        let client = Client::new(server_name, port, cert_path).await?;
        let (sender, receiver) = mpsc::channel(200);
        let actor = ClientActor::new(client, receiver, passwd);
        tokio::spawn(run_client_actor(actor));
        Ok(Self { sender })
    }

    pub async fn open_bi(self, remote_addr: Addr) -> io::Result<QuicStream> {
        let (sender, respond_to) = oneshot::channel();
        let msg = Message::OpenStream {
            sender,
            remote_addr,
        };
        let _ = self.sender.send(msg).await;
        let (send, recv) = respond_to
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let stream = QuicStream::new(recv, send);
        Ok(stream)
    }
}

async fn run_client_actor(mut actor: ClientActor) {
    trace!("Accecpt client request.");
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle(msg).await;
    }
}
