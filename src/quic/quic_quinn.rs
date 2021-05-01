use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    u8, usize,
};

use bytes::{BufMut, BytesMut};
use futures::{ready, FutureExt, Stream, StreamExt, TryStreamExt};
use quinn::{
    crypto::rustls::TlsSession, generic::ServerConfig, Endpoint, NewConnection, RecvStream,
    SendStream,
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_trace::log::warn;
use tracing::{error, trace};

use crate::{
    error::{Error, Result},
    generate_key_and_cert_der, load_private_cert, load_private_key,
    socks::protocol::Addr,
    stream::Transfer,
    ALPN_QUIC,
};

const PASSWORD_VALIDATE_RESPONSE: [u8; 1] = [0];
const OPEN_REMOTE_FAILED_RESPONSE: [u8; 1] = [0];

pub struct QuinnStream<'a> {
    send: &'a mut SendStream,
    recv: &'a mut RecvStream,
}

impl<'a> QuinnStream<'a> {
    pub fn new(send: &'a mut SendStream, recv: &'a mut RecvStream) -> Self {
        Self { send, recv }
    }

    pub async fn send_open_remote(&mut self, buf: &[u8]) -> Result<()> {
        self.send.write_all(buf).await?;
        let mut buf = [0; 1];
        match self.recv.read(&mut buf).await? {
            Some(n) => {
                trace!("Read {:?} bytes", n);
                if OPEN_REMOTE_FAILED_RESPONSE == buf {
                    trace!("Open remote failed");
                    Err(Error::OpenRemoteAddrError)
                } else {
                    trace!("Open remote successfully.");
                    Ok(())
                }
            }
            None => {
                trace!("Connection is closed");
                Err(Error::NotConnectedError)
            }
        }
    }

    pub async fn send_password(&mut self, passwd: &[u8]) -> Result<()> {
        trace!("Send password: {:?}", passwd);
        self.send.write_all(passwd).await?;
        let mut buf = [0; 1];
        match self.recv.read(&mut buf).await? {
            Some(n) => {
                trace!("Read {:?} bytes", n);
                return if PASSWORD_VALIDATE_RESPONSE == buf[..n] {
                    trace!("Password is validate.");
                    Ok(())
                } else {
                    warn!("Wrong password");
                    Err(Error::WrongPassword)
                };
            }
            None => {
                trace!("Connection is closed.");
                Err(Error::NotConnectedError)
            }
        }
    }

    pub async fn validate_password(&mut self, password: &str) -> Result<()> {
        trace!("Validate password");
        let mut buf = vec![0; 1024];
        match self.recv.read(&mut buf).await? {
            Some(n) => {
                trace!("Recv {:?} bytes from client.", n,);
                if let Some(len) = buf.get(0) {
                    let len = *len as usize;
                    if len > buf.len() {
                        trace!("buf: {:?}", buf);
                        return Err(Error::ParsePasswordFail);
                    } else {
                        let buf = &buf[1..1 + len];
                        if len != password.len() || buf != password.as_bytes() {
                            error!("Wrong password: {:?}", buf);
                            Err(Error::WrongPassword)
                        } else {
                            self.send.write_all(&PASSWORD_VALIDATE_RESPONSE).await?;
                            self.send.finish().await?;
                            trace!("Password is validate.");
                            Ok(())
                        }
                    }
                } else {
                    error!("Wrong password");
                    Err(Error::ParsePasswordFail)
                }
            }
            None => {
                trace!("Connection is closed");
                Err(Error::NotConnectedError)
            }
        }
    }

    pub async fn open_remote(&mut self) -> Result<TcpStream> {
        let mut buf = vec![0; 1024];
        let remote = match self.recv.read(&mut buf).await? {
            Some(n) => match Addr::decode(&buf[..n])? {
                Addr::SocketAddr(ip) => Some(TcpStream::connect(ip).await),
                Addr::DomainName(domain, port) => {
                    let domain = std::str::from_utf8(&domain)?;
                    let socket = (domain, port);
                    Some(TcpStream::connect(socket).await)
                }
            },
            None => None,
        };
        trace!("Connect remote: {:?}", &remote);
        match remote {
            Some(remote) => {
                buf.clear();
                match remote {
                    Ok(remote) => {
                        buf.put_u8(1);
                        self.send.write_all(&buf[0..1]).await?;
                        trace!("Connection is setup. Notify client.");
                        Ok(remote)
                    }
                    Err(err) => {
                        buf.put_u8(0);
                        self.send.write_all(&buf[0..1]).await?;
                        trace!("Failed to open remote: {:?}", &err);
                        Err(Error::IoError(err))
                    }
                }
            }
            None => Err(Error::NotConnectedError),
        }
    }
}

pub struct Connection {
    connection: quinn::generic::Connection<TlsSession>,
    password: String,
}

impl Connection {
    pub fn new(conn: quinn::generic::Connection<TlsSession>, password: String) -> Self {
        Self {
            connection: conn,
            password,
        }
    }

    pub async fn validate_password(&mut self) -> Result<()> {
        trace!("Validate password");
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let mut buf = BytesMut::new();
        match recv.read(&mut buf).await? {
            Some(n) => {
                trace!(
                    "Recv {:?} bytes from client: {:?}.",
                    n,
                    self.connection.remote_address()
                );
                if let Some(len) = buf.get(0) {
                    let len = *len as usize;
                    if len != buf.len() + 1 {
                        return Err(Error::ParsePasswordFail);
                    } else {
                        let buf = &buf[1..1 + len];
                        if len != self.password.len() || buf != self.password.as_bytes() {
                            Err(Error::WrongPassword)
                        } else {
                            send.write_all(&PASSWORD_VALIDATE_RESPONSE).await?;
                            send.finish().await?;
                            trace!("Password is validate.");
                            Ok(())
                        }
                    }
                } else {
                    Err(Error::ParsePasswordFail)
                }
            }
            None => Err(Error::NotConnectedError),
        }
    }

    pub async fn open_remote(&mut self) -> Result<Transfer> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let mut buf = vec![0; 1024];
        let remote = match recv.read(&mut buf).await? {
            Some(n) => match Addr::decode(&buf[..n])? {
                Addr::SocketAddr(ip) => Some(TcpStream::connect(ip).await),
                Addr::DomainName(domain, port) => {
                    let domain = std::str::from_utf8(&domain)?;
                    let socket = (domain, port);
                    Some(TcpStream::connect(socket).await)
                }
            },
            None => None,
        };
        trace!("remote: {:?}", &remote);
        match remote {
            Some(remote) => {
                buf.clear();
                match remote {
                    Ok(remote) => {
                        buf.put_u8(0);
                        send.write_all(&buf[0..1]).await?;
                        let transfer = Transfer::new(send, recv, remote);
                        Ok(transfer)
                    }
                    Err(err) => {
                        buf.put_u8(0);
                        send.write_all(&buf[0..1]).await?;
                        trace!("Failed to open remote: {:?}", &err);
                        Err(Error::IoError(err))
                    }
                }
            }
            None => Err(Error::NotConnectedError),
        }
    }
}

impl Stream for Connection {
    type Item = Result<(SendStream, RecvStream)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.connection.open_bi().poll_unpin(cx)) {
            Ok((send, recv)) => Poll::Ready(Some(Ok((send, recv)))),
            Err(err) => Poll::Ready(Some(Err(Error::QuinnConnectionError(err)))),
        }
    }
}

pub struct QuicQuinnClient {
    conn: quinn::generic::Connection<TlsSession>,
    buf: BytesMut,
}

impl QuicQuinnClient {
    pub async fn new(host: &str, port: u16, cert_path: Option<PathBuf>) -> Result<Self> {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(ALPN_QUIC);
        client_config.enable_keylog();
        cert_path
            .map(|path| {
                fs::read(path)
                    .map(|cert| quinn::Certificate::from_der(&cert))
                    .map(|cert| match cert {
                        Ok(cert) => {
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
        let remote = (host, port)
            .to_socket_addrs()?
            .find(|add| add.is_ipv4())
            .ok_or(Error::UnknownRemoteHost)?;
        trace!("Connect remote: {:?}", &remote);
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.default_client_config(config);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // Bind this endpoint to a UDP socket on the given client address.
        let (endpoint, incoming) = endpoint_builder.bind(&addr)?;
        trace!("Client bind endpoint: {:?}", &addr);

        // Connect to the server passing in the server name which is supposed to be in the server certificate.
        let connection = endpoint.connect(&remote, host)?.await?;
        let NewConnection { connection, .. } = connection;
        Ok(Self {
            conn: connection,
            buf: BytesMut::with_capacity(128),
        })
    }

    pub async fn send_passwd(&mut self, password: &str) -> Result<()> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        let mut buf = &mut self.buf;
        buf.put_u8(password.len() as u8);
        buf.put_slice(password.as_bytes());
        let slice = &buf[0..password.len() + 1];
        trace!("Sending: {:?} bytes, {:?}", slice.len(), slice);
        send.write_all(slice).await?;
        trace!("Sent password validation request.");
        match recv.read(&mut buf).await? {
            Some(n) => {
                trace!("Password validate successfully. n: {:?}", n);
                Ok(())
            }
            None => {
                trace!("Close connection due to wrong password.");
                Err(Error::WrongPassword)
            }
        }
    }

    pub async fn open_remote(&mut self, buf: &[u8]) -> Result<(SendStream, RecvStream)> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        send.write_all(buf).await?;
        trace!("Sent open remote request.");
        match recv.read(&mut self.buf).await? {
            Some(1) => {
                trace!("Open remote successfully.");
                Ok((send, recv))
            }
            Some(n) => {
                trace!("Cannot open remote: {:?}", &self.buf[..n]);
                Err(Error::OpenRemoteAddrError)
            }
            None => {
                trace!("Connection is closed.");
                Err(Error::NotConnectedError)
            }
        }
    }
}

pub struct QuinnServer {
    incoming: quinn::generic::Incoming<TlsSession>,
    password: String,
}

impl QuinnServer {
    pub async fn new(
        key_cert: Option<(PathBuf, PathBuf)>,
        port: u16,
        password: String,
    ) -> Result<Self> {
        let mut endpoint_builder = Endpoint::builder();
        let server_config = ServerConfig::default();
        let mut server_config = quinn::ServerConfigBuilder::new(server_config);
        server_config.enable_keylog();
        let (key, cert) = key_cert.unwrap_or(generate_key_and_cert_der()?);
        let key = load_private_key(key.as_path())?;
        let cert_chain = load_private_cert(cert.as_path())?;
        server_config.certificate(cert_chain, key)?;
        server_config.protocols(ALPN_QUIC);
        endpoint_builder.listen(server_config.build());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let (_, incoming) = endpoint_builder.bind(&addr)?;
        trace!("Quic server bind: {:?}", &addr);
        Ok(Self { password, incoming })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some(connecting) = self.incoming.next().await {
            trace!("connecting from remote: {:?}", &connecting.remote_address());
            match connecting.await {
                Ok(quinn::generic::NewConnection { mut bi_streams, .. }) => {
                    let password = self.password.clone();
                    tokio::spawn(async move {
                        if let Some((mut send, mut recv)) = bi_streams.try_next().await? {
                            let mut stream = QuinnStream::new(&mut send, &mut recv);
                            stream.validate_password(&password).await?;
                        }
                        while let Some((mut send, mut recv)) = bi_streams.try_next().await? {
                            tokio::spawn(async move {
                                trace!("Accept open remote request");
                                let mut stream = QuinnStream::new(&mut send, &mut recv);
                                let remote = stream.open_remote().await?;
                                let mut transfer = Transfer::new(send, recv, remote);
                                transfer.copy().await?;
                                Ok::<(), Error>(())
                            });
                        }
                        Ok::<(), Error>(())
                    });
                }
                Err(err) => {
                    trace!("Connection error: {:?}", err);
                }
            }
        }
        Ok(())
    }
}

impl Stream for QuinnServer {
    type Item = Result<Connection>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.incoming).poll_next_unpin(cx)) {
            Some(mut c) => {
                trace!("connecting from remote: {:?}", &c.remote_address());
                match ready!(c.poll_unpin(cx)) {
                    Ok(quinn::generic::NewConnection { connection, .. }) => {
                        trace!("Accept new connection: {:?}", &connection.remote_address());
                        Poll::Ready(Some(Ok(Connection::new(connection, self.password.clone()))))
                    }
                    Err(err) => {
                        trace!("Connection error: {:?}", err);
                        Poll::Ready(Some(Err(Error::QuinnConnectionError(err))))
                    }
                }
            }
            None => Poll::Ready(None),
        }
    }
}

pub async fn run_quinn_client_actor(mut actor: QuinnClientActor) {
    while let Some(recv) = actor.receiver.recv().await {
        actor.handle(recv).await;
    }
}

pub struct QuinnClientActor {
    pub receiver: mpsc::Receiver<OpenRemoteMessage>,
    remote_addr: SocketAddr,
    endpoint: Endpoint,
    password: Vec<u8>,
    server_name: String,
    connection: Option<quinn::Connection>,
}

impl QuinnClientActor {
    pub async fn new(
        server_name: String,
        port: u16,
        cert_path: Option<PathBuf>,
        password: Vec<u8>,
        receiver: mpsc::Receiver<OpenRemoteMessage>,
    ) -> Result<Self> {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(ALPN_QUIC);
        client_config.enable_keylog();
        cert_path
            .map(|path| {
                fs::read(path)
                    .map(|cert| quinn::Certificate::from_der(&cert))
                    .map(|cert| match cert {
                        Ok(cert) => {
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
        trace!("Connect remote: {:?}", &remote_addr);
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.default_client_config(config);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // Bind this endpoint to a UDP socket on the given client address.
        let (endpoint, _) = endpoint_builder.bind(&addr)?;
        trace!("Client bind endpoint: {:?}", &addr);

        Ok(Self {
            receiver,
            remote_addr,
            endpoint,
            password,
            server_name,
            connection: None,
        })
    }

    pub async fn open_conn(&mut self) -> Result<()> {
        if self.connection.is_none() {
            let connection = self
                .endpoint
                .connect(&self.remote_addr, &self.server_name)?
                .await?;
            let NewConnection { connection, .. } = connection;
            let (mut send, mut recv) = connection.open_bi().await?;
            let mut stream = QuinnStream::new(&mut send, &mut recv);
            stream.send_password(&self.password).await?;
            trace!("Sent password");
            self.connection = Some(connection);
        }
        Ok(())
    }

    /**
    Send proxy info to remote server.
    */
    pub async fn handle(&mut self, msg: OpenRemoteMessage) {
        if let Err(err) = self.open_conn().await {
            error!("open connection failed: {:?}", &err);
            let _ = &msg.respond(Err(err));
            return;
        }
        if let Some(connection) = self.connection.as_mut() {
            trace!("Processing open remote message.");
            match connection.open_bi().await {
                Ok((mut send, mut recv)) => {
                    trace!("Open remote addr");
                    let mut stream = QuinnStream::new(&mut send, &mut recv);
                    match stream.send_open_remote(&msg.get_buf()).await {
                        Ok(_) => {
                            let _ = &msg.respond(Ok((send, recv)));
                        }
                        Err(err) => {
                            trace!("Open remote failed");
                            let _ = &msg.respond(Err(err));
                        }
                    }
                }
                Err(err) => {
                    error!("Not connected");
                    let _ = &msg.respond(Err(Error::QuinnConnectionError(err)));
                }
            }
            if let Ok((mut send, recv)) = connection.open_bi().await {
                send.write_all(b"asdfasdf").await.expect("cannot write");
                let _ = send.finish().await;
                trace!("Send something....");
            }
        }
    }
}

#[derive(Clone)]
pub struct QuinnClientHandle {
    sender: mpsc::Sender<OpenRemoteMessage>,
}

impl QuinnClientHandle {
    pub async fn new(
        server_name: String,
        port: u16,
        cert_path: Option<PathBuf>,
        password: Vec<u8>,
    ) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(200);
        let actor = QuinnClientActor::new(server_name, port, cert_path, password, receiver).await?;
        tokio::spawn(run_quinn_client_actor(actor));

        Ok(Self { sender })
    }

    pub async fn open_remote(&self, buf: Vec<u8>) -> Result<(SendStream, RecvStream)> {
        let (send, recv) = oneshot::channel();
        let msg = OpenRemoteMessage::new(buf, send);
        let _ = self.sender.send(msg).await;
        recv.await?
    }
}

pub struct OpenRemoteMessage {
    buf: Vec<u8>,
    respond_to: oneshot::Sender<Result<(SendStream, RecvStream)>>,
}

impl OpenRemoteMessage {
    pub fn new(
        buf: Vec<u8>,
        respond_to: oneshot::Sender<Result<(SendStream, RecvStream)>>,
    ) -> Self {
        Self { buf, respond_to }
    }

    pub fn respond(self, response: Result<(SendStream, RecvStream)>) {
        let _ = self.respond_to.send(response);
    }

    pub fn get_buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
