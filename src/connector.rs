use std::io;

use futures::future::BoxFuture;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::{
    quic::{self, stream::QuicStream},
    socks5::proto::Addr,
};

pub trait Connector: Clone {
    type Connection: AsyncRead + AsyncWrite + Unpin;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>>;
}

#[derive(Clone)]
pub struct LocalConnector;

impl Connector for LocalConnector {
    type Connection = TcpStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        match a {
            Addr::SocketAddr(addr) => Box::pin(TcpStream::connect(addr)),
            Addr::DomainName(host, port) => {
                let addr = (String::from_utf8(host).unwrap(), port);
                Box::pin(TcpStream::connect(addr))
            }
        }
    }
}

#[derive(Clone)]
pub struct QuicConnector {
    quic_client: quic::client::ClientActorHndler,
}

impl QuicConnector {
    pub fn new(quic_client: quic::client::ClientActorHndler) -> Self {
        Self { quic_client }
    }
}

impl Connector for QuicConnector {
    type Connection = QuicStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        let client = self.quic_client.clone();
        let stream = client.open_bi(a);
        Box::pin(stream)
    }
}
