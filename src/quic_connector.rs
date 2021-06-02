use std::io;

use futures::future::BoxFuture;
use socks5lib::Connector;

use crate::quic::{self, stream::QuicStream};


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

    fn connect(
        &mut self,
        a: socks5lib::proto::Addr,
    ) -> BoxFuture<'static, io::Result<Self::Connection>> {
        let client = self.quic_client.clone();
        let stream = client.open_bi(a);
        Box::pin(stream)
    }
}
