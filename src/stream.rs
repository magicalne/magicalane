use futures::future::try_join;
use quinn::{RecvStream, SendStream};
use tokio::{io::copy, net::TcpStream};
use tracing::trace;

use crate::error::Result;

pub struct Transfer {
    send: SendStream,
    recv: RecvStream,
    tcp: TcpStream
}

impl Transfer {
    pub fn new(send: SendStream, recv: RecvStream, tcp: TcpStream) -> Self {
        Self {
            send, recv, tcp
        }
    }

    pub async fn copy(&mut self) -> Result<()> {
        let (mut rd, mut sd) = self.tcp.split();
        let cp1 = copy(&mut rd, &mut self.send);
        let cp2 = copy(&mut self.recv, &mut sd);
        let (i, o) = try_join(cp1, cp2).await?;
        trace!("Transport in: {:?} bytes out: {:?} bytes", i, o);
        Ok(())
    }
}