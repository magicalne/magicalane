use std::pin::Pin;

use crate::connector::Connector;
use bytes::{Buf, BufMut, BytesMut};
use futures::future::poll_fn;
use log::trace;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    spawn,
};
use tokio_util::io::{poll_read_buf, poll_write_buf};

use crate::{
    error::{Error, Result},
    quic::{proto::compare_passwd, stream::QuicStream},
};

use super::stream::Stream;

pub struct Connection<C> {
    conn: quinn::Connection,
    buf: BytesMut,
    connector: C,
    passwd: Vec<u8>,
    bandwidth: usize,
}

impl<C, O> Connection<C>
where
    O: AsyncRead + AsyncWrite + Unpin + 'static,
    C: Connector<Connection = O> + Send + 'static,
{
    pub fn new(conn: quinn::Connection, connector: C, passwd: Vec<u8>, bandwidth: usize) -> Self {
        Self {
            conn,
            buf: BytesMut::new(),
            connector,
            passwd,
            bandwidth,
        }
    }

    /// Handle one QUIC connection: the first bi-stream authenticates the
    /// password, then every accepted bi-stream becomes a relay.
    pub async fn accept(&mut self) -> Result<()> {
        let me = &mut *self;
        match me.conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let n = poll_fn(|cx| poll_read_buf(Pin::new(&mut recv), cx, &mut me.buf)).await?;
                trace!("Read {:?}Bytes", n);
                if n == 0 {
                    return Err(Error::StreamClose);
                }
                let buf = me.buf.chunk();
                let ret = compare_passwd(buf, &me.passwd);
                let flag = match ret.as_ref() {
                    Ok(_) => 0,
                    Err(_) => 1,
                };
                me.buf.clear();
                me.buf.put_u8(flag);
                poll_fn(|cx| poll_write_buf(Pin::new(&mut send), cx, &mut me.buf)).await?;
                trace!("Write passwd ack");
                poll_fn(|cx| Pin::new(&mut send).poll_flush(cx)).await?;
                if flag != 0 {
                    return Err(Error::WrongPassword);
                }
            }
            Err(_) => return Err(Error::StreamClose),
        };
        loop {
            match me.conn.accept_bi().await {
                Ok((send, recv)) => {
                    let connector = me.connector.clone();
                    let stream = QuicStream::new(recv, send);
                    let bandwidth = me.bandwidth;
                    let stream = Stream::new(stream, connector, bandwidth);
                    spawn(async move {
                        if let Err(err) = stream.await {
                            trace!("Stream error: {:?}", err);
                        };
                    });
                }
                Err(_) => return Ok(()),
            }
        }
    }
}

impl<C> Unpin for Connection<C> {}
