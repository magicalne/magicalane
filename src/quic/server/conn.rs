use std::pin::Pin;

use bytes::{Buf, BufMut, BytesMut};
use futures::{future::poll_fn, StreamExt, TryStreamExt};
use quinn::IncomingBiStreams;
use socks5lib::Connector;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    spawn,
};
use tokio_util::io::{poll_read_buf, poll_write_buf};
use tracing::trace;

use crate::{
    error::{Error, Result},
    quic::{proto::compare_passwd, stream::QuicStream},
};

use super::stream::Stream;

pub struct Connection<C> {
    bi_streams: IncomingBiStreams,
    buf: BytesMut,
    connector: C,
    passwd: Vec<u8>,
}

impl<C, O> Connection<C>
where
    O: AsyncRead + AsyncWrite + Unpin + 'static,
    C: Connector<Connection = O> + Send + 'static,
{
    pub fn new(bi_streams: IncomingBiStreams, connector: C, passwd: Vec<u8>) -> Self {
        Self {
            bi_streams,
            buf: BytesMut::new(),
            connector,
            passwd,
        }
    }

    pub async fn accept(&mut self) -> Result<()> {
        let me = &mut *self;
        match me.bi_streams.try_next().await? {
            Some((mut send, mut recv)) => {
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
                let n = poll_fn(|cx| poll_write_buf(Pin::new(&mut send), cx, &mut me.buf)).await?;
                trace!("Write {:?}Bytes", n);
                let _ = poll_fn(|cx| Pin::new(&mut send).poll_flush(cx)).await?;
            }
            None => return Err(Error::StreamClose),
        };
        while let Some(next) = me.bi_streams.next().await {
            match next {
                Ok((send, recv)) => {
                    let connector = me.connector.clone();
                    let stream = QuicStream::new(recv, send);
                    let stream = Stream::new(stream, connector);
                    spawn(async move {
                        if let Err(err) = stream.await {
                            trace!("Stream error: {:?}", err);
                        };
                    });
                }
                Err(err) => return Err(Error::QuinnConnectionError(err)),
            }
        }

        Ok(())
    }
}

impl<C> Unpin for Connection<C> {}
