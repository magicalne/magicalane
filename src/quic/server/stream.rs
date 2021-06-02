use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{future::BoxFuture, ready, Future};
use socks5lib::{
    proto::Addr,
    proxy::Proxy,
    Connector,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::io::{poll_read_buf, poll_write_buf};
use tracing::trace;

use crate::error::{Error, Result};

enum State {
    ReadAddrReq,
    OpenRemote,
    SendAddrRes,
    Finished,
    Proxy,
}

pub struct Stream<IO, C, O> {
    io: Option<IO>,
    buf: BytesMut,
    connector: C,
    connector_fut: Option<BoxFuture<'static, io::Result<O>>>,
    remote: Option<O>,
    state: State,
    proxy: Option<Proxy<IO, O>>,
}

impl<IO, C, O> Stream<IO, C, O>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
    C: Connector<Connection = O>,
{
    pub fn new(io: IO, connector: C) -> Self {
        Self {
            io: Some(io),
            buf: BytesMut::new(),
            connector,
            connector_fut: None,
            remote: None,
            state: State::ReadAddrReq,
            proxy: None
        }
    }

    fn poll_read_addr(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.buf.clear();
        let n = ready!(poll_read_buf(
            Pin::new(self.io.as_mut().unwrap()),
            cx,
            &mut self.buf
        ))?;
        trace!("Read addr: {:?}Bytes: {:?}", n, &self.buf[..n]);
        let addr = Addr::new(&self.buf.chunk())?;
        trace!("read addr: {:?}", &addr);
        self.connector_fut = Some(self.connector.connect(addr));
        self.state = State::OpenRemote;
        Poll::Ready(Ok(()))
    }

    fn poll_open_remote(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match ready!(Pin::new(&mut self.connector_fut)
            .as_pin_mut()
            .unwrap()
            .poll(cx))
        {
            Ok(remote) => {
                trace!("Open remote successfully.");
                self.remote = Some(remote);
            }
            Err(err) => {
                trace!("Open remote failed: {:?}", err);
            }
        }
        self.state = State::SendAddrRes;
        Poll::Ready(Ok(()))
    }

    fn poll_send_addr(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let flag = if self.remote.is_some() { 0 } else { 1 };
        self.buf.clear();
        self.buf.put_u8(flag);
        let n = ready!(poll_write_buf(
            Pin::new(&mut self.io).as_pin_mut().unwrap(),
            cx,
            &mut self.buf
        ))?;
        trace!("Write {:?}Bytes", n);
        let _ = ready!(Pin::new(&mut self.io).as_pin_mut().unwrap().poll_flush(cx))?;
        let res = match &self.remote {
            Some(_) => {
                self.state = State::Finished;
                Ok(())
            }
            None => Err(Error::OpenRemoteError),
        };
        Poll::Ready(res)
    }
}

impl<IO, C, O> Unpin for Stream<IO, C, O> {}

unsafe impl<IO, C, O> Send for Stream<IO, C, O> {}

impl<IO, C, O> Future for Stream<IO, C, O>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
    C: Connector<Connection = O>,
{
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            match me.state {
                State::ReadAddrReq => {
                    let _ = ready!(me.poll_read_addr(cx))?;
                }
                State::OpenRemote => {
                    let _ = ready!(me.poll_open_remote(cx))?;
                }
                State::SendAddrRes => {
                    let _ = ready!(me.poll_send_addr(cx))?;
                }
                State::Finished => {
                    let src = me.io.take().unwrap();
                    let dst = me.remote.take().unwrap();
                    let proxy = Proxy::new(src, dst);
                    me.proxy = Some(proxy);
                    me.state = State::Proxy;
                }
                State::Proxy => {
                    let _ = ready!(Pin::new(&mut me.proxy).as_pin_mut().unwrap().poll(cx))?;
                    return Poll::Ready(Ok(()))
                }
            }
        }
    }
}
