use std::{
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{Future, future::BoxFuture, ready};
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::io::{poll_read_buf, poll_write_buf};

use crate::{connector::Connector, proxy::Proxy};

use super::{
    Result,
    error::Error,
    proto::{Addr, Command, Decoder, Encoder, Reply, Version},
};

enum ConnectingState {
    Negotiation,
    Auth,
    SubNegotiation,
    OpenRemote,
}
struct Connecting<IO, C, O> {
    io: Option<IO>,
    buf: BytesMut,
    state: ConnectingState,
    connector: C,
    connector_fut: Option<BoxFuture<'static, io::Result<O>>>,
    ver: Option<Version>,
    addr: Option<Addr>,
    /// user:pass entries; empty = auth disabled.
    users: Vec<(String, String)>,
}

impl<IO, C, O> Unpin for Connecting<IO, C, O> {}

impl<IO, C, O> Connecting<IO, C, O>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Connector<Connection = O>,
    O: AsyncRead + AsyncWrite + Unpin,
{
    fn new(io: IO, connector: C, users: Vec<(String, String)>) -> Self {
        let buf = BytesMut::new();
        Self {
            io: Some(io),
            buf,
            state: ConnectingState::Negotiation,
            connector,
            connector_fut: None,
            ver: None,
            addr: None,
            users,
        }
    }

    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(IO, O)>> {
        let me = &mut *self;
        loop {
            match &mut me.state {
                ConnectingState::Negotiation => {
                    ready!(me.poll_negotiation(cx))?;
                }
                ConnectingState::Auth => {
                    ready!(me.poll_auth(cx))?;
                }
                ConnectingState::SubNegotiation => {
                    ready!(me.poll_subnegotiation(cx))?;
                }
                ConnectingState::OpenRemote => {
                    let remote = ready!(me.poll_open_remote(cx))?;
                    let source = me.io.take().unwrap();
                    return Poll::Ready(Ok((source, remote)));
                }
            }
        }
    }

    fn poll_negotiation(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        trace!("negotiation...");
        self.buf.clear();
        let n = ready!(poll_read_buf(
            Pin::new(self.io.as_mut().unwrap()),
            cx,
            &mut self.buf
        ))?;
        if n == 0 {
            return Poll::Ready(Err(Error::ConnectionClose));
        }
        let buf = self.buf.chunk();
        let (ver, methods) = Decoder::parse_connecting(buf)?;
        // Pick the strongest method we support: with users configured
        // require username/password (RFC 1929); otherwise no-auth.
        let m = if self.users.is_empty() {
            if methods.iter().any(|m| matches!(m, super::proto::Method::NoAuth)) {
                &super::proto::Method::NoAuth
            } else {
                &super::proto::Method::NoAcceptableMethod
            }
        } else if methods
            .iter()
            .any(|m| matches!(m, super::proto::Method::UsernamePassword))
        {
            &super::proto::Method::UsernamePassword
        } else {
            &super::proto::Method::NoAcceptableMethod
        };
        let going_auth = matches!(m, super::proto::Method::UsernamePassword);
        self.buf.clear();
        Encoder::encode_method_select_msg(ver, m, &mut self.buf);
        trace!("poll negotiation writing: {:?}", self.buf);
        let n = ready!(poll_write_buf(
            Pin::new(self.io.as_mut().unwrap()),
            cx,
            &mut self.buf
        ))?;
        if n == 0 {
            return Poll::Ready(Err(Error::ConnectionClose));
        }
        ready!(Pin::new(self.io.as_mut().unwrap()).poll_flush(cx))?;
        self.state = if going_auth {
            ConnectingState::Auth
        } else {
            ConnectingState::SubNegotiation
        };
        Poll::Ready(Ok(()))
    }

    /// RFC 1929 username/password subnegotiation.
    fn poll_auth(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.buf.clear();
        let n = ready!(poll_read_buf(
            Pin::new(self.io.as_mut().unwrap()),
            cx,
            &mut self.buf
        ))?;
        if n == 0 {
            return Poll::Ready(Err(Error::ConnectionClose));
        }
        let (user, pass) = Decoder::parse_username_password(self.buf.chunk())?;
        let user = String::from_utf8_lossy(user);
        let pass = String::from_utf8_lossy(pass);
        let ok = self
            .users
            .iter()
            .any(|(u, p)| u == &user && p == &pass);
        self.buf.clear();
        Encoder::encode_auth_status(ok, &mut self.buf);
        let n = ready!(poll_write_buf(
            Pin::new(self.io.as_mut().unwrap()),
            cx,
            &mut self.buf
        ))?;
        if n == 0 {
            return Poll::Ready(Err(Error::ConnectionClose));
        }
        ready!(Pin::new(self.io.as_mut().unwrap()).poll_flush(cx))?;
        if !ok {
            return Poll::Ready(Err(Error::AuthFailed()));
        }
        self.state = ConnectingState::SubNegotiation;
        Poll::Ready(Ok(()))
    }

    fn poll_subnegotiation(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        trace!("sub negotiation...");
        self.buf.clear();
        let n = ready!(poll_read_buf(
            Pin::new(self.io.as_mut().unwrap()),
            cx,
            &mut self.buf
        ))?;
        if n == 0 {
            return Poll::Ready(Err(Error::ConnectionClose));
        }
        let buf = self.buf.chunk();
        let (ver, cmd, addr) = Decoder::parse_nego_req(buf)?;
        match cmd {
            Command::Connect => {
                self.state = ConnectingState::OpenRemote;
                self.ver = Some(ver);
                self.addr = Some(addr);
            }
            Command::Bind => {
                unimplemented!()
            }
            Command::UdpAssociate => {
                unimplemented!()
            }
        };
        Poll::Ready(Ok(()))
    }

    fn poll_open_remote(&mut self, cx: &mut Context<'_>) -> Poll<Result<O>> {
        if self.connector_fut.is_none() {
            let addr = self.addr.clone().unwrap();
            self.connector_fut = Some(self.connector.connect(addr));
        }
        let fut = self.connector_fut.as_mut().unwrap();
        let remote_io = ready!(fut.as_mut().poll(cx))?;
        trace!("Remote connected.");
        self.buf.clear();
        let ver = self.ver.as_ref().unwrap();
        let addr = self.addr.as_ref().unwrap();
        Encoder::encode_server_reply(ver, &Reply::Succeeded, addr, &mut self.buf);
        let n = ready!(poll_write_buf(
            Pin::new(self.io.as_mut().unwrap()),
            cx,
            &mut self.buf
        ))?;
        if n == 0 {
            return Poll::Ready(Err(Error::ConnectionClose));
        }
        ready!(Pin::new(self.io.as_mut().unwrap()).poll_flush(cx))?;
        Poll::Ready(Ok(remote_io))
    }
}

#[pin_project::pin_project]
struct CommandConnect<C, O> {
    ver: Version,
    addr: Addr,
    #[pin]
    remote_fut: Option<BoxFuture<'static, io::Result<O>>>,
    connector: C,
    phantom: PhantomData<O>,
}

impl<C, O> Future for CommandConnect<C, O>
where
    C: Connector<Connection = O>,
    O: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<O>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        if me.remote_fut.is_none() {
            *me.remote_fut = Some(me.connector.connect(me.addr.clone()));
        }
        let remote_io = ready!(me.remote_fut.as_pin_mut().unwrap().poll(cx))?;
        Poll::Ready(Ok(remote_io))
    }
}

#[pin_project::pin_project(project = ConnStateProj)]
enum ConnState<IO, C, O> {
    Connecting(Connecting<IO, C, O>),
    Connected(Proxy<IO, O>),
}

#[pin_project::pin_project]
pub struct Connection<IO, C, O> {
    bandwidth: usize,
    #[pin]
    state: ConnState<IO, C, O>,
}

impl<IO, C, O> Connection<IO, C, O>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Connector<Connection = O>,
    O: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: IO, connector: C, users: Vec<(String, String)>, bandwidth: usize) -> Self {
        let connecting = Connecting::new(io, connector, users);
        Self {
            bandwidth,
            state: ConnState::Connecting(connecting),
        }
    }
}

impl<IO, C, O> Future for Connection<IO, C, O>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Connector<Connection = O>,
    O: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let bandwidth = self.bandwidth;
        let mut me = self.project();
        loop {
            match me.state.as_mut().project() {
                ConnStateProj::Connecting(connecting) => {
                    let (i, o) = ready!(connecting.poll_inner(cx))?;
                    let proxy = Proxy::new(i, o, bandwidth);
                    me.state.set(ConnState::Connected(proxy));
                }
                ConnStateProj::Connected(mut proxy) => {
                    ready!(Pin::new(&mut proxy).poll(cx))?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

/// Safety: Connection is not cloneable and shared nothing.
unsafe impl<IO, C, O> Send for Connection<IO, C, O> {}
