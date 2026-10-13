use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{connector::Connector, proxy::Proxy, socks5::proto::Addr};
use bytes::{Buf, BufMut, BytesMut};
use futures::{Future, future::BoxFuture, ready};
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::io::{poll_read_buf, poll_write_buf};

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
    bandwidth: usize,
    /// The addr-response flag byte has been written; only flush may re-poll.
    addr_res_written: bool,
}

impl<IO, C, O> Stream<IO, C, O>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
    C: Connector<Connection = O>,
{
    pub fn new(io: IO, connector: C, bandwidth: usize) -> Self {
        Self {
            io: Some(io),
            buf: BytesMut::new(),
            connector,
            connector_fut: None,
            remote: None,
            state: State::ReadAddrReq,
            proxy: None,
            bandwidth,
            addr_res_written: false,
        }
    }

    fn poll_read_addr(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.buf.clear();
        // The address frame may arrive split across reads (long domains
        // exceed common packet/chunk boundaries). Keep reading until
        // `encoded_len` bytes are buffered before decoding; decoding a
        // partial chunk used to panic (see `Addr::new`).
        loop {
            let complete = match Addr::encoded_len(&self.buf) {
                // Complete enough to decode (unknown types decode to an
                // error, not a panic — fall through).
                Some(len) => self.buf.len() >= len,
                None => false,
            };
            if complete {
                let addr = Addr::new(self.buf.chunk())?;
                trace!("read addr: {:?}", &addr);
                self.connector_fut = Some(self.connector.connect(addr));
                self.state = State::OpenRemote;
                return Poll::Ready(Ok(()));
            }
            let n = ready!(poll_read_buf(
                Pin::new(self.io.as_mut().unwrap()),
                cx,
                &mut self.buf
            ))?;
            trace!("Read addr: +{} bytes", n);
            if n == 0 {
                return Poll::Ready(Err(Error::StreamClose));
            }
            // 1 type + 1 len + 255 domain + 2 port: anything beyond is
            // not a valid frame.
            if self.buf.len() > 259 {
                return Poll::Ready(Err(Error::from(
                    crate::socks5::error::Error::InvalidAddress,
                )));
            }
        }
    }

    fn poll_open_remote(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match ready!(
            Pin::new(&mut self.connector_fut)
                .as_pin_mut()
                .unwrap()
                .poll(cx)
        ) {
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
        // Re-entrancy guard: this state is polled again whenever a previous
        // write or flush returned Pending (common over TLS-on-KCP). Writing
        // the flag on every re-poll would duplicate it onto the stream.
        if !self.addr_res_written {
            self.buf.clear();
            self.buf.put_u8(flag);
            let n = ready!(poll_write_buf(
                Pin::new(&mut self.io).as_pin_mut().unwrap(),
                cx,
                &mut self.buf
            ))?;
            if n == 0 {
                return Poll::Ready(Err(Error::StreamClose));
            }
            self.addr_res_written = true;
            trace!("Write {:?}Bytes", n);
        }
        ready!(Pin::new(&mut self.io).as_pin_mut().unwrap().poll_flush(cx))?;
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
                    ready!(me.poll_read_addr(cx))?;
                }
                State::OpenRemote => {
                    ready!(me.poll_open_remote(cx))?;
                }
                State::SendAddrRes => {
                    ready!(me.poll_send_addr(cx))?;
                }
                State::Finished => {
                    let src = me.io.take().unwrap();
                    let dst = me.remote.take().unwrap();
                    let bandwidth = me.bandwidth;
                    let proxy = Proxy::new(src, dst, bandwidth);
                    me.proxy = Some(proxy);
                    me.state = State::Proxy;
                }
                State::Proxy => {
                    ready!(Pin::new(&mut me.proxy).as_pin_mut().unwrap().poll(cx))?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks5::proto::Addr;
    use futures::FutureExt;
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

    /// Serves its bytes one fixed chunk per read, whatever the caller's
    /// buffer size — forces the split-read conditions of the regression.
    struct ChunkedIo {
        chunks: Vec<Vec<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for ChunkedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let me = &mut *self;
            match me.chunks.first_mut() {
                None => Poll::Ready(Ok(())), // EOF
                Some(chunk) => {
                    let n = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..n]);
                    chunk.drain(..n);
                    if chunk.is_empty() {
                        me.chunks.remove(0);
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    impl AsyncWrite for ChunkedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone)]
    struct MockConnector {
        seen: Arc<Mutex<Vec<Addr>>>,
    }

    impl Connector for MockConnector {
        type Connection = DuplexStream;
        fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<DuplexStream>> {
            self.seen.lock().unwrap().push(a);
            let (_tx_side_is_dropped_after_connect, rx) = tokio::io::duplex(64);
            async move { Ok(rx) }.boxed()
        }
    }

    // Regression (2026-10-13): a long-domain addr frame delivered as a
    // 64-byte chunk followed by the remainder used to panic the relay
    // task at Addr::new (socks5/proto.rs); with the full-frame wait the
    // relay must connect to the right domain.
    #[tokio::test]
    async fn addr_frame_split_across_reads_still_connects() {
        let domain =
            "deepviz-nlb-prod-ap-southeast-1-f64fb66f5d07c49a.elb.ap-southeast-1.amazonaws.com";
        let mut frame = vec![3u8, domain.len() as u8];
        frame.extend_from_slice(domain.as_bytes());
        frame.extend_from_slice(&443u16.to_be_bytes());

        // split at the production-observed boundary: 64 then the rest
        let mut chunks = vec![frame[..64].to_vec(), frame[64..].to_vec()];
        chunks.push(Vec::new()); // EOF after the frame
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = ChunkedIo {
            chunks,
            written: written.clone(),
        };
        let connector = MockConnector {
            seen: Arc::new(Mutex::new(Vec::new())),
        };
        let stream = Stream::new(io, connector.clone(), 1 << 20);
        stream.await.expect("relay must succeed");

        let seen = connector.seen.lock().unwrap();
        match &seen[0] {
            Addr::DomainName(d, port) => {
                assert_eq!(d.as_slice(), domain.as_bytes());
                assert_eq!(*port, 443);
            }
            other => panic!("expected domain, got {:?}", other),
        }
        // success flag must have been written back
        assert_eq!(written.lock().unwrap()[0], 0u8);
    }
}
