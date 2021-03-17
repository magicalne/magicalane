use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use futures::{ready, Future};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error, info, trace};

use crate::error::{Error, Result};

pub struct ProxyOpenConnection<R: AsyncRead, W: AsyncWrite> {
    read: R,
    write: W,
}

impl<R, W> ProxyOpenConnection<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(r: R, w: W) {
        
    }
}

struct ProxyStream<R: AsyncRead, W: AsyncWrite> {
    reader: R,
    read_done: bool,
    writer: W,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
    finish: bool,
}

impl<R, W> ProxyStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            read_done: false,
            writer,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; 4096].into_boxed_slice(),
            finish: false,
        }
    }

    fn poll_next_(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<u64>> {
        if self.pos == self.cap && !self.read_done {
            let me = &mut *self;
            let mut buf = ReadBuf::new(&mut me.buf);
            ready!(Pin::new(&mut me.reader).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                self.read_done = true;
            } else {
                self.pos = 0;
                self.cap = n;
            }
        }
        while self.pos < self.cap {
            let me = &mut *self;
            let buf = &me.buf[me.pos..me.cap];
            let n = ready!(Pin::new(&mut me.writer).poll_write(cx, buf))?;
            if n == 0 {
                me.finish = true;
                return Poll::Ready(Err(Error::StreamWriteZero));
            } else {
                self.pos += n;
                self.amt += n as u64;
            }
        }
        if self.pos == self.cap && self.read_done {
            ready!(Pin::new(&mut self.writer).poll_flush(cx))?;
            self.finish = true;
            return Poll::Ready(Ok(self.amt));
        }
        Poll::Pending
    }
}

pub struct ProxyPool<R: AsyncRead, W: AsyncWrite> {
    receiver: Receiver<(R, W)>,
    pool: Vec<ProxyStream<R, W>>,
}

impl<R, W> ProxyPool<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new() -> (Sender<(R, W)>, Self) {
        let (sender, receiver) = unbounded::<(R, W)>();
        (
            sender,
            Self {
                receiver,
                pool: Vec::with_capacity(200),
            },
        )
    }

    fn recv_proxy_stream(&mut self) -> std::result::Result<(), TryRecvError> {
        self.receiver.try_recv().map(|(r, w)| {
            let proxy_stream = ProxyStream::new(r, w);
            self.pool.push(proxy_stream);
        })
    }
}

impl<R, W> Future for ProxyPool<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.as_mut().recv_proxy_stream() {
                error!("Cannot recv from channel: {:?}", err);
                return Poll::Ready(Err(Error::RecvProxyStreamError));
            }
            let pool = &mut *self.pool;
            pool.iter_mut().for_each(|p| {
                if let Poll::Ready(res) = Pin::new(p).poll_next_(cx) {
                    match res {
                        Ok(amount) => trace!("transport {:?} bytes", amount),
                        Err(err) => trace!("[ERROR] {:?}", err),
                    };
                }
            });
            self.pool.retain(|p| !p.finish);
            //TODO: Optmized with drain filter once it's stable.
            // self.as_ref().pool.drain_filter(|p| {
            //     if let Poll::Ready(res) = Pin::new(p).poll_next_(cx) {
            //         match res {
            //             Ok(amount) => trace!("transport {:?} bytes", amount),
            //             Err(err) => trace!("[ERROR] {:?}", err),
            //         };
            //         true
            //     } else {
            //         false
            //     }
            // });
        }
    }
}
