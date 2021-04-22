use std::{
    mem::MaybeUninit,
    pin::Pin,
    task::{Context, Poll},
    u8, usize,
};

use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use futures::{ready, Future};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error, info, trace};

use crate::error::{Error, Result};

pub struct Proxy<S: AsyncRead + AsyncWrite> {
    s1: S,
    s2: S,
    buf: Vec<MaybeUninit<u8>>,
}

impl<S: AsyncRead + AsyncWrite> Proxy<S> {
    pub fn new(s1: S, s2: S, size: usize) -> Self {
        let buf = vec![MaybeUninit::uninit(); size];
        Self { s1, s2, buf }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Future for Proxy<S> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {}
    }
}

#[pin_project::pin_project]
struct Stream<S: AsyncRead + AsyncWrite> {
    #[pin]
    s: S,
    read: usize,
    is_shutdown: bool,
    buf: Box<[u8; 1024 * 64]>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    fn new(s: S) -> Self {
        let buf = Box::new([0; 1024 * 64]);
        let read = 0;
        let is_shutdown = false;
        Self {
            s,
            buf,
            read,
            is_shutdown,
        }
    }

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize>> {
        if self.read > 0 {
            return Poll::Ready(Ok(self.read));
        }
        let mut buf = ReadBuf::new(&mut self.buf[..]);
        match ready!(Pin::new(&mut self.s).poll_read(cx, &mut buf)) {
            Ok(_) => {
                self.read = buf.filled().len();
                if self.read == 0 {
                    Poll::Ready(Err(Error::StreamClose))
                } else {
                    Poll::Ready(Ok(self.read))
                }
            }
            Err(err) => Poll::Ready(Err(Error::IoError(err))),
        }
    }

    fn poll_copy_into(&mut self, out: &mut Stream<S>, cx: &mut Context<'_>) -> Poll<Result<usize>> {
        let mut size = 0;
        while self.read > 0 {
            let buf = &self.buf[..self.read];
            match ready!(Pin::new(&mut out.s).poll_write(cx, buf)) {
                Ok(sz) => {
                    if sz == 0 {
                        return Poll::Ready(Err(Error::StreamWriteZero));
                    }
                    self.read -= sz;
                    size += sz;
                }
                Err(err) => return Poll::Ready(Err(Error::IoError(err))),
            }
        }
        Poll::Ready(Ok(size))
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match Pin::new(&mut self.s).poll_shutdown(cx) {
            Poll::Ready(_) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending
        }
    }
}
