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

#[pin_project::pin_project]
pub struct Proxy<S: AsyncRead + AsyncWrite> {
    s1: Stream<S>,
    s2: Stream<S>,
}

impl<S: AsyncRead + AsyncWrite> Proxy<S> {
    pub fn new(s1: Stream<S>, s2: Stream<S>) -> Self {
        Self { s1, s2 }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Future for Proxy<S> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        let _ = me.s1.copy_into(&mut me.s2, cx)?;
        let _ = me.s2.copy_into(&mut me.s1, cx)?;

        if me.s1.is_shutdown() && me.s2.is_shutdown() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

enum State {
    Read,
    Write(usize),
    Flush,
    Shutdown,
}

#[pin_project::pin_project]
pub struct Stream<S: AsyncRead + AsyncWrite> {
    #[pin]
    s: S,
    state: State,
    buf: Box<[u8; 1024 * 64]>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    fn new(s: S) -> Self {
        let buf = Box::new([0; 1024 * 64]);
        let state = State::Read;
        Self {
            s,
            state,
            buf,
        }
    }

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize>> {
        let mut buf = ReadBuf::new(&mut self.buf[..]);
        match ready!(Pin::new(&mut self.s).poll_read(cx, &mut buf)) {
            Ok(_) => {
                let sz = buf.filled().len();
                if sz == 0 {
                    Poll::Ready(Err(Error::StreamClose))
                } else {
                    Poll::Ready(Ok(sz))
                }
            }
            Err(err) => Poll::Ready(Err(Error::IoError(err))),
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        match ready!(Pin::new(&mut self.s).poll_write(cx, &buf)) {
            Ok(sz) => {
                if sz == 0 {
                    Poll::Ready(Err(Error::StreamWriteZero))
                } else {
                    Poll::Ready(Ok(sz))
                }
            },
            Err(err) => {
                Poll::Ready(Err(Error::IoError(err)))
            }
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match ready!(Pin::new(&mut self.s).poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(Error::IoError(err)))
        }
    }

    fn copy_into(&mut self, out: &mut Stream<S>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            match self.state {
                State::Read => {
                    match ready!(self.poll_read(cx)) {
                        Ok(n) => {
                            self.state = State::Write(n);
                            return Poll::Pending
                        },
                        Err(err) => {
                            trace!("Read to buf with error: {:?}", err);
                            self.state = State::Shutdown;
                            return Poll::Pending
                        }
                    }                    
                }
                State::Write(n) => {
                    let buf = &self.buf[..n];
                    match ready!(Pin::new(&mut out.s).poll_write(cx, buf)) {
                        Ok(m) => {
                            if m == 0 {
                                out.state = State::Shutdown;
                                self.state = State::Shutdown
                            } else if m < n {
                                self.state = State::Write(n-m);
                            } else {
                                self.state = State::Flush;
                            }
                        }
                        Err(err) => {
                            trace!("Write to out with error: {:?}", err);
                            self.state = State::Shutdown;
                        }
                    }
                }
                State::Flush => {
                    match ready!(Pin::new(&mut out.s).poll_flush(cx)) {
                        Ok(_) => self.state = State::Read,
                        Err(err) => {
                            trace!("Flush to out with error: {:?}", err);
                            self.state = State::Shutdown;
                        }
                    }
                }
                State::Shutdown => {
                    return self.poll_shutdown(cx);
                }
            }
        }
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match Pin::new(&mut self.s).poll_shutdown(cx) {
            Poll::Ready(_) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_shutdown(&self) -> bool {
        matches!(self.state, State::Shutdown)
    }
}
