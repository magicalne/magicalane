use std::{
    io::{Error, ErrorKind::ConnectionAborted, Result},
    pin::Pin,
    task::{Context, Poll},
    usize,
};

use bytes::{Buf, BytesMut};
use futures::{ready, Future};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::io::{poll_read_buf, poll_write_buf};
use tracing::{error, trace};
#[pin_project::pin_project]

/// Copy from linkerd2-proxy.
pub struct Proxy<I, O> {
    i: Reader<I>,
    o: Reader<O>,
}

impl<I, O> Proxy<I, O>
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(i: I, o: O, capacity: usize) -> Self {
        Self {
            i: Reader::new(i, "src->dst", capacity),
            o: Reader::new(o, "dst->src", capacity),
        }
    }
}

impl<I, O> Future for Proxy<I, O>
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        trace!("poll");
        let _ = this.i.poll_copy_into(cx, this.o)?;
        let _ = this.o.poll_copy_into(cx, this.i)?;
        if this.i.is_done() && this.o.is_done() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

enum BufRead {
    Read(usize),
    NotEmpty,
    Eof,
}

enum BufWrite {
    BufEmpty,
    Partial(usize),
    All(usize),
}

#[pin_project::pin_project]
struct Reader<I> {
    buf: BytesMut,
    is_shutdown: bool,
    #[pin]
    io: I,
    direction: &'static str,
    flushing: bool,
}

impl<I> Reader<I>
where
    I: AsyncRead + Unpin,
{
    fn new(io: I, direction: &'static str, capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
            is_shutdown: false,
            io,
            direction,
            flushing: false,
        }
    }

    fn is_done(&self) -> bool {
        self.is_shutdown
    }

    /// Reads data from `self` and writing it to `dst`.
    /// Returns ready when the stream has shutdown.
    fn poll_copy_into<O: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut Reader<O>,
    ) -> Poll<Result<()>> {
        if dst.is_shutdown {
            trace!(direction = %self.direction, "already shutdown");
            return Poll::Ready(Ok(()));
        }

        if self.flushing {
            ready!(self.poll_flush(cx, dst))?;
        }

        let mut needs_flush = false;

        loop {
            match self.poll_read(cx)? {
                Poll::Pending => {
                    // If there's no data to be read and we've written data, try
                    // flushing before returning pending.
                    if needs_flush {
                        // The poll status of the flush isn't relevant, as we
                        // have registered interest in the read (and maybe the
                        // write as well). If the flush did not complete
                        // `self.flushing` is true so that it maybe resumed on
                        // the next poll.
                        let _ = self.poll_flush(cx, dst)?;
                    }
                    return Poll::Pending;
                }
                Poll::Ready(BufRead::NotEmpty) | Poll::Ready(BufRead::Read(_)) => {
                    // Write buf to the dst.
                    match self.drain_into(cx, dst)? {
                        // All the buf was written, so continue to read.
                        BufWrite::All(sz) => {
                            debug_assert!(sz > 0);
                            needs_flush = true;
                        }
                        // Only some of the buffered data could be written
                        // before the dst became pending. Try to flush the
                        // written data to get capacity.
                        BufWrite::Partial(_) => {
                            ready!(self.poll_flush(cx, dst))?;
                            // `BufWrite::Partital` matches with `Poll::Pending`
                            // If the flush completed, try writeing again to
                            // ensure that we have a notification registered. If
                            // all of the buffered data still cannot be written,
                            // return pending. Otherwise, continue.
                            if let BufWrite::Partial(_) = self.drain_into(cx, dst)? {
                                return Poll::Pending;
                            }
                            needs_flush = false;
                        }
                        BufWrite::BufEmpty => {
                            error!(
                                direction = self.direction,
                                "Invalid state: attempted to write from an empty buffer"
                            );
                            debug_assert!(false, "The write buffer should never be empty");
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                Poll::Ready(BufRead::Eof) => {
                    trace!(direction = %self.direction, "shutting down");
                    debug_assert!(!dst.is_shutdown, "attempted to shut down destination twice");
                    ready!(Pin::new(&mut dst.io).poll_shutdown(cx))?;
                    dst.is_shutdown = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<BufRead>> {
        if self.buf.has_remaining() {
            trace!(direction = %self.direction, remaining = self.buf.remaining(), "skipping read");
            return Poll::Ready(Ok(BufRead::NotEmpty));
        }
        self.buf.clear();
        trace!(direction = %self.direction, "reading");
        let sz = ready!(poll_read_buf(Pin::new(&mut self.io), cx, &mut self.buf))?;
        trace!(direction = %self.direction, "read {}B", sz);

        if sz > 0 {
            Poll::Ready(Ok(BufRead::Read(sz)))
        } else {
            trace!("eof");
            self.buf.clear();
            Poll::Ready(Ok(BufRead::Eof))
        }
    }

    fn drain_into<O: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut Reader<O>,
    ) -> Result<BufWrite> {
        let mut sz = 0;

        while self.buf.has_remaining() {
            trace!(direction = %self.direction, "writing {}B", self.buf.remaining());
            let n = match poll_write_buf(Pin::new(&mut dst.io), cx, &mut self.buf)? {
                Poll::Pending => return Ok(BufWrite::Partial(sz)),
                Poll::Ready(n) => n,
            };
            trace!(direction = %self.direction, "wrote {}B", n);
            if n == 0 {
                return Err(Error::new(ConnectionAborted, "Connection closed."));
            }
            sz += n;
        }

        if sz == 0 {
            Ok(BufWrite::BufEmpty)
        } else {
            Ok(BufWrite::All(sz))
        }
    }

    fn poll_flush<O: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut Reader<O>,
    ) -> Poll<Result<()>> {
        trace!(direction = %self.direction, "flushing");
        match Pin::new(&mut dst.io).poll_flush(cx) {
            Poll::Ready(Ok(_)) => {
                trace!(direction = %self.direction, "flushed");
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                self.flushing = true;
                Poll::Pending
            }
        }
    }
}
