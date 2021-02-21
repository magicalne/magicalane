use std::{
    future::Future,
    pin::Pin,
    task::{self, Poll},
};

use crate::quic::RecvStream;
use bytes::BytesMut;
use futures::ready;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream as TokioTcpStream,
};

use crate::error::Result;

#[pin_project::pin_project]
pub struct Proxy<S: AsyncRead + AsyncWrite> {
    #[pin]
    src: S,
    #[pin]
    dst: S,
    buf: Box<[u8]>,
}

impl<S: AsyncRead + AsyncWrite> Proxy<S> {
    pub fn new(src: S, dst: S) -> Self {
        Self {
            src,
            dst,
            buf: vec![0; 1000].into_boxed_slice(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite> Future for Proxy<S> {
    type Output = Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        let mut buf = ReadBuf::new(&mut me.buf);
        ready!(me.src.poll_read(cx, &mut buf))?;
        let n = buf.filled().len();

        ready!(me.dst.poll_write(cx, &me.buf))?;
        Poll::Ready(Ok(n))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::error::Result;

    #[tokio::test]
    pub async fn test_tcp() -> Result<()> {
        //ncat -l 2000 --keep-open --exec "/bin/cat"
        Ok(())
    }
}
