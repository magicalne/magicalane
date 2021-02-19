use std::{
    marker::PhantomData,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures::{ready, FutureExt, StreamExt};
use quinn::{
    crypto::Session,
    VarInt,
};

pub struct SendStream<B: Buf, S: Session> {
    stream: quinn::generic::SendStream<S>,
    writing: Option<B>,
}

impl<B: Buf, S: Session> SendStream<B, S> {
    fn new(stream: quinn::generic::SendStream<S>) -> SendStream<B, S> {
        Self {
            stream,
            writing: None,
        }
    }
}

impl<B: Buf, S: Session> super::SendStream<B> for SendStream<B, S> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<super::Result<()>> {
        if let Some(ref mut data) = self.writing {
            ready!(self.stream.write_all(data.chunk()).poll_unpin(cx))?;
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data(&mut self, data: B) -> super::Result<()> {
        if self.writing.is_some() {
            return Err(super::QuicError::SendStreamNotReadyError);
        }
        self.writing = Some(data);
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<super::Result<()>> {
        self.stream
            .finish()
            .poll_unpin(cx)
            .map_err(super::QuicError::QuinnWriteError)
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::MAX));
    }

    fn id(&self) -> u64 {
        self.stream.id().0
    }
}

pub struct RecvStream<S: Session> {
    buf: BytesMut,
    stream: quinn::generic::RecvStream<S>,
}

impl<S: Session> RecvStream<S> {
    fn new(stream: quinn::generic::RecvStream<S>) -> Self {
        Self {
            buf: BytesMut::new(),
            stream,
        }
    }
}

const READ_BUF_SIZE: usize = 1024 * 4;

impl<S: Session> super::RecvStream for RecvStream<S> {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<super::Result<Option<Self::Buf>>> {
        self.buf.resize(READ_BUF_SIZE, 0);
        match self.stream.read(&mut self.buf).poll_unpin(cx) {
            Poll::Ready(Ok(Some(n))) => {
                let buf = self.buf.split_to(n).freeze();
                Poll::Ready(Ok(Some(buf)))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(super::QuicError::QuinnReadError(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        todo!()
    }
}

pub struct BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    send: SendStream<B, S>,
    recv: RecvStream<S>,
}

impl<B, S> BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    pub fn new(send: quinn::generic::SendStream<S>, recv: quinn::generic::RecvStream<S>) -> Self {
        Self {
            send: SendStream::new(send),
            recv: RecvStream::new(recv),
        }
    }
}

impl<B, S> super::SendStream<B> for BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<super::Result<()>> {
        self.send.poll_ready(cx)
    }

    fn send_data(&mut self, data: B) -> super::Result<()> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<super::Result<()>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn id(&self) -> u64 {
        self.send.id()
    }
}

impl<B, S> super::RecvStream for BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<super::Result<Option<Self::Buf>>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }
}

impl<B, S> super::BidiStream<B> for BidiStream<B, S>
where
    B: Buf,
    S: Session,
{
    type SendStream = SendStream<B, S>;
    type RecvStream = RecvStream<S>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

pub struct Connection<B: Buf, S: Session> {
    connection: quinn::generic::NewConnection<S>,
    _phantom_data: PhantomData<B>,
}

impl<B, S> Connection<B, S>
where
    B: Buf,
    S: Session,
{
    pub fn new(conn: quinn::generic::NewConnection<S>) -> Self {
        Self {
            connection: conn,
            _phantom_data: PhantomData,
        }
    }
}

impl<B, S> super::Connection<B> for Connection<B, S>
where
    B: Buf,
    S: Session,
{
    type SendStream = SendStream<B, S>;

    type RecvStream = RecvStream<S>;

    type BidiStream = BidiStream<B, S>;

    fn poll_accept_bidi_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<super::Result<Self::BidiStream>> {
        match ready!(self.connection.bi_streams.poll_next_unpin(cx)) {
            Some(Ok((send, recv))) => Poll::Ready(Ok(BidiStream::new(send, recv))),
            Some(Err(err)) => Poll::Ready(Err(super::QuicError::QuinnConnectionError(err))),
            None => Poll::Pending,
        }
    }

    fn poll_accept_recv_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<super::Result<Option<Self::RecvStream>>> {
        todo!()
    }

    fn poll_open_bidi_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<super::Result<Self::BidiStream>> {
        let mut open = self.connection.connection.open_bi();
        match ready!(open.poll_unpin(cx)) {
            Ok((send, recv)) => Poll::Ready(Ok(BidiStream::new(send, recv))),
            Err(err) => Poll::Ready(Err(super::QuicError::QuinnConnectionError(err))),
        }
    }

    fn poll_open_send_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<super::Result<Option<Self::SendStream>>> {
        todo!()
    }
}
