use std::{path::PathBuf, task::{Context, Poll}};

use bytes::Buf;

pub mod quic_quinn;
pub mod quinn_server;
pub mod quinn_client;
pub mod stream;
use crate::error::Result;

pub enum KeyPemPair {
    Empty,
    Pair { key: PathBuf, cert: PathBuf },
}

pub trait SendStream<B: Buf> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn send_data(&mut self, data: B) -> Result<()>;
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn reset(&mut self, reset_code: u64);
    fn id(&self) -> u64;
}

pub trait RecvStream {
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<usize>>>;
    fn stop_sending(&mut self, error_code: u64);
}

pub trait BidiStream<B: Buf>: SendStream<B> + RecvStream {
    type SendStream: SendStream<B>;
    type RecvStream: RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream);
}

pub trait Connection<B: Buf> {
    type SendStream: SendStream<B>;
    type RecvStream: RecvStream;
    type BidiStream: BidiStream<B>;

    fn poll_accept_bidi_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream>>;
    fn poll_accept_recv_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::RecvStream>>>;
    fn poll_open_bidi_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream>>;
    fn poll_open_send_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::SendStream>>>;
}