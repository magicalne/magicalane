use std::{path::PathBuf, task::{Context, Poll}};

use bytes::Buf;
use thiserror::Error;

pub mod quic_quinn;

pub enum KeyPemPair {
    Empty,
    Pair { key: PathBuf, cert: PathBuf },
}

#[derive(Error, Debug)]
pub enum QuicError {
    #[error("Send stream error.")]
    SendStreamError,
    #[error("Send stream is not ready")]
    SendStreamNotReadyError,
    #[error("Empty remote address")]
    EmptyRemoteAddrError,
    #[error("Not binded")]
    NotBindedError,
    #[error("Not connected")]
    NotConnectedError,
    #[error("Quinn read error: {0}")]
    QuinnReadError(#[from] quinn::ReadError),
    #[error("Quinn write error: {0}")]
    QuinnWriteError(#[from] quinn::WriteError),
    #[error("Quinn connect error: {0}")]
    QuinnConnectingError(#[from] quinn::ConnectError),
    #[error("Quinn connection error: {0}")]
    QuinnConnectionError(#[from] quinn::ConnectionError),
}

pub type Result<T> = std::result::Result<T, QuicError>;

pub trait SendStream<B: Buf> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn send_data(&mut self, data: B) -> Result<()>;
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn reset(&mut self, reset_code: u64);
    fn id(&self) -> u64;
}

pub trait RecvStream {
    type Buf: Buf;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>>>;
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