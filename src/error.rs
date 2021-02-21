use quinn::{ParseError, crypto::rustls::TLSError};
use rcgen::RcgenError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Server down
    #[error("Server is down.")]
    ServerDown,
    /// First byte of protocol is not implemented.
    #[error("Wrong protocol.")]
    WrongProtocol,
    /// Buffer is empty.
    #[error("Empty buffer.")]
    EmptyBuffer,
    /// Empty password.
    #[error("Empty password.")]
    EmptyPassword,
    /// Parse password from [u8] to String failed.
    #[error("Parse password failed.")]
    ParsePasswordFail,
    #[error("Empty host.")]
    EmptyHost,
    /// Parse host from [u8] to String failed.
    #[error("Parse host failed.")]
    ParseHostFail,
    #[error("Empty port.")]
    EmptyPort,
    #[error("Parse port failed.")]
    ParsePortFail,
    #[error("Parse error")]
    ParseError,
    #[error("Known protocol kind")]
    UnknowProtocolKindErrlr,
    #[error("Poll from server lost error.")]
    PollServerDriverLostError,
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Generate key or cert error: {0}")]
    RcgenError(#[from] RcgenError),
    #[error("Parse key or cert error: {0}")]
    CertParseError(#[from] ParseError),
    #[error("TLSError: {0}")]
    TLSError(#[from] TLSError),

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
    #[error("Quinn endpoint error: {0}")]
    QuinnEndpointError(#[from] quinn::EndpointError),
    #[error("Quinn connect error: {0}")]
    QuinnConnectingError(#[from] quinn::ConnectError),
    #[error("Quinn connection error: {0}")]
    QuinnConnectionError(#[from] quinn::ConnectionError),
}

pub type Result<T> = std::result::Result<T, Error>;