use rcgen::RcgenError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MagicalaneError {
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
    #[error("Poll from server lost error.")]
    PollServerDriverLostError,
    #[error("io error: {0}")]
    IoError(std::io::Error),
    #[error("generate key or cert error: {0}")]
    RcgenError(#[from] RcgenError)
}

impl From<std::io::Error> for MagicalaneError {
    fn from(v: std::io::Error) -> Self {
        MagicalaneError::IoError(v)
    }
}

pub type Result<T> = std::result::Result<T, MagicalaneError>;