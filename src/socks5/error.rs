use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Stream colsed.")]
    ConnectionClose,
    #[error("InvalidMessage")]
    InvalidMessage(),
    #[error("auth failed")]
    AuthFailed(),
    #[error("InvalidVersion: {0}")]
    InvalidVersion(u8),
    #[error("InvalidMethod: {0}")]
    InvalidMethod(u8),
    #[error("InvalidCommand: {0}")]
    InvalidCommand(u8),
    #[error("InvalidAddress")]
    InvalidAddress,
}
