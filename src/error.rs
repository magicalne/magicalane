use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq)]
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
    ParseError
}
