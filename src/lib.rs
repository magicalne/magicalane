mod proxy;
mod application;
mod transport;
pub mod client;
pub mod server;
pub mod error;
pub mod protocol;

pub const ALPN_QUIC: &[&[u8]] = &[b"hq-29"];