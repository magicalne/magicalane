use std::usize;

pub mod client;
pub mod proto;
pub mod server;
pub mod stream;

pub(crate) const SOCKET_RECV_BUF_SIZE: usize = 26214400;
pub(crate) const SOCKET_SEND_BUF_SIZE: usize = 26214400;
