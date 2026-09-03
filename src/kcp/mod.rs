//! KCP transport: reliable UDP sessions with optional TLS.
//!
//! Wire layout (client -> server):
//!   UDP datagrams <-> KCP (conv-routed reliable messages)
//!   ...carrying a TLS stream (tokio-rustls) when enabled
//!   ...carrying the proxy protocol:
//!     [len u8][password] -> [flag u8]          (authentication)
//!     [Addr encoding]     -> [flag u8]          (relay request)
//!     ... raw relay ...
//!
//! Each relay request uses a fresh KCP conversation (conv). EOF is
//! propagated as a zero-length KCP message.

pub mod connector;
pub mod listener;
pub mod session;

pub(crate) const KCP_TICK_MS: u64 = 10;
/// Drop a session after this long without any packet in either direction.
pub(crate) const KCP_IDLE_TIMEOUT_SECS: u64 = 120;
/// Largest single KCP message payload we hand to `kcp.send`.
pub(crate) const KCP_MAX_WRITE: usize = 32 * 1024;

pub(crate) const ALPN_KCP: &[&[u8]] = &[b"magicalane-kcp-1"];
