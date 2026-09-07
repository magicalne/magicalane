//! TCP+TLS transport: the tunnel rides a plain TLS session over TCP.
//!
//! Purpose: resilience against protocol-selective filtering that kills
//! UDP (QUIC/KCP) toward a server — TLS/TCP on :443 is indistinguishable
//! from ordinary HTTPS at the flow level. One TLS connection per proxy
//! connection (no multiplexing): each connection gets a fresh handshake,
//! which also means a blocked/stalled connection can never poison others.
//!
//! Wire protocol (identical to the KCP session layer, see
//! `src/kcp/listener.rs`): after the TLS handshake the client sends
//! `[len u8][password]`, reads a status byte (0 = ok), sends the target
//! `Addr` (socks5 encoding), reads a status byte, then both sides relay.

pub mod connector;
pub mod listener;

/// ALPN advertised by both sides. `http/1.1` keeps the flow looking
/// like ordinary HTTPS to middleboxes.
pub(crate) const ALPN_TCP: &[&[u8]] = &[b"http/1.1"];
