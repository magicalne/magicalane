//! Regression for #18 (K1 / pool liveness): prewarm-pooled KCP sessions
//! idle out at `KCP_IDLE_TIMEOUT_SECS` (120s) with no keepalive, but stay
//! in the pool. `connect()` used to return the zombie's EOF error instead
//! of falling back to a fresh handshake — so the FIRST request after an
//! idle gap failed, and the bench showed it as a wedge (one dead pop per
//! attempt until the morgue drained).
//!
//! With `MAGICALANE_TEST_KCP_IDLE_SECS` we reap in 1s, let the pool rot,
//! and require `connect()` to still succeed via a fresh handshake.
//! regression: https://github.com/magicalne/magicalane/issues/18

use std::time::Duration;

use lib::connector::{Connector, LocalConnector};
use lib::kcp::{connector::KcpConnector, listener::Server as KcpServer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn pooled_zombie_falls_back_to_fresh_handshake() -> anyhow::Result<()> {
    // Single test in this binary; set before any sessions exist.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("MAGICALANE_TEST_KCP_IDLE_SECS", "1")
    };
    let _ = rustls::crypto::ring::default_provider().install_default();

    // --- origin echo
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let origin = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // --- certs + KCP server (TLS, like the lab/production)
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let dir = std::env::temp_dir().join(format!("magicalane-zombie-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    let ca_path = dir.join("ca.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    std::fs::write(&ca_path, cert.cert.pem())?;

    let mut server = KcpServer::new(
        LocalConnector::default(),
        (key_path, cert_path),
        0,
        "test-password".to_string(),
        65536,
        true,
        None,
    )?;
    let kcp_port = server.local_addr()?.port();
    tokio::spawn(async move { server.run().await });

    let connector = KcpConnector::new(
        "localhost".to_string(),
        kcp_port,
        Some(ca_path),
        b"test-password".to_vec(),
        true,
        None,
    )?;
    connector.prewarm(); // fill the pool so idle rot has something to reap

    // --- sanity: a connect works while everything is fresh
    let addr = lib::socks5::proto::Addr::SocketAddr(origin);
    {
        let mut c = connector.clone();
        let mut io =
            tokio::time::timeout(Duration::from_secs(10), c.connect(addr.clone())).await??;
        io.write_all(b"ping").await?;
        io.flush().await?;
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf)).await??;
        assert_eq!(&buf, b"ping");
        drop(io);
    }

    // --- let every pooled session idle out (zombie morgue: entries stay
    // pooled and prewarm will not refill while len() == cap)
    tokio::time::sleep(Duration::from_secs(4)).await;

    // --- the pin: connect must transparently fall back to a fresh
    // handshake instead of surfacing the zombie's EOF error
    let mut c = connector.clone();
    let io = tokio::time::timeout(Duration::from_secs(15), c.connect(addr.clone()))
        .await
        .expect("15s bound")
        .expect(
            "connect after idle rot must succeed via fresh handshake, not fail on a pooled zombie",
        );

    // and the fresh session must actually relay
    let mut io = io;
    io.write_all(b"pong").await?;
    io.flush().await?;
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf)).await??;
    assert_eq!(&buf, b"pong");
    Ok(())
}
