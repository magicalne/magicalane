//! Regression for #18: the TCP transport listener wrapped the ENTIRE
//! relay (Stream::new) inside its 10s HANDSHAKE_TIMEOUT — every
//! connection was hard-killed at 10s. Invisible on fast links (whole
//! relay finishes in ms), fatal on WAN-shaped paths: rtt/upload phases
//! of a bench regularly exceed 10s and died with reset/early-eof.
//!
//! Pin: complete a relay, go quiet for longer than HANDSHAKE_TIMEOUT,
//! then keep exchanging data — the connection must still work.
//! regression: https://github.com/magicalne/magicalane/issues/18

use std::time::Duration;

use lib::connector::{Connector, LocalConnector};
use lib::tcp::{connector::TcpConnector, listener::Server as TcpServer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// Must exceed the listener's HANDSHAKE_TIMEOUT (10s).
const QUIET: Duration = Duration::from_secs(11);

#[tokio::test]
async fn tcp_transport_relay_survives_idle_longer_than_handshake_timeout() -> anyhow::Result<()> {
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

    // --- certs + TCP+TLS transport server
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let dir = std::env::temp_dir().join(format!("magicalane-tcptimeout-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    let ca_path = dir.join("ca.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    std::fs::write(&ca_path, cert.cert.pem())?;

    // no local_addr() on the transport server: pick a free port ourselves
    let probe = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = probe.local_addr()?.port();
    drop(probe);
    let server = TcpServer::new(
        LocalConnector::default(),
        (key_path, cert_path),
        port,
        "test-password".to_string(),
        65536,
        true,
    )?;
    tokio::spawn(async move { server.run().await });

    // wait for the transport server to bind
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let connector = TcpConnector::new(
        "localhost",
        port,
        Some(ca_path),
        b"test-password".to_vec(),
        true,
    )?;

    // --- full relay, then idle past the (old) kill deadline, then talk
    let addr = lib::socks5::proto::Addr::SocketAddr(origin);
    let mut c = connector.clone();
    let mut io = tokio::time::timeout(Duration::from_secs(10), c.connect(addr)).await??;

    io.write_all(b"first").await?;
    io.flush().await?;
    let mut buf = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf)).await??;
    assert_eq!(&buf, b"first");

    // Go quiet longer than HANDSHAKE_TIMEOUT: pre-fix, the server kills
    // the connection here (the timeout wrapped the whole relay).
    tokio::time::sleep(QUIET).await;

    io.write_all(b"after").await?;
    io.flush().await?;
    match tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf)).await {
        Ok(Ok(_)) => assert_eq!(&buf, b"after"),
        Ok(Err(e)) => {
            panic!("relay was killed during idle (handshake timeout wrapped the relay): {e}")
        }
        Err(_) => panic!("relay unresponsive after idle: killed by the 10s bound"),
    }
    Ok(())
}
