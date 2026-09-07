//! End-to-end loopback for the TCP+TLS transport: the real
//! `tcp::listener::Server` + `tcp::connector::TcpConnector` over
//! loopback TCP with TLS and password auth, relaying to a local echo
//! server through the same `Stream` relay machine used in production.
//! Mirrors `tests/kcp_loopback.rs` (raw + TLS).

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use futures::future::BoxFuture;
use lib::{
    connector::{Connector, LocalConnector},
    socks5::proto::Addr,
    tcp,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn temp_files(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("magicalane-tcp-test-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    (dir.join("server.pem"), dir.join("server.key"), dir.join("ca.pem"))
}

/// Self-signed cert for "localhost", written to the given paths.
fn write_cert(cert_path: &PathBuf, key_path: &PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    std::fs::write(cert_path, cert.cert.pem()).unwrap();
    std::fs::write(key_path, cert.key_pair.serialize_pem()).unwrap();
}

/// Local TCP echo server; returns its address.
async fn echo_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { continue };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

#[tokio::test]
async fn tcp_transport_tls_loopback_echo() -> anyhow::Result<()> {
    let (cert_path, key_path, ca_path) = temp_files("tls");
    write_cert(&cert_path, &key_path);
    std::fs::copy(&cert_path, &ca_path)?;

    // Relay target: echo server.
    let echo = echo_server().await?;

    // Tunnel server on an ephemeral port.
    // Discover the bound port via a placeholder listener trick: bind 0.
    // The Server API takes an explicit port, so pick a free one first.
    let probe = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = probe.local_addr()?.port();
    drop(probe);

    let resolver = std::sync::Arc::new(lib::dns::resolve::Resolver::new(Vec::new(), None));
    let connector = LocalConnector::new(resolver);
    let server = tcp::listener::Server::new(
        connector,
        (key_path.clone(), cert_path.clone()),
        port,
        "sekret".into(),
        65536,
        true,
    )?;
    tokio::spawn(server.run());

    // Wait for the listener.
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Client connector -> echo through the tunnel.
    let mut client = tcp::connector::TcpConnector::new(
        "localhost",
        port,
        Some(ca_path),
        b"sekret".to_vec(),
        true,
    )?;
    let mut stream = Connector::connect(
        &mut client,
        Addr::SocketAddr(echo),
    )
    .await?;

    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await?;
    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await?;
    assert_eq!(payload, got, "echo roundtrip mismatch");

    // And back the other way (full duplex check).
    stream.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"ping");
    Ok(())
}

#[tokio::test]
async fn tcp_transport_wrong_password_rejected() -> anyhow::Result<()> {
    let (cert_path, key_path, ca_path) = temp_files("badpw");
    write_cert(&cert_path, &key_path);
    std::fs::copy(&cert_path, &ca_path)?;

    let echo = echo_server().await?;
    let probe = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = probe.local_addr()?.port();
    drop(probe);

    let resolver = std::sync::Arc::new(lib::dns::resolve::Resolver::new(Vec::new(), None));
    let connector = LocalConnector::new(resolver);
    let server = tcp::listener::Server::new(
        connector,
        (key_path, cert_path),
        port,
        "right".into(),
        65536,
        true,
    )?;
    tokio::spawn(server.run());
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut client = tcp::connector::TcpConnector::new(
        "localhost",
        port,
        Some(ca_path),
        b"wrong".to_vec(),
        true,
    )?;
    let res: BoxFuture<'_, std::io::Result<tcp::connector::TcpTunnelStream>> =
        Connector::connect(&mut client, Addr::SocketAddr(echo));
    let err = match res.await {
        Ok(_) => panic!("wrong password must be rejected"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    Ok(())
}
