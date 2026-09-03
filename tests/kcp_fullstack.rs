//! Full-stack local repro of the KCP transport path:
//! mini-origin TCP server <- kcp::listener::Server <- KcpConnector <- raw socks5 client.
//! Mirrors env/test.sh T1 without containers.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use lib::connector::{Connector, LocalConnector};
use lib::kcp::{connector::KcpConnector, listener::Server as KcpServer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const PASSWORD: &str = "test-password";

async fn spawn_origin() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
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
    Ok(addr)
}

#[tokio::test]
async fn kcp_full_stack() -> anyhow::Result<()> {
    lib_test_init();
    let origin = spawn_origin().await?;

    // Certs
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let dir = tempfile_dir();
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    let ca_path = dir.join("ca.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    std::fs::write(&ca_path, cert.cert.pem())?;

    // KCP server
    let mut server = KcpServer::new(
        LocalConnector,
        (key_path.clone(), cert_path.clone()),
        0,
        PASSWORD.to_string(),
        65536,
        true,
        None,
    )?;
    let kcp_port = server.local_addr()?.port();
    tokio::spawn(async move { server.run().await });

    // Connector
    let mut connector = KcpConnector::new(
        "localhost".to_string(),
        kcp_port,
        Some(ca_path.clone()),
        PASSWORD.as_bytes().to_vec(),
        true,
        None,
    )?;

    // One relay request to the origin via the connector (socks5 Addr).
    let addr = lib::socks5::proto::Addr::SocketAddr(origin);
    let mut io = tokio::time::timeout(Duration::from_secs(10), {
        let mut c = connector.clone();
        let a = addr.clone();
        async move { c.connect(a).await }
    })
    .await??;

    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 247) as u8).collect();
    for chunk in payload.chunks(400) {
        io.write_all(chunk).await?;
    }
    io.flush().await?;

    let mut got = Vec::new();
    let mut buf = vec![0u8; 8192];
    while got.len() < payload.len() {
        let n = tokio::time::timeout(Duration::from_secs(10), io.read(&mut buf)).await??;
        if n == 0 {
            break;
        }
        eprintln!("read {} bytes: {:02x?}", n, &buf[..n.min(16)]);
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, payload, "echoed payload must match");
    Ok(())
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("magicalane-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn lib_test_init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[allow(dead_code)]
async fn unused(_s: TcpStream) {}
