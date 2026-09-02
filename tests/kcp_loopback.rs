use std::{net::SocketAddr, sync::Arc, time::Duration};

use lib::kcp::session::{self, KcpStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::mpsc,
};

/// Loopback KCP: two sessions over real localhost UDP sockets, echoing data
/// in both directions. Exercises the same session driver used by the
/// transports (without TLS - see env/test.sh for the full-stack checks).
#[tokio::test]
async fn kcp_loopback_echo() -> anyhow::Result<()> {
    let server_sock = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
    let client_sock = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
    let server_addr: SocketAddr = server_sock.local_addr()?;
    let client_addr: SocketAddr = client_sock.local_addr()?;

    // Server side: route every incoming packet to session 42.
    let (stx, srx) = mpsc::channel(256);
    let server_shared = Arc::new(session::Shared::new(42));
    let server_stream = KcpStream::new(server_shared.clone());
    {
        let sock = server_sock.clone();
        let stx = stx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await?;
                let _ = stx.send((from, buf[..n].to_vec())).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        });
    }
    tokio::spawn(session::drive_session(
        server_shared,
        server_sock.clone(),
        client_addr,
        srx,
        || {},
    ));

    // Client side: its own socket and session 42.
    let (ctx, crx) = mpsc::channel(256);
    let client_shared = Arc::new(session::Shared::new(42));
    let mut client_stream = KcpStream::new(client_shared.clone());
    {
        let sock = client_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await?;
                if from != server_addr {
                    continue;
                }
                let _ = ctx.send((from, buf[..n].to_vec())).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        });
    }
    tokio::spawn(session::drive_session(
        client_shared,
        client_sock.clone(),
        server_addr,
        crx,
        || {},
    ));

    // Echo server on the server-side stream.
    tokio::spawn(async move {
        let mut server_stream = server_stream;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = server_stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            server_stream.write_all(&buf[..n]).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });

    // Client: send and expect the echo.
    let payload: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
    for chunk in payload.chunks(7) {
        client_stream.write_all(chunk).await?;
    }
    client_stream.flush().await?;

    let mut got = Vec::new();
    let deadline = Duration::from_secs(10);
    let read_all = async {
        while got.len() < payload.len() {
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(deadline, client_stream.read(&mut buf)).await??;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        Ok::<(), anyhow::Error>(())
    };
    read_all.await?;
    assert_eq!(got, payload, "echoed data must match");
    Ok(())
}

/// Full TLS-over-KCP loopback: same as above but the echo runs through
/// tokio-rustls, mirroring the KcpConnector <-> kcp::listener stack.
#[tokio::test]
async fn kcp_tls_loopback_echo() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Self-signed cert for "localhost".
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)?;
    server_cfg.alpn_protocols = vec![b"magicalane-kcp-1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;
    let mut client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"magicalane-kcp-1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_cfg));

    let server_sock = std::sync::Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
    let client_sock = std::sync::Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
    let server_addr: SocketAddr = server_sock.local_addr()?;
    let client_addr: SocketAddr = client_sock.local_addr()?;

    let (stx, srx) = mpsc::channel(256);
    let server_shared = std::sync::Arc::new(session::Shared::new(7));
    let server_stream = KcpStream::new(server_shared.clone());
    {
        let sock = server_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await?;
                let _ = stx.send((from, buf[..n].to_vec())).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        });
    }
    tokio::spawn(session::drive_session(
        server_shared,
        server_sock,
        client_addr,
        srx,
        || {},
    ));

    let (ctx, crx) = mpsc::channel(256);
    let client_shared = std::sync::Arc::new(session::Shared::new(7));
    let client_stream = KcpStream::new(client_shared.clone());
    {
        let sock = client_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await?;
                if from != server_addr {
                    continue;
                }
                let _ = ctx.send((from, buf[..n].to_vec())).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        });
    }
    tokio::spawn(session::drive_session(
        client_shared,
        client_sock,
        server_addr,
        crx,
        || {},
    ));

    // Server: TLS-accept then echo.
    tokio::spawn(async move {
        let mut tls = match acceptor.accept(server_stream).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("tls accept err: {e}");
                return;
            }
        };
        let mut buf = vec![0u8; 4096];
        loop {
            let n = match tls.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            eprintln!("server read {} bytes", n);
            if tls.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = tls.shutdown().await;
    });

    let mut tls = connector
        .connect(
            rustls_pki_types::ServerName::try_from("localhost".to_string())?,
            client_stream,
        )
        .await?;

    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    for chunk in payload.chunks(997) {
        tls.write_all(chunk).await?;
    }
    tls.flush().await?;
    tls.get_mut().0.shutdown().await?;

    let mut got = Vec::new();
    let mut buf = vec![0u8; 8192];
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await {
            Err(_) => {
                eprintln!("read timeout after {} bytes", got.len());
                break;
            }
            Ok(r) => r?,
        };
        eprintln!("client read {} bytes: {:02x?}", n, &buf[..n.min(24)]);
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, payload, "TLS echo must match");
    Ok(())
}
