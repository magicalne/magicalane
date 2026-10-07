//! Regression for #16: KCP sessions leaked sockets two ways.
//!
//!  1. Client: the per-attempt receiver task parks on `recv_from`
//!     forever after the session driver exits (it only notices a dead
//!     rx when the next datagram arrives, which never comes from a
//!     silent peer). Every KCP connect/session leaked one
//!     wildcard-bound unconnected UDP fd — the production gateway
//!     drifted to EMFILE within ~2 days (~20 fds/h, all state-07 UDP).
//!  2. Server: the FIN set `eof` without waking parked readers, so the
//!     relay task never unwound and pinned its origin TCP pair.
//!
//! regression: https://github.com/magicalne/magicalane/issues/16
//!
//! BOTH scenarios live in ONE test on purpose: fd accounting is
//! process-global, and two #[tokio::test]s run on parallel threads
//! with separate runtimes — the sibling test's setup/teardown churns
//! fds (sockets, mio registrations) exactly while this one measures,
//! which showed up as flaky "+4 leaked" on slow shared CI runners.
//! One test = one runtime = deterministic accounting.

use std::time::Duration;

#[cfg(target_os = "linux")]
use lib::connector::{Connector, LocalConnector};
#[cfg(target_os = "linux")]
use lib::kcp::{connector::KcpConnector, listener::Server as KcpServer};
#[cfg(target_os = "linux")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

/// How long to wait after a session/connect ended for the lingering
/// machinery to finish (drive_session lingers up to 2s after handle
/// drop) and any leaked fd to become observable. Generous: shared CI
/// runners starve tokio timers; a real leak never converges, so we
/// poll for the invariant up to this deadline instead of blind sleep.
const SETTLE_MAX: Duration = Duration::from_secs(15);

/// Count open fds of the test process. The read_dir's own directory
/// handle shows up in the listing, but it is present in every call, so
/// before/after deltas cancel it out.
#[cfg(target_os = "linux")]
fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.filter_map(|e| e.ok()).count())
        .unwrap_or(0)
}

/// Poll until `fd_count() <= baseline + slack` or the deadline passes.
/// Returns the last count seen.
#[cfg(target_os = "linux")]
async fn settle_fds(baseline: usize, slack: usize) -> usize {
    let mut after = fd_count();
    let deadline = std::time::Instant::now() + SETTLE_MAX;
    while after > baseline + slack && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        after = fd_count();
    }
    after
}

/// A "blackhole" peer: a bound UDP port that never responds (and never
/// sends), so the client handshake parks until the connector's own
/// bound gives up.
async fn blackhole() -> std::io::Result<std::net::SocketAddr> {
    let s = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let a = s.local_addr()?;
    tokio::spawn(async move {
        // Hold the port open, discard anything that arrives.
        let mut buf = vec![0u8; 1500];
        loop {
            if s.recv_from(&mut buf).await.is_err() {
                break;
            }
        }
    });
    Ok(a)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn kcp_session_fd_lifecycle() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ============================================================
    // Phase A — two connects that time out inside the connector (10s
    // bound each) must not leave session sockets behind.
    // ============================================================
    let baseline = fd_count();
    let dead = blackhole().await?;
    let connector = KcpConnector::new(
        "127.0.0.1".to_string(),
        dead.port(),
        None,
        b"test-password".to_vec(),
        false, // plain KCP: no TLS certs needed; the handshake still parks
        None,
    )?;
    let target = lib::socks5::proto::Addr::SocketAddr("127.0.0.1:80".parse().unwrap());

    for i in 0..2 {
        let mut c = connector.clone();
        let started = std::time::Instant::now();
        let res = tokio::time::timeout(Duration::from_secs(15), c.connect(target.clone())).await;
        let res = res.expect("connector-internal 10s bound must fire first");
        assert!(
            res.is_err(),
            "attempt {i}: connect to silent peer must fail"
        );
        eprintln!(
            "attempt {i}: failed as expected after {:?}",
            started.elapsed()
        );
    }

    // Give drive_session its 2s linger + slack; the blackhole socket
    // itself is the only allowed resident (+1).
    let after = settle_fds(baseline, 1).await;
    eprintln!("phase A fds: baseline={baseline} after={after}");
    assert!(
        after <= baseline + 1,
        "timed-out KCP connects leaked {} fd(s): the receiver task parks on recv_from forever holding the session socket (baseline={baseline} after={after})",
        after.saturating_sub(baseline + 1)
    );

    // ============================================================
    // Phase B — a completed relay must release the client session
    // socket AND let the server relay unwind (origin TCP pair closed).
    // Resident fds allowed: the origin TCP listener and the KCP server
    // UDP listener (+2).
    // ============================================================
    let baseline = fd_count();

    // --- origin echo server
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

    // --- certs
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let dir = std::env::temp_dir().join(format!("magicalane-fdleak-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    let ca_path = dir.join("ca.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    std::fs::write(&ca_path, cert.cert.pem())?;

    // --- KCP server + connector (TLS, like production)
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

    // --- one full relay: request, echo exchange, drop the stream
    let addr = lib::socks5::proto::Addr::SocketAddr(origin);
    let mut io = tokio::time::timeout(Duration::from_secs(10), {
        let mut c = connector.clone();
        let a = addr.clone();
        async move { c.connect(a).await }
    })
    .await??;

    let payload: Vec<u8> = (0..2000u32).map(|i| (i % 247) as u8).collect();
    io.write_all(&payload).await?;
    io.flush().await?;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 8192];
    while got.len() < payload.len() {
        let n = tokio::time::timeout(Duration::from_secs(10), io.read(&mut buf)).await??;
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, payload, "echoed payload must match");

    drop(io); // relay done: client stream handle goes away
    let after = settle_fds(baseline, 2).await;
    eprintln!("phase B fds: baseline={baseline} after={after}");
    assert!(
        after <= baseline + 2,
        "completed KCP session leaked {} fd(s) beyond the two resident listeners (baseline={baseline} after={after}): client session socket not released, or the server relay parked on an unwoken EOF holding the origin TCP pair",
        after.saturating_sub(baseline + 2)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn fd_leak_tests_are_linux_only() -> anyhow::Result<()> {
    // /proc/self/fd accounting is linux-only; other runners skip.
    Ok(())
}
