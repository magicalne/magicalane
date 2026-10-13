//! Regression test for the DNS TCP keep-alive / INFLIGHT semaphore
//! interaction (PR #20 review): the global in-flight permit must be
//! held per decoded QUERY, not per TCP connection. With the old
//! per-connection acquisition, 256 idle RFC 7766 keep-alive sessions
//! (each having sent one query) exhausted the semaphore and blocked
//! every DNS path — UDP queries and new TCP clients alike — forever.

use std::time::Duration;

use bytes::BufMut;
use futures::future::BoxFuture;
use lib::connector::Connector;
use lib::dns;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Connector whose "tunnel" answers every framed DNS query with a
/// canned framed response (echo server side of query_once's exchange).
#[derive(Clone)]
struct EchoConnector;

impl Connector for EchoConnector {
    type Connection = tokio::io::DuplexStream;

    fn connect(
        &mut self,
        _a: lib::socks5::proto::Addr,
    ) -> BoxFuture<'static, std::io::Result<Self::Connection>> {
        Box::pin(async {
            let (mine, mut theirs) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                loop {
                    let mut hdr = [0u8; 2];
                    if theirs.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
                    if theirs.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    let mut ans = Vec::with_capacity(2 + q.len());
                    ans.put_u16(q.len() as u16);
                    ans.extend_from_slice(&q);
                    if theirs.write_all(&ans).await.is_err() {
                        return;
                    }
                }
            });
            Ok(mine)
        })
    }
}

fn query() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    q.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    q.extend_from_slice(&[0, 1, 0, 1]);
    q
}

/// One framed query round-trip on a TCP client connection; Ok(false)
/// means no answer within the timeout (the failure mode under test).
async fn ask(stream: &mut tokio::net::TcpStream, timeout: Duration) -> bool {
    let q = query();
    let mut frame = Vec::with_capacity(2 + q.len());
    frame.put_u16(q.len() as u16);
    frame.extend_from_slice(&q);
    let write = stream.write_all(&frame);
    if tokio::time::timeout(timeout, write).await.is_err() {
        return false;
    }
    read_answer(stream, timeout).await
}

async fn read_answer(stream: &mut tokio::net::TcpStream, timeout: Duration) -> bool {
    let mut hdr = [0u8; 2];
    let hdr_fut = stream.read_exact(&mut hdr);
    if tokio::time::timeout(timeout, hdr_fut).await.is_err() {
        return false;
    }
    let mut resp = vec![0u8; u16::from_be_bytes(hdr) as usize];
    let body_fut = stream.read_exact(&mut resp);
    tokio::time::timeout(timeout, body_fut).await.is_ok()
}

/// Fire-and-forget framed query (keep-alive traffic: keeps the server's
/// frame-header read from timing out without waiting for the answer).
async fn ping(stream: &mut tokio::net::TcpStream) {
    let q = query();
    let mut frame = Vec::with_capacity(2 + q.len());
    frame.put_u16(q.len() as u16);
    frame.extend_from_slice(&q);
    let _ = stream.write_all(&frame).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_keepalive_sessions_do_not_starve_new_dns_queries() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(dns::serve_client_tcp(listener, EchoConnector));

    // more keep-alive sessions than the INFLIGHT semaphore (256)
    const SESSIONS: usize = 300;
    // Connect CONCURRENTLY: sequential asks would let 44 starved
    // sessions burn their timeouts serially (~11s) and the first
    // sessions would hit their 5s frame timeout (releasing permits)
    // before the keep-alive phase even starts.
    let mut handles = Vec::with_capacity(SESSIONS);
    for _ in 0..SESSIONS {
        handles.push(tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            // each session served exactly one query, then stays open
            // (RFC 7766 keep-alive). Under the old per-connection
            // permit, sessions beyond the semaphore got no answer —
            // fine, we only need them CONNECTED.
            let ok = ask(&mut s, Duration::from_millis(400)).await;
            (s, ok)
        }));
    }
    let results = futures::future::join_all(handles).await;
    let mut sessions = Vec::with_capacity(SESSIONS);
    let mut answered = 0usize;
    for r in results {
        let (s, ok) = r.expect("session task panicked");
        if ok {
            answered += 1;
        }
        sessions.push(s);
    }
    // sanity: the listener is alive and most sessions served a query
    assert!(
        answered > 100,
        "expected most sessions served, got {answered}"
    );

    // Keep ALL sessions actively renewing from the start: a query
    // before each server-side frame timeout (QUERY_TIMEOUT = 5s) is
    // exactly the "sending a query before each read timeout" pattern
    // from the review — under the old code that held the permit for
    // the connection lifetime, and no permit ever freed. Rounds every
    // 1.5s for 6s prove the hold is persistent, not a startup race.
    for _ in 0..4 {
        for s in sessions.iter_mut() {
            ping(s).await;
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }

    // the actual regression: a brand-new query (fresh connection here;
    // the same semaphore gates the UDP paths) must still be served
    // while 300 keep-alive sessions stay active.
    let mut fresh = tokio::net::TcpStream::connect(addr).await.unwrap();
    let served = ask(&mut fresh, Duration::from_secs(3)).await;

    // cleanup BEFORE asserting so a failure cannot leak held permits
    // into other tests (drop closes the connections and their tasks).
    drop(sessions);
    drop(fresh);

    assert!(
        served,
        "new DNS query starved by {SESSIONS} active keep-alive sessions \
         (per-connection INFLIGHT permit regression)"
    );
}

/// Keep-alive must still WORK (multiple queries per connection) — the
/// fix must not have broken connection reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalive_multiple_queries_one_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(dns::serve_client_tcp(listener, EchoConnector));

    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    for _ in 0..5 {
        assert!(
            ask(&mut s, Duration::from_secs(3)).await,
            "query on keep-alive connection not served"
        );
    }
}
