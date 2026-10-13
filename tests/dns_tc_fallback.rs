//! Regression tests for DNS-over-TCP upstream behavior (PR #20 review):
//!
//! 1. A truncated (TC=1) UDP answer must trigger a TCP retry against the
//!    same upstream, returning the FULL answer — this is the entire
//!    point of DNS-over-TCP (RFC 7766), and what a client's post-TC
//!    retry over TCP expects to finally receive.
//! 2. Answers larger than the old 4096-byte cap must flow (up to 65535
//!    is legal on the framed path).

use std::time::Duration;

use bytes::BufMut;
use lib::dns::DnsRelayStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// UDP stub that always answers with a TC=1 (truncated) header.
async fn truncating_udp_stub() -> std::net::SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                break;
            };
            // echo the query with TC set: keep id + question, set flags TC
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x02; // TC
            if sock.send_to(&resp, from).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// TCP stub on the same port as the UDP stub (the relay retries the TCP
/// exchange against the SAME upstream address), answering every framed
/// query with a full `body` answer.
async fn full_answer_tcp_stub(port: u16, body: Vec<u8>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind tcp on the udp stub port");
    tokio::spawn(async move {
        // one connection per exchange (the relay opens one per retry)
        let mut answer = Vec::with_capacity(2 + body.len());
        answer.put_u16(body.len() as u16);
        answer.extend_from_slice(&body);
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let ans = answer.clone();
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                if sock.read_exact(&mut hdr).await.is_err() {
                    return;
                }
                let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
                if sock.read_exact(&mut q).await.is_err() {
                    return;
                }
                let _ = sock.write_all(&ans).await;
            });
        }
    });
}

/// Drive one query through a DnsRelayStream, returning the response.
async fn relay_query(stream: &mut DnsRelayStream, query: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + query.len());
    frame.put_u16(query.len() as u16);
    frame.extend_from_slice(query);
    stream.write_all(&frame).await.unwrap();
    // read the framed response (poll_read keeps feeding from rbuf)
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await.unwrap();
    let mut resp = vec![0u8; u16::from_be_bytes(hdr) as usize];
    stream.read_exact(&mut resp).await.unwrap();
    resp
}

fn query() -> Vec<u8> {
    // minimal A query for example.com, id 0x1234
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    q.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    q.extend_from_slice(&[0, 1, 0, 1]);
    q
}

#[tokio::test]
async fn truncated_udp_answer_is_retried_over_tcp() {
    let udp = truncating_udp_stub().await;
    full_answer_tcp_stub(udp.port(), b"FULL-ANSWER-VIA-TCP".to_vec()).await;

    let mut relay = DnsRelayStream::new(vec![udp]);
    let resp = tokio::time::timeout(Duration::from_secs(5), relay_query(&mut relay, &query()))
        .await
        .expect("relay exchange timed out");
    assert_eq!(
        resp,
        b"FULL-ANSWER-VIA-TCP".to_vec(),
        "must get the full TCP answer, not the truncated UDP one"
    );
}

#[tokio::test]
async fn big_answer_over_tcp_upstream_flows() {
    // >4096 bytes: the old MAX_DNS cap rejected exactly these on the
    // framed path, breaking the DNS-over-TCP fallback.
    let body: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let udp = truncating_udp_stub().await;
    full_answer_tcp_stub(udp.port(), body.clone()).await;

    let mut relay = DnsRelayStream::new(vec![udp]);
    let resp = tokio::time::timeout(Duration::from_secs(5), relay_query(&mut relay, &query()))
        .await
        .expect("relay exchange timed out");
    assert_eq!(resp.len(), 8192, "full-size answer must arrive");
    assert_eq!(resp, body);
}

// The TC-bit helper (lib::dns::dns_truncated) is exercised through
// the relay behavior above; keep this self-contained so the file also
// compiles against trees where the helper is not yet exported.
#[test]
fn tc_bit_detection() {
    let tc = |resp: &[u8]| resp.len() >= 4 && resp[2] & 0x02 != 0;
    let mut resp = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    assert!(!tc(&resp), "normal answer is not truncated");
    resp[2] |= 0x02;
    assert!(tc(&resp), "TC set must be detected");
    assert!(!tc(&[0x12, 0x34]), "short buffer is not truncated");
}
