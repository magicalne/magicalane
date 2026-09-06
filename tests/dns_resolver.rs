//! Layered resolver integration tests: real UDP stubs on localhost.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use lib as lib;
use lib::dns::{proto, resolve::Resolver};

/// A minimal DNS stub: answers A with `ip4`, AAAA with `ip6`, after an
/// optional delay. Counts answered queries.
struct Stub {
    addr: SocketAddr,
    count: Arc<AtomicUsize>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        // task ends with the socket
    }
}

async fn spawn_stub(ip4: std::net::Ipv4Addr, ip6: std::net::Ipv6Addr, delay_ms: u64) -> Stub {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { break };
            let resp = match proto::parse_query(&buf[..n]) {
                Some(q) => {
                    if q.qtype == proto::QTYPE_AAAA {
                        proto::build_aaaa_response(&q, ip6)
                    } else {
                        proto::build_a_response(&q, ip4)
                    }
                }
                None => continue,
            };
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = sock.send_to(&resp, from).await;
        }
    });
    Stub { addr, count }
}

/// A guaranteed-dead "upstream": closed port on localhost.
fn dead_upstream() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = s.local_addr().unwrap();
    drop(s); // port now closed -> ICMP refused / timeout
    a
}

#[tokio::test]
async fn hosts_first_without_upstreams() {
    let r = Resolver::new(vec![], None);
    let addrs = r.resolve("localhost", 80).await.expect("hosts resolution");
    assert!(!addrs.is_empty());
    assert!(addrs.iter().all(|a| a.ip().is_loopback()));
}

#[tokio::test]
async fn failover_to_second_upstream() {
    let dead = dead_upstream();
    let stub = spawn_stub(
        std::net::Ipv4Addr::new(203, 0, 113, 7),
        "2001:db8::7".parse().unwrap(),
        0,
    )
    .await;
    let r = Resolver::new(vec![dead, stub.addr], None);
    let addrs = r
        .resolve("service-under-test.example", 443)
        .await
        .expect("must fail over to the live upstream");
    assert!(addrs.iter().any(|a| a.ip().to_string() == "203.0.113.7"), "{addrs:?}");
    assert!(stub.count.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn cache_dedupes_upstream_queries() {
    let stub = spawn_stub(
        std::net::Ipv4Addr::new(198, 51, 100, 9),
        "2001:db8::9".parse().unwrap(),
        0,
    )
    .await;
    let r = Resolver::new(vec![stub.addr], None);
    let a = r.resolve("hot.example", 80).await.expect("first");
    let b = r.resolve("hot.example", 80).await.expect("second (cache)");
    assert_eq!(a, b);
    // give any in-flight duplicate a moment, then require exactly the
    // two family queries of ONE resolution round (AAAA + A = 2 answers)
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stub.count.load(Ordering::SeqCst), 2, "one round of AAAA+A only");
}

#[tokio::test]
async fn cache_expires_with_ttl() {
    // proto answers carry TTL=1s (clamped to >=1s)
    let stub = spawn_stub(
        std::net::Ipv4Addr::new(198, 51, 100, 10),
        "2001:db8::10".parse().unwrap(),
        0,
    )
    .await;
    let r = Resolver::new(vec![stub.addr], None);
    r.resolve("ttl.example", 80).await.expect("first");
    tokio::time::sleep(Duration::from_millis(1200)).await; // expiry
    r.resolve("ttl.example", 80).await.expect("after expiry");
    assert!(stub.count.load(Ordering::SeqCst) >= 4, "re-queried after TTL");
}

#[tokio::test]
async fn racing_first_answer_wins() {
    let slow = spawn_stub(
        std::net::Ipv4Addr::new(203, 0, 113, 1),
        "2001:db8::1".parse().unwrap(),
        400,
    )
    .await;
    let fast = spawn_stub(
        std::net::Ipv4Addr::new(203, 0, 113, 2),
        "2001:db8::2".parse().unwrap(),
        0,
    )
    .await;
    let r = Resolver::new(vec![slow.addr, fast.addr], None);
    let t0 = std::time::Instant::now();
    let addrs = r.resolve("race.example", 80).await.expect("raced");
    let elapsed = t0.elapsed();
    assert!(
        addrs.iter().any(|a| a.ip().to_string() == "203.0.113.2"),
        "fast upstream must win: {addrs:?}"
    );
    assert!(elapsed < Duration::from_millis(350), "racing took {elapsed:?}");
}

#[tokio::test]
async fn system_fallback_without_upstreams() {
    // No upstreams, not in hosts -> system resolver (resolv.conf works
    // on the dev host / CI). localhost IS in hosts, so use a name that
    // only the system stack knows: the machine's own hostname.
    let name = hostname();
    if name.contains('.') || name.len() > 2 {
        let r = Resolver::new(vec![], None);
        // Any result (Ok or NotFound) is acceptable offline; assert no panic.
        let _ = r.resolve(&name, 22).await;
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[test]
fn config_one_or_many_parses() {
    let single: lib::config::Config = toml::from_str(
        r#"
password = "x"
bandwidth = 1
verbose = false
kind = { Client = { proxy = { host = "h", port = 1 }, socks5_port = 1, tproxy = { mode = "off", tcp_port = 1, udp_port = 1 }, routing = { direct_dns = "223.5.5.5:53" } } }
"#,
    )
    .unwrap();
    match &single.kind {
        lib::config::Kind::Client { routing, .. } => {
            let v = routing.as_ref().unwrap().direct_dns.as_ref().unwrap().to_vec();
            assert_eq!(v, vec!["223.5.5.5:53".to_string()]);
        }
        _ => panic!(),
    }

    let many: lib::config::Config = toml::from_str(
        r#"
password = "x"
bandwidth = 1
verbose = false
kind = { Client = { proxy = { host = "h", port = 1 }, socks5_port = 1, tproxy = { mode = "off", tcp_port = 1, udp_port = 1 }, routing = { direct_dns = ["192.0.2.1:53", "223.5.5.5:53"] } } }
[dns]
upstream = ["1.1.1.1:53", "8.8.8.8:53"]
cache_size = 128
"#,
    )
    .unwrap();
    assert_eq!(many.dns.as_ref().unwrap().cache_size, Some(128));
    assert_eq!(many.dns.as_ref().unwrap().upstream.as_ref().unwrap().to_vec().len(), 2);
    match &many.kind {
        lib::config::Kind::Client { routing, .. } => {
            let v = routing.as_ref().unwrap().direct_dns.as_ref().unwrap().to_vec();
            assert_eq!(v.len(), 2);
        }
        _ => panic!(),
    }
}

#[test]
fn order_addrs_prefers_v6_when_asked() {
    use lib::dns::resolve::order_addrs;
    let addrs: Vec<SocketAddr> = ["1.2.3.4:80", "[2001:db8::1]:80", "5.6.7.8:80"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    let ordered = order_addrs(addrs.clone(), true);
    assert!(ordered[0].is_ipv6());
    let flat = order_addrs(addrs, false);
    assert!(flat[0].is_ipv4());
}
