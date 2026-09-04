//! Fake-IP engine: instant, locally-answered DNS with bidirectional
//! domain↔IP mappings (the "routing token" architecture).
//!
//! Every A query gets an immediate answer from `198.18.0.0/15`
//! (RFC 2544 benchmark space — Clash convention); every AAAA query
//! (when enabled) gets one from `fc00::/18` (ULA space). No DNS query
//! ever crosses the network for faked families: DNS pollution is
//! impossible by construction, and the connection-time interceptor
//! maps the token back to the domain for rule-based routing.
//!
//! The map is shared between the DNS interceptor (assign, on query)
//! and the TCP/UDP interceptors (lookup, on connect). All operations
//! are lock-and-copy (no await inside), so a std Mutex suffices.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
};

/// Fake IPv4 pool: 198.18.0.0/15 (131070 usable hosts).
pub const FAKE_V4_RANGE: (u32, u32) = (0xC612_0000, 0xC613_FFFF); // 198.18.0.0 ..= 198.19.255.255
/// Fake IPv6 pool: fc00::/18 (effectively inexhaustible).
pub const FAKE_V6_BASE: u128 = 0xfc00 << 112;
pub const FAKE_V6_PREFIX: u8 = 112; // fc00::/112 slice is plenty (65k tokens)

/// Default per-family mapping capacity (LRU evicts beyond this).
const CAPACITY: usize = 65536;

#[derive(Debug)]
struct Inner {
    domain_to_ip: HashMap<String, IpAddr>,
    ip_to_domain: HashMap<IpAddr, String>,
    /// LRU order, front = oldest. Entries are domains.
    lru: VecDeque<String>,
    v4_next: u32,
    v6_next: u128,
    capacity: usize,
}

/// Shared bidirectional fake-IP map.
#[derive(Debug, Default)]
pub struct FakeIpMap {
    inner: Mutex<Inner>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
            lru: VecDeque::new(),
            v4_next: FAKE_V4_RANGE.0 + 1,
            v6_next: FAKE_V6_BASE + 1,
            capacity: CAPACITY,
        }
    }
}

impl FakeIpMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `ip` is inside the fake v4 pool.
    pub fn is_fake_v4(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let n = u32::from(v4);
                (FAKE_V4_RANGE.0..=FAKE_V4_RANGE.1).contains(&n)
            }
            IpAddr::V6(_) => false,
        }
    }

    /// Whether `ip` is inside the fake v6 pool.
    pub fn is_fake_v6(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V6(v6) => (u128::from(v6) >> FAKE_V6_PREFIX) == (FAKE_V6_BASE >> FAKE_V6_PREFIX),
            IpAddr::V4(_) => false,
        }
    }

    /// Whether `ip` belongs to either pool.
    pub fn is_fake(ip: IpAddr) -> bool {
        Self::is_fake_v4(ip) || Self::is_fake_v6(ip)
    }

    /// Get (or assign) the fake IPv4 token for `domain`.
    pub fn assign_v4(&self, domain: &str) -> Ipv4Addr {
        let domain = domain.to_ascii_lowercase();
        let mut inner = self.inner.lock().unwrap();
        if let Some(ip) = inner.domain_to_ip.get(&domain).copied() {
            touch(&mut inner, &domain);
            if let IpAddr::V4(v4) = ip {
                return v4;
            }
        }
        let ip = loop {
            let n = inner.v4_next;
            inner.v4_next = if n >= FAKE_V4_RANGE.1 { FAKE_V4_RANGE.0 + 1 } else { n + 1 };
            if !inner.ip_to_domain.contains_key(&IpAddr::V4(Ipv4Addr::from(n))) {
                break Ipv4Addr::from(n);
            }
        };
        insert(&mut inner, domain.clone(), IpAddr::V4(ip));
        ip
    }

    /// Get (or assign) the fake IPv6 token for `domain`.
    pub fn assign_v6(&self, domain: &str) -> Ipv6Addr {
        let domain = domain.to_ascii_lowercase();
        let mut inner = self.inner.lock().unwrap();
        if let Some(ip) = inner.domain_to_ip.get(&domain).copied() {
            touch(&mut inner, &domain);
            if let IpAddr::V6(v6) = ip {
                return v6;
            }
        }
        let ip = loop {
            let n = inner.v6_next;
            inner.v6_next = if n >= (FAKE_V6_BASE | ((1u128 << FAKE_V6_PREFIX) - 1)) {
                FAKE_V6_BASE + 1
            } else {
                n + 1
            };
            if !inner.ip_to_domain.contains_key(&IpAddr::V6(Ipv6Addr::from(n))) {
                break Ipv6Addr::from(n);
            }
        };
        insert(&mut inner, domain.clone(), IpAddr::V6(ip));
        ip
    }

    /// Map a fake IP back to its domain (connect-time reverse lookup).
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();
        let domain = inner.ip_to_domain.get(&ip)?.clone();
        touch(&mut inner, &domain);
        Some(domain)
    }

    /// Number of live mappings (both families).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().domain_to_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn touch(inner: &mut Inner, domain: &str) {
    if let Some(pos) = inner.lru.iter().position(|d| d == domain) {
        let d = inner.lru.remove(pos).expect("position checked");
        inner.lru.push_back(d);
    }
}

fn insert(inner: &mut Inner, domain: String, ip: IpAddr) {
    if inner.domain_to_ip.len() >= inner.capacity {
        // Evict oldest until below capacity.
        while inner.domain_to_ip.len() >= inner.capacity {
            let Some(victim) = inner.lru.pop_front() else { break };
            if let Some(vip) = inner.domain_to_ip.remove(&victim) {
                inner.ip_to_domain.remove(&vip);
            }
        }
    }
    inner.domain_to_ip.insert(domain.clone(), ip);
    inner.ip_to_domain.insert(ip, domain.clone());
    inner.lru.push_back(domain);
}


impl FakeIpMap {
    /// Test/debug helper: is a domain currently mapped?
    #[cfg(test)]
    fn lookup_by_domain(&self, domain: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .domain_to_ip
            .contains_key(&domain.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_v4_is_in_range_and_stable() {
        let m = FakeIpMap::new();
        let a = m.assign_v4("twitter.com");
        let b = m.assign_v4("twitter.com");
        assert_eq!(a, b, "same domain must get same token");
        assert!(FakeIpMap::is_fake_v4(IpAddr::V4(a)));
        assert!(FakeIpMap::is_fake(IpAddr::V4(a)));
        let c = m.assign_v4("example.com");
        assert_ne!(a, c, "different domains get different tokens");
    }

    #[test]
    fn assign_v6_is_in_range_and_stable() {
        let m = FakeIpMap::new();
        let a = m.assign_v6("twitter.com");
        assert_eq!(a, m.assign_v6("twitter.com"));
        assert!(FakeIpMap::is_fake_v6(IpAddr::V6(a)));
        let text = a.to_string();
        assert!(text.starts_with("fc00:"), "v6 tokens live in fc00::/18: {text}");
    }

    #[test]
    fn roundtrip_both_families() {
        let m = FakeIpMap::new();
        let v4 = m.assign_v4("baidu.com");
        let v6 = m.assign_v6("baidu.com");
        assert_eq!(
            m.lookup(IpAddr::V4(v4)).as_deref(),
            Some("baidu.com"),
            "v4 token maps back"
        );
        assert_eq!(
            m.lookup(IpAddr::V6(v6)).as_deref(),
            Some("baidu.com"),
            "v6 token maps back"
        );
        assert_eq!(m.lookup(IpAddr::V4(v4)).as_deref(), Some("baidu.com"));
    }

    #[test]
    fn case_insensitive() {
        let m = FakeIpMap::new();
        let a = m.assign_v4("GitHub.com");
        assert_eq!(m.lookup(IpAddr::V4(a)).as_deref(), Some("github.com"));
    }

    #[test]
    fn lru_eviction_keeps_capacity() {
        let m = FakeIpMap::new();
        {
            let mut inner = m.inner.lock().unwrap();
            inner.capacity = 8;
        }
        for i in 0..20 {
            m.assign_v4(&format!("host{i}.example"));
        }
        assert!(m.len() <= 8, "capacity respected, len = {}", m.len());
        // Oldest entries must have been evicted; newest kept.
        assert!(m.lookup_by_domain("host19.example"), "newest kept");
        assert!(!m.lookup_by_domain("host0.example"), "oldest evicted");
    }

    #[test]
    fn real_ips_are_not_fake() {
        assert!(!FakeIpMap::is_fake(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!FakeIpMap::is_fake(
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        ));
        assert!(!FakeIpMap::is_fake(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
