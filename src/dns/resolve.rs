//! Shared resolution engine for BOTH sides of the tunnel:
//!
//! - **client direct path** (`DirectConnector`): resolve China-routed
//!   domains via the configured resolver LIST (racing + failover)
//! - **server side** (`DispatchConnector`/`LocalConnector` + DNS relay):
//!   resolve tunnel-routed domains via the `[dns] upstream` list or all
//!   nameservers in resolv.conf
//!
//! Layers, per lookup:
//!   1. cache (TTL from the answer, clamped)
//!   2. /etc/hosts (containers, LANs, nsswitch parity)
//!   3. racing UDP probes across ALL upstreams (first answer wins,
//!      per-candidate search domains applied)
//!   4. last resort: system resolver (getaddrinfo)
//!
//! Answers are ordered getaddrinfo-style (RFC 6724): v6 first when the
//! host has a global v6 route.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

use log::{debug, warn};

/// Probe round timeout per upstream (racing makes the worst case this,
/// not timeout x N).
const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);
/// TTL clamps for cache entries.
const TTL_MIN: u32 = 1;
const TTL_MAX: u32 = 600;
const DEFAULT_CACHE_CAP: usize = 4096;

// ---------------------------------------------------------------- probes

/// Build a minimal DNS query for `host` (label-encoded, fixed id).
pub fn build_probe_query(host: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

/// One answer record pulled from a response.
pub struct AnswerRecord {
    pub addr: SocketAddr,
    pub ttl: u32,
}

/// Extract A/AAAA records (and the minimum TTL) from a DNS response.
pub fn collect_answers(resp: &[u8]) -> (Vec<AnswerRecord>, Option<u32>) {
    let mut out = Vec::new();
    let mut min_ttl: Option<u32> = None;
    if resp.len() < 12 {
        return (out, min_ttl);
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    // Skip the question section.
    let mut rest = &resp[12..];
    {
        let mut r = rest;
        loop {
            let Some(&len) = r.first() else { return (out, min_ttl) };
            if len & 0xC0 == 0xC0 {
                r = &r[2..];
                break;
            }
            if len == 0 {
                r = &r[1..];
                break;
            }
            if r.len() < 1 + len as usize {
                return (out, min_ttl);
            }
            r = &r[1 + len as usize..];
        }
        if r.len() < 4 {
            return (out, min_ttl);
        }
        rest = &r[4..];
    }
    for _ in 0..ancount {
        let mut r = rest;
        loop {
            let Some(&len) = r.first() else { return (out, min_ttl) };
            if len & 0xC0 == 0xC0 {
                r = &r[2..];
                break;
            }
            if len == 0 {
                r = &r[1..];
                break;
            }
            if r.len() < 1 + len as usize {
                return (out, min_ttl);
            }
            r = &r[1 + len as usize..];
        }
        if r.len() < 10 {
            return (out, min_ttl);
        }
        let rtype = u16::from_be_bytes([r[0], r[1]]);
        let ttl = u32::from_be_bytes([r[4], r[5], r[6], r[7]]);
        let rdlen = u16::from_be_bytes([r[8], r[9]]) as usize;
        let rdata = &r[10..10 + rdlen.min(r.len().saturating_sub(10))];
        let addr = match rtype {
            1 if rdata.len() == 4 => {
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )), 0)
            }
            28 if rdata.len() == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(o)), 0)
            }
            _ => {
                rest = &r[10 + rdlen..];
                continue;
            }
        };
        min_ttl = Some(match min_ttl {
            Some(m) => m.min(ttl),
            None => ttl,
        });
        out.push(AnswerRecord { addr, ttl });
        rest = &r[10 + rdlen..];
    }
    (out, min_ttl)
}

/// Query one upstream once (A + AAAA). Returns (answers, min_ttl).
async fn probe_upstream(
    upstream: SocketAddr,
    host: &str,
) -> io::Result<(Vec<AnswerRecord>, Option<u32>)> {
    let bind: SocketAddr = match upstream {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = crate::connector::udp_socket_marked(bind).await?;
    sock.connect(upstream).await?;
    let mut answers = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for qtype in [crate::dns::proto::QTYPE_AAAA, crate::dns::proto::QTYPE_A] {
        sock.send(&build_probe_query(host, qtype)).await?;
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(PROBE_TIMEOUT, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns probe timeout"))??;
        let (recs, ttl) = collect_answers(&buf[..n]);
        if !recs.is_empty() {
            answers.extend(recs);
            min_ttl = match (min_ttl, ttl) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            // Both families queried regardless; keep collecting.
        }
    }
    if answers.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no answers"));
    }
    Ok((answers, min_ttl))
}

// ---------------------------------------------------------------- helpers

/// Search domains from /etc/resolv.conf ("search"/"domain" lines).
pub fn search_domains() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("search").or_else(|| line.strip_prefix("domain")) {
                for d in rest.split_whitespace() {
                    if !d.is_empty() {
                        out.push(d.trim_end_matches('.').to_string());
                    }
                }
            }
        }
    }
    out
}

/// ALL nameservers from /etc/resolv.conf (not just the first).
pub fn nameservers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    out.push(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    if out.is_empty() {
        out.push("127.0.0.1:53".parse().unwrap());
    }
    out
}

/// /etc/hosts lookup: all addresses bound to `name` (case-insensitive).
pub fn hosts_lookup(name: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string("/etc/hosts") else { return out };
    let name = name.to_ascii_lowercase();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(ip), mut names) = (fields.next(), fields) else { continue };
        let Ok(ip) = ip.parse::<IpAddr>() else { continue };
        if names.any(|n| n.eq_ignore_ascii_case(&name)) {
            out.push(ip);
        }
    }
    out
}

/// Whether the host has a GLOBAL v6 route (RFC 6724 ordering heuristic).
pub fn host_has_global_v6() -> bool {
    std::fs::read_to_string("/proc/net/ipv6_route")
        .map(|t| {
            t.lines().any(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.len() > 2 && f[0] == "00000000000000000000000000000000" && f[1] == "00"
            })
        })
        .unwrap_or(false)
}

/// Order answers getaddrinfo-style: v6 first when preferred.
pub fn order_addrs(mut addrs: Vec<SocketAddr>, prefer_v6: bool) -> Vec<SocketAddr> {
    addrs.sort_by_key(|a| if prefer_v6 && a.is_ipv6() { 0 } else { 1 });
    addrs
}

// ---------------------------------------------------------------- resolver

struct CacheEntry {
    addrs: Vec<IpAddr>,
    expiry: Option<Instant>, // None = hosts entry (no expiry)
    touched: Instant,
}

#[derive(Default)]
struct CacheInner {
    map: HashMap<String, CacheEntry>,
}

/// Layered resolver: cache -> hosts -> racing upstreams -> system.
pub struct Resolver {
    upstreams: Vec<SocketAddr>,
    cache: Mutex<CacheInner>,
    cap: usize,
}

impl Resolver {
    pub fn new(upstreams: Vec<SocketAddr>, cache_cap: Option<usize>) -> Self {
        Self {
            upstreams,
            cache: Mutex::new(CacheInner::default()),
            cap: cache_cap.unwrap_or(DEFAULT_CACHE_CAP),
        }
    }

    /// From server config: explicit list, else every nameserver.
    pub fn from_config_list(list: Option<Vec<SocketAddr>>) -> Self {
        Self::new(list.unwrap_or_else(nameservers), None)
    }

    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }

    /// Resolve `host` to addresses (port stamped in), layered.
    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();

        // 1. cache
        if let Some(hit) = self.cache_get(&host) {
            debug!("resolve[{host}]: cache hit ({:?})", hit.len());
            return Ok(hit.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
        }

        // 2. hosts
        let hosts = hosts_lookup(&host);
        if !hosts.is_empty() {
            debug!("resolve[{host}]: /etc/hosts ({})", hosts.len());
            self.cache_put(host.clone(), hosts.clone(), None);
            return Ok(order_addrs(
                hosts.iter().map(|ip| SocketAddr::new(*ip, port)).collect(),
                host_has_global_v6(),
            ));
        }

        // 3. racing upstreams (bare name + search domains)
        let mut candidates = vec![host.clone()];
        for suffix in search_domains() {
            candidates.push(format!("{host}.{suffix}"));
        }
        for cand in &candidates {
            match self.race_upstreams(cand).await {
                Ok((answers, ttl)) if !answers.is_empty() => {
                    let ips: Vec<IpAddr> = answers.iter().map(|a| a.addr.ip()).collect();
                    let clamped = ttl.map(|t| t.clamp(TTL_MIN, TTL_MAX));
                    debug!(
                        "resolve[{host}] via {cand}: {} addrs (ttl {:?})",
                        ips.len(),
                        clamped
                    );
                    self.cache_put(host.clone(), ips.clone(), clamped.map(|s| Instant::now() + Duration::from_secs(s as u64)));
                    return Ok(order_addrs(
                        ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect(),
                        host_has_global_v6(),
                    ));
                }
                Ok(_) => continue,
                Err(err) => {
                    debug!("resolve[{cand}] upstreams failed: {err}");
                }
            }
        }

        // 4. last resort: system resolver (covers odd nss setups).
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(addrs) => {
                let addrs: Vec<SocketAddr> = addrs.collect();
                if !addrs.is_empty() {
                    debug!("resolve[{host}]: system resolver fallback");
                    return Ok(addrs);
                }
            }
            Err(err) => debug!("resolve[{host}]: system fallback failed: {err}"),
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "no resolution"))
    }

    /// Race ALL upstreams on one candidate name; first success wins.
    async fn race_upstreams(&self, host: &str) -> io::Result<(Vec<AnswerRecord>, Option<u32>)> {
        if self.upstreams.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no upstreams"));
        }
        let mut tasks = Vec::with_capacity(self.upstreams.len());
        for up in &self.upstreams {
            let (up, host) = (*up, host.to_string());
            tasks.push(tokio::spawn(async move { probe_upstream(up, &host).await }));
        }
        let (result, _idx, rest) = futures::future::select_all(tasks).await;
        // Abort the losers (best effort).
        for t in rest {
            t.abort();
        }
        match result {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => {
                warn!("dns race: first upstream failed: {e}");
                Err(e)
            }
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn cache_get(&self, host: &str) -> Option<Vec<IpAddr>> {
        let mut c = self.cache.lock().unwrap();
        let entry = c.map.get_mut(host)?;
        match entry.expiry {
            Some(exp) if Instant::now() >= exp => {
                c.map.remove(host);
                None
            }
            _ => {
                entry.touched = Instant::now();
                Some(entry.addrs.clone())
            }
        }
    }

    fn cache_put(&self, host: String, addrs: Vec<IpAddr>, expiry: Option<Instant>) {
        let mut c = self.cache.lock().unwrap();
        if c.map.len() >= self.cap {
            // Evict expired first, then the least recently touched.
            let now = Instant::now();
            c.map.retain(|_, e| e.expiry.map(|x| x > now).unwrap_or(true));
            while c.map.len() >= self.cap {
                let victim = c
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.touched)
                    .map(|(k, _)| k.clone());
                match victim {
                    Some(k) => {
                        c.map.remove(&k);
                    }
                    None => break,
                }
            }
        }
        c.map.insert(host, CacheEntry { addrs, expiry, touched: Instant::now() });
    }
}
