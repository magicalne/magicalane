//! Client-side tunnel pool: multiple servers + automatic proxy groups.
//!
//! A client may configure several tunnel servers (mixed transports:
//! QUIC and KCP freely) and groups over them:
//!
//!   `url-test`      — probe each member through its own tunnel, use
//!                     the fastest; hysteresis via `tolerance` (ms).
//!   `fallback`      — priority order: first alive member wins.
//!   `load-balance`  — spread connections: `round-robin` (default) or
//!                     `sticky` (destination hash).
//!
//! Routing rules can pin traffic to a server or group by name
//! (`action = "work"`); unmatched traffic uses the default target.
//! Health: a server is dead after 3 consecutive probe failures and
//! alive again after one success. All selection is automatic — no
//! manual mode.

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    config::GroupSpec,
    connector::{Connector, QuicConnector},
    kcp::connector::KcpConnector,
    socks5::proto::Addr,
};

/// One live tunnel connection: whatever the transport hands back.
pub enum TunnelStream {
    Quic(crate::quic::stream::QuicStream),
    Kcp(crate::kcp::connector::EitherKcpStream),
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TunnelStream::Quic(s) => Pin::new(s).poll_read(cx, buf),
            TunnelStream::Kcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            TunnelStream::Quic(s) => Pin::new(s).poll_write(cx, buf),
            TunnelStream::Kcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            TunnelStream::Quic(s) => Pin::new(s).poll_flush(cx),
            TunnelStream::Kcp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            TunnelStream::Quic(s) => Pin::new(s).poll_shutdown(cx),
            TunnelStream::Kcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// One configured tunnel server, transport-agnostic.
#[derive(Clone)]
pub enum TunnelConnector {
    Quic(QuicConnector),
    Kcp(KcpConnector),
}

impl TunnelConnector {
    /// KCP: fill the prewarm session pool (QUIC: no-op).
    pub fn prewarm(&self) {
        if let TunnelConnector::Kcp(c) = self {
            c.prewarm();
        }
    }

    pub fn protocol(&self) -> &'static str {
        match self {
            TunnelConnector::Quic(_) => "quic",
            TunnelConnector::Kcp(_) => "kcp",
        }
    }
}

impl Connector for TunnelConnector {
    type Connection = TunnelStream;

    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        let mut c = self.clone();
        match &mut c {
            TunnelConnector::Quic(qc) => {
                let fut = Connector::connect(qc, a);
                Box::pin(async move { fut.await.map(TunnelStream::Quic) })
            }
            TunnelConnector::Kcp(kc) => {
                let fut = Connector::connect(kc, a);
                Box::pin(async move { fut.await.map(TunnelStream::Kcp) })
            }
        }
    }
}

/// Server health as seen by the probe tasks.
#[derive(Debug, Clone)]
pub struct Health {
    pub alive: bool,
    pub latency: Option<std::time::Duration>,
    pub consecutive_failures: u32,
}

impl Default for Health {
    fn default() -> Self {
        Self { alive: true, latency: None, consecutive_failures: 0 }
    }
}

/// Probe outcome recorded by the health task.
#[derive(Debug, Clone, Copy)]
pub enum ProbeResult {
    Ok(std::time::Duration),
    Failed,
}

/// Failures before a server is marked dead.
pub const DEAD_THRESHOLD: u32 = 3;

/// Apply a probe result to a server's health.
pub fn record_probe(h: &mut Health, r: ProbeResult) -> bool {
    let was_alive = h.alive;
    match r {
        ProbeResult::Ok(d) => {
            h.alive = true;
            h.latency = Some(d);
            h.consecutive_failures = 0;
        }
        ProbeResult::Failed => {
            h.latency = None;
            h.consecutive_failures = h.consecutive_failures.saturating_add(1);
            if h.consecutive_failures >= DEAD_THRESHOLD {
                h.alive = false;
            }
        }
    }
    was_alive != h.alive
}

pub struct ServerEntry {
    pub name: Arc<str>,
    pub connector: TunnelConnector,
    pub state: Arc<std::sync::RwLock<Health>>,
}

impl ServerEntry {
    fn alive(&self) -> bool {
        self.state.read().unwrap().alive
    }
}

/// Group selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Fastest alive member (probe latency), switch on > tolerance gain.
    UrlTest { tolerance_ms: u64 },
    /// First alive member in config order.
    Fallback,
    /// Spread connections: round-robin or destination-hash sticky.
    LoadBalance { sticky: bool },
}

/// A named group over servers and/or other groups.
pub struct Group {
    pub name: Arc<str>,
    pub strategy: Strategy,
    /// Ordered member targets (server or group names).
    pub members: Vec<String>,
    pub probe_url: String,
    pub interval: std::time::Duration,
    /// Current selection (url-test / fallback): server name.
    chosen: std::sync::RwLock<Option<Arc<str>>>,
    /// Round-robin counter (load-balance).
    rr: std::sync::atomic::AtomicU64,
}

impl Group {
    pub fn chosen(&self) -> Option<Arc<str>> {
        self.chosen.read().unwrap().clone()
    }
    pub fn set_chosen(&self, name: Arc<str>) {
        *self.chosen.write().unwrap() = Some(name);
    }
    fn next_rr(&self) -> u64 {
        self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

impl std::fmt::Debug for ProxyPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyPool")
            .field("servers", &self.inner.servers.keys().collect::<Vec<_>>())
            .field("groups", &self.inner.groups.keys().collect::<Vec<_>>())
            .field("default", &&*self.inner.default)
            .finish()
    }
}

impl Connector for ProxyPool {
    type Connection = TunnelStream;

    /// Default-target connect (socks5 / DNS magic / provider fetches).
    fn connect(&mut self, a: Addr) -> BoxFuture<'static, io::Result<Self::Connection>> {
        ProxyPool::connect(self, None, a, None)
    }
}

/// Everything the client needs to pick a tunnel for a connection.
#[derive(Clone)]
pub struct ProxyPool {
    inner: Arc<Inner>,
}

struct Inner {
    servers: HashMap<Arc<str>, Arc<ServerEntry>>,
    groups: HashMap<Arc<str>, Arc<Group>>,
    /// Default target name (server or group); the primary server is
    /// conventionally named "default".
    default: Arc<str>,
}

/// Errors while building a pool from config.
#[derive(Debug)]
pub enum PoolError {
    DuplicateName(String),
    UnknownTarget(String),
    EmptyGroup(String),
    GroupCycle(String),
    UnknownStrategy(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::DuplicateName(n) => write!(f, "duplicate server/group name {n:?}"),
            PoolError::UnknownTarget(n) => {
                write!(f, "unknown server/group {n:?} (referenced by a rule or group)")
            }
            PoolError::EmptyGroup(n) => write!(f, "group {n:?} has no members"),
            PoolError::GroupCycle(n) => write!(f, "group {n:?} is part of a reference cycle"),
            PoolError::UnknownStrategy(s) => write!(f, "unknown group type {s:?}"),
        }
    }
}

impl std::error::Error for PoolError {}

impl ProxyPool {
    /// Single-server pool (back-compat shape).
    pub fn single(connector: TunnelConnector) -> Self {
        let name: Arc<str> = Arc::from("default");
        let mut servers = HashMap::new();
        servers.insert(
            name.clone(),
            Arc::new(ServerEntry {
                name: name.clone(),
                connector,
                state: Arc::new(std::sync::RwLock::new(Health::default())),
            }),
        );
        Self {
            inner: Arc::new(Inner { servers, groups: HashMap::new(), default: name }),
        }
    }

    fn entry(name: &str, connector: TunnelConnector) -> Arc<ServerEntry> {
        Arc::new(ServerEntry {
            name: Arc::from(name),
            connector,
            state: Arc::new(std::sync::RwLock::new(Health::default())),
        })
    }

    /// Build from parts. `entries` must contain the primary "default"
    /// server. `known_targets` = every name referenced by routing rules
    /// (plus the routing `default`); all are validated here so config
    /// mistakes fail at startup.
    pub fn build(
        entries: Vec<(Arc<str>, TunnelConnector)>,
        groups: Vec<GroupSpec>,
        default: Option<&str>,
        known_targets: &[String],
    ) -> Result<Self, PoolError> {
        let mut servers = HashMap::new();
        for (name, connector) in entries {
            if servers.contains_key(&name) {
                return Err(PoolError::DuplicateName(name.to_string()));
            }
            servers.insert(
                name.clone(),
                Self::entry(&name, connector),
            );
        }
        let primary: Arc<str> = Arc::from("default");
        if !servers.contains_key(&primary) {
            return Err(PoolError::UnknownTarget("default".into()));
        }

        let mut group_map: HashMap<Arc<str>, Arc<Group>> = HashMap::new();
        for g in &groups {
            let name: Arc<str> = Arc::from(g.name.as_str());
            if servers.contains_key(&name) || group_map.contains_key(&name) {
                return Err(PoolError::DuplicateName(g.name.clone()));
            }
            if g.servers.is_empty() {
                return Err(PoolError::EmptyGroup(g.name.clone()));
            }
            let strategy = match g.gtype.as_str() {
                "url-test" => Strategy::UrlTest {
                    tolerance_ms: g.tolerance.unwrap_or(50),
                },
                "fallback" => Strategy::Fallback,
                "load-balance" => Strategy::LoadBalance {
                    sticky: g.strategy.as_deref() == Some("sticky"),
                },
                other => return Err(PoolError::UnknownStrategy(other.to_string())),
            };
            group_map.insert(
                name.clone(),
                Arc::new(Group {
                    name,
                    strategy,
                    members: g.servers.clone(),
                    probe_url: g
                        .url
                        .clone()
                        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".into()),
                    interval: std::time::Duration::from_secs(g.interval.unwrap_or(300)),
                    chosen: std::sync::RwLock::new(None),
                    rr: std::sync::atomic::AtomicU64::new(0),
                }),
            );
        }

        // Validate every referenced target.
        for g in group_map.values() {
            for m in &g.members {
                if !servers.contains_key(m.as_str()) && !group_map.contains_key(m.as_str()) {
                    return Err(PoolError::UnknownTarget(m.clone()));
                }
            }
        }
        for t in known_targets {
            if t != "proxy"
                && !servers.contains_key(t.as_str())
                && !group_map.contains_key(t.as_str())
            {
                return Err(PoolError::UnknownTarget(t.clone()));
            }
        }
        // Cycle detection: DFS from every group.
        for g in group_map.values() {
            let mut seen = vec![g.name.to_string()];
            if let Some(cycle) = find_cycle(g, &group_map, &mut seen) {
                return Err(PoolError::GroupCycle(cycle));
            }
        }

        let default: Arc<str> = match default {
            None | Some("proxy") => primary,
            Some("direct") => return Err(PoolError::UnknownTarget(
                "routing default \"direct\" makes no sense for the tunnel pool".into(),
            )),
            Some(name) => {
                let key: Arc<str> = Arc::from(name);
                if !servers.contains_key(&key) && !group_map.contains_key(&key) {
                    return Err(PoolError::UnknownTarget(name.to_string()));
                }
                key
            }
        };

        Ok(Self {
            inner: Arc::new(Inner { servers, groups: group_map, default }),
        })
    }

    pub fn servers(&self) -> &HashMap<Arc<str>, Arc<ServerEntry>> {
        &self.inner.servers
    }

    pub fn groups(&self) -> &HashMap<Arc<str>, Arc<Group>> {
        &self.inner.groups
    }

    pub fn default_name(&self) -> &str {
        &self.inner.default
    }

    pub fn server(&self, name: &str) -> Option<Arc<ServerEntry>> {
        self.inner.servers.get(name).cloned()
    }

    /// Resolve a target name (or None = default) down to a server
    /// entry, applying group strategy and health state.
    pub fn resolve(&self, target: Option<&str>) -> io::Result<Arc<ServerEntry>> {
        let name = target.unwrap_or(&self.inner.default);
        self.resolve_name(name, 0)
    }

    fn resolve_name(&self, name: &str, depth: usize) -> io::Result<Arc<ServerEntry>> {
        if depth > 16 {
            return Err(io::Error::other(format!("group nesting too deep at {name:?}")));
        }
        if let Some(s) = self.inner.servers.get(name) {
            return Ok(s.clone());
        }
        let Some(g) = self.inner.groups.get(name) else {
            return Err(io::Error::other(format!("unknown server/group {name:?}")));
        };
        match g.strategy {
            Strategy::Fallback => {
                // Walk members in priority order: first alive wins.
                for m in &g.members {
                    if let Ok(entry) = self.resolve_name(m, depth + 1) {
                        if entry.alive() {
                            g.set_chosen(entry.name.clone());
                            return Ok(entry);
                        }
                    }
                }
                // Nothing alive: first member (the connect will fail loudly).
                self.resolve_name(&g.members[0], depth + 1)
            }
            Strategy::UrlTest { .. } => {
                // The probe task maintains `chosen`; serve it while alive.
                if let Some(chosen) = g.chosen() {
                    if let Some(entry) = self.inner.servers.get(&chosen) {
                        if entry.alive() {
                            return Ok(entry.clone());
                        }
                    }
                }
                // Stopgap until the next probe reelects: any alive member.
                for m in &g.members {
                    if let Ok(entry) = self.resolve_name(m, depth + 1) {
                        if entry.alive() {
                            return Ok(entry);
                        }
                    }
                }
                self.resolve_name(&g.members[0], depth + 1)
            }
            Strategy::LoadBalance { sticky } => {
                let _ = sticky; // sticky handled by resolve_sticky (needs the key)
                let alive = self.alive_members(g, depth);
                if alive.is_empty() {
                    return self.resolve_name(&g.members[0], depth + 1);
                }
                let i = g.next_rr() as usize % alive.len();
                Ok(alive[i].clone())
            }
        }
    }

    fn alive_members(
        &self,
        g: &Group,
        depth: usize,
    ) -> Vec<Arc<ServerEntry>> {
        g.members
            .iter()
            .filter_map(|m| self.resolve_name(m, depth + 1).ok())
            .filter(|e| e.alive())
            .collect()
    }

    /// Destination-keyed selection: sticky load-balance hashes the key
    /// so one destination keeps one server while it lives; all other
    /// strategies behave like `resolve`.
    pub fn resolve_sticky(&self, target: Option<&str>, key: &str) -> io::Result<Arc<ServerEntry>> {
        let name = target.unwrap_or(&self.inner.default);
        if let Some(g) = self.inner.groups.get(name) {
            if let Strategy::LoadBalance { sticky: true } = g.strategy {
                let alive = self.alive_members(g, 0);
                if !alive.is_empty() {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    std::hash::Hash::hash(&key, &mut h);
                    let i = std::hash::Hasher::finish(&h) as usize % alive.len();
                    return Ok(alive[i].clone());
                }
                return self.resolve_name(&g.members[0], 0);
            }
        }
        self.resolve(target)
    }

    /// Connect through a target (None = default). The decision layer's
    /// `server` name flows in here. `dst_key` (destination domain or
    /// ip:port) enables sticky load-balance when present.
    pub fn connect(
        &self,
        target: Option<&str>,
        dst: Addr,
        dst_key: Option<&str>,
    ) -> BoxFuture<'static, io::Result<TunnelStream>> {
        let entry = match dst_key {
            Some(k) => self.resolve_sticky(target, k),
            None => self.resolve(target),
        };
        Box::pin(async move {
            let mut c = entry?.connector.clone();
            c.connect(dst).await
        })
    }

    /// Log the pool layout at startup.
    pub fn log_layout(&self) {
        let mut names: Vec<&str> = self.inner.servers.keys().map(|s| &**s).collect();
        names.sort_unstable();
        log::info!(
            "pool: {} server(s) [{}] default={:?}",
            names.len(),
            names.join(", "),
            &*self.inner.default
        );
        for g in self.inner.groups.values() {
            log::info!(
                "pool: group {:?} {} members={:?} interval={}s",
                &*g.name,
                match g.strategy {
                    Strategy::UrlTest { tolerance_ms } => {
                        format!("url-test(tol={tolerance_ms}ms)")
                    }
                    Strategy::Fallback => "fallback".into(),
                    Strategy::LoadBalance { sticky: true } => "load-balance(sticky)".into(),
                    Strategy::LoadBalance { sticky: false } => "load-balance(rr)".into(),
                },
                g.members,
                g.interval.as_secs()
            );
        }
    }
}

fn find_cycle(
    g: &Group,
    groups: &HashMap<Arc<str>, Arc<Group>>,
    seen: &mut Vec<String>,
) -> Option<String> {
    for m in &g.members {
        if let Some(next) = groups.get(m.as_str()) {
            if seen.iter().any(|s| s == m) {
                return Some(m.clone());
            }
            seen.push(m.clone());
            if let Some(c) = find_cycle(next, groups, seen) {
                return Some(c);
            }
            seen.pop();
        }
    }
    None
}

// ---------------------------------------------------------------- probes

/// Spawn one health-probe task per group (immediate probe, then on
/// `interval`). Servers not referenced by any group are never probed
/// (they stay "alive" until a real connect fails).
pub fn spawn_probes(pool: ProxyPool) {
    for g in pool.groups().values() {
        let pool = pool.clone();
        let gname: Arc<str> = g.name.clone();
        let url = g.probe_url.clone();
        let interval = g.interval;
        tokio::spawn(async move {
            loop {
                probe_cycle(&pool, &gname, &url).await;
                tokio::time::sleep(interval).await;
            }
        });
    }
}

/// Collect the distinct servers under a group (recursing through
/// nested groups), preserving first-seen order.
fn group_servers(pool: &ProxyPool, gname: &str, out: &mut Vec<Arc<str>>, depth: usize) {
    if depth > 16 {
        return;
    }
    let Some(g) = pool.groups().get(gname) else { return };
    for m in &g.members {
        if let Some(s) = pool.servers().get(m.as_str()) {
            if !out.iter().any(|n| **n == *s.name) {
                out.push(s.name.clone());
            }
        } else {
            group_servers(pool, m, out, depth + 1);
        }
    }
}

/// One probe round for a group: measure every member, update health,
/// re-elect url-test choices.
async fn probe_cycle(pool: &ProxyPool, gname: &str, url: &str) {
    let Some(group) = pool.groups().get(gname) else { return };
    let mut members = Vec::new();
    group_servers(pool, gname, &mut members, 0);
    let u = match crate::httpfetch::parse_url(url) {
        Ok(u) => u,
        Err(e) => {
            log::warn!("probe[{gname}]: bad probe url: {e}");
            return;
        }
    };
    let addr = crate::httpfetch::url_addr(&u);

    let mut results: Vec<(Arc<str>, Option<std::time::Duration>)> = Vec::new();
    for name in members {
        let Some(entry) = pool.server(&name) else { continue };
        let started = std::time::Instant::now();
        let ok = probe_one(&entry.connector, addr.clone(), &u).await;
        let elapsed = started.elapsed();
        let r = if ok { ProbeResult::Ok(elapsed) } else { ProbeResult::Failed };
        let mut h = entry.state.write().unwrap();
        let was = h.clone();
        let changed = record_probe(&mut h, r);
        let latency = h.latency;
        drop(h);
        if changed {
            log::info!(
                "probe[{gname}]: {name} is now {}",
                if was.alive { "DEAD" } else { "ALIVE" }
            );
        }
        results.push((name, if ok { latency } else { None }));
    }

    // url-test election with tolerance hysteresis.
    if let Strategy::UrlTest { tolerance_ms } = group.strategy {
        let mut best: Option<(&Arc<str>, std::time::Duration)> = None;
        for (name, lat) in &results {
            if let Some(lat) = lat {
                if best.is_none() || Some(*lat) < best.map(|(_, l)| l) {
                    best = Some((name, *lat));
                }
            }
        }
        if let Some((best_name, best_lat)) = best {
            let incumbent_lat = group
                .chosen()
                .and_then(|c| results.iter().find(|(n, _)| *n == c))
                .and_then(|(_, l)| *l);
            let switch = match incumbent_lat {
                None => true,
                Some(inc) => {
                    inc.saturating_sub(best_lat).as_millis() as u64 > tolerance_ms
                }
            };
            if switch {
                if group.chosen().as_deref() != Some(&**best_name) {
                    log::info!(
                        "probe[{gname}]: url-test -> {best_name} ({}ms)",
                        best_lat.as_millis()
                    );
                }
                group.set_chosen(best_name.clone());
            }
        }
    }
    // Fallback/load-balance resolve live at connect time from health.
}

/// Probe one server: one HTTP GET through its own tunnel; true on any
/// completed response within the timeout.
async fn probe_one(
    connector: &TunnelConnector,
    addr: crate::socks5::proto::Addr,
    u: &crate::httpfetch::Url<'_>,
) -> bool {
    let fut = async {
        let mut c = connector.clone();
        let stream = c.connect(addr).await?;
        let body = if u.tls {
            let tls = crate::httpfetch::tls_wrap(stream, u.host).await?;
            crate::httpfetch::fetch_over(tls, u).await
        } else {
            crate::httpfetch::fetch_over(stream, u).await
        }?;
        io::Result::Ok(body.len())
    };
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), fut).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GroupSpec;

    /// A connector that can be built without a runtime (KCP to a dead
    /// local port — selection tests never connect).
    fn dummy() -> TunnelConnector {
        TunnelConnector::Kcp(
            KcpConnector::new("127.0.0.1".into(), 1, None, vec![], false, None).unwrap(),
        )
    }

    fn spec(name: &str, gtype: &str, members: &[&str]) -> GroupSpec {
        GroupSpec {
            name: name.into(),
            gtype: gtype.into(),
            servers: members.iter().map(|s| s.to_string()).collect(),
            url: None,
            interval: Some(2),
            tolerance: Some(0),
            strategy: None,
        }
    }

    fn pool(groups: Vec<GroupSpec>) -> ProxyPool {
        let entries = vec![
            (Arc::from("default"), dummy()),
            (Arc::from("a"), dummy()),
            (Arc::from("b"), dummy()),
        ];
        ProxyPool::build(entries, groups, None, &[]).unwrap()
    }

    fn mark(p: &ProxyPool, name: &str, alive: bool, latency_ms: Option<u64>) {
        let entry = p.server(name).unwrap();
        let mut h = entry.state.write().unwrap();
        h.alive = alive;
        h.latency = latency_ms.map(std::time::Duration::from_millis);
        if !alive {
            h.consecutive_failures = DEAD_THRESHOLD;
        }
    }

    #[test]
    fn build_validates_names_and_cycles() {
        let entries = vec![(Arc::from("default"), dummy())];
        // unknown rule target
        let err = ProxyPool::build(
            entries.clone(),
            vec![],
            None,
            &["nope".to_string()],
        )
        .unwrap_err();
        assert!(matches!(err, PoolError::UnknownTarget(_)), "{err}");
        // cycle: g1 -> g2 -> g1
        let err = ProxyPool::build(
            entries,
            vec![
                spec("g1", "fallback", &["g2", "default"]),
                spec("g2", "fallback", &["g1"]),
            ],
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, PoolError::GroupCycle(_)), "{err}");
        // duplicate name
        let err = ProxyPool::build(
            vec![(Arc::from("default"), dummy()), (Arc::from("default"), dummy())],
            vec![],
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, PoolError::DuplicateName(_)), "{err}");
        // empty group
        let err = ProxyPool::build(
            vec![(Arc::from("default"), dummy())],
            vec![spec("g", "fallback", &[])],
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, PoolError::EmptyGroup(_)), "{err}");
        // unknown strategy
        let err = ProxyPool::build(
            vec![(Arc::from("default"), dummy())],
            vec![spec("g", "select", &["default"])],
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, PoolError::UnknownStrategy(_)), "{err}");
    }

    #[test]
    fn fallback_first_alive_wins() {
        let p = pool(vec![spec("fb", "fallback", &["a", "b"])]);
        assert_eq!(p.resolve(Some("fb")).unwrap().name.as_ref(), "a");
        mark(&p, "a", false, None);
        assert_eq!(p.resolve(Some("fb")).unwrap().name.as_ref(), "b");
        mark(&p, "b", false, None);
        // all dead: first member (loud failure)
        assert_eq!(p.resolve(Some("fb")).unwrap().name.as_ref(), "a");
        mark(&p, "a", true, None);
        assert_eq!(p.resolve(Some("fb")).unwrap().name.as_ref(), "a");
        // group as member of another group
        let p2 = pool(vec![
            spec("inner", "fallback", &["a", "b"]),
            spec("outer", "fallback", &["inner", "default"]),
        ]);
        mark(&p2, "a", false, None);
        assert_eq!(p2.resolve(Some("outer")).unwrap().name.as_ref(), "b");
    }

    #[test]
    fn url_test_serves_chosen_and_stopgaps() {
        let p = pool(vec![spec("ut", "url-test", &["a", "b"])]);
        p.groups()["ut"].set_chosen(Arc::from("b"));
        assert_eq!(p.resolve(Some("ut")).unwrap().name.as_ref(), "b");
        // chosen died: stopgap to any alive member until re-election
        mark(&p, "b", false, None);
        assert_eq!(p.resolve(Some("ut")).unwrap().name.as_ref(), "a");
    }

    #[test]
    fn load_balance_round_robin_spreads() {
        let p = pool(vec![spec("lb", "load-balance", &["a", "b"])]);
        let mut seen = Vec::new();
        for _ in 0..4 {
            seen.push(p.resolve(Some("lb")).unwrap().name.as_ref().to_string());
        }
        seen.sort();
        assert_eq!(seen, vec!["a", "a", "b", "b"]);
        // dead members skipped
        mark(&p, "a", false, None);
        let mut all_b = true;
        for _ in 0..4 {
            if p.resolve(Some("lb")).unwrap().name.as_ref() != "b" {
                all_b = false;
            }
        }
        assert!(all_b, "dead member must be skipped");
    }

    #[test]
    fn sticky_hash_stable_and_consistent() {
        let groups = vec![GroupSpec {
            name: "lb".into(),
            gtype: "load-balance".into(),
            servers: vec!["a".into(), "b".into()],
            url: None,
            interval: Some(2),
            tolerance: None,
            strategy: Some("sticky".into()),
        }];
        let p = pool(groups);
        let first = p.resolve_sticky(Some("lb"), "example.com:443").unwrap();
        for _ in 0..5 {
            assert_eq!(
                p.resolve_sticky(Some("lb"), "example.com:443").unwrap().name,
                first.name
            );
        }
        // a different destination may land elsewhere; both keys must be
        // stable across calls (that's the guarantee under test).
        let other = p.resolve_sticky(Some("lb"), "other.example:443").unwrap();
        for _ in 0..5 {
            assert_eq!(
                p.resolve_sticky(Some("lb"), "other.example:443").unwrap().name,
                other.name
            );
        }
        // dead server: consistent fallback to the alive one
        let dead = first.name.clone();
        mark(&p, &dead, false, None);
        let after = p.resolve_sticky(Some("lb"), "example.com:443").unwrap();
        assert_ne!(after.name, dead);
    }

    #[test]
    fn health_thresholds() {
        let mut h = Health::default();
        assert!(h.alive);
        for _ in 0..(DEAD_THRESHOLD - 1) {
            assert!(!record_probe(&mut h, ProbeResult::Failed));
        }
        assert!(record_probe(&mut h, ProbeResult::Failed), "dies at threshold");
        assert!(record_probe(&mut h, ProbeResult::Ok(std::time::Duration::from_millis(5))));
        assert!(h.alive);
        assert_eq!(h.latency, Some(std::time::Duration::from_millis(5)));
    }

    #[test]
    fn default_target_resolution() {
        let p = pool(vec![spec("fb", "fallback", &["a", "default"])]);
        assert_eq!(p.resolve(None).unwrap().name.as_ref(), "default");
        let p2 = ProxyPool::build(
            vec![(Arc::from("default"), dummy()), (Arc::from("x"), dummy())],
            vec![],
            Some("x"),
            &[],
        )
        .unwrap();
        assert_eq!(p2.resolve(None).unwrap().name.as_ref(), "x");
    }
}
