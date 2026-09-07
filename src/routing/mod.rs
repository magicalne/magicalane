//! Routing engine: first-match rule evaluation at connection time.
//!
//! Every intercepted connection (TCP via tproxy, UDP via the relay)
//! asks the engine where to go:
//!
//!   `Proxy`  → through the tunnel pool (server-side resolution);
//!              a named rule target (`action = "work"`) pins the
//!              connection to that server or proxy group
//!   `Direct` → DirectConnector (local resolution + direct connect)
//!
//! Rules are evaluated top to bottom; first match wins; `default`
//! catches the rest (also nameable: `default = "auto"` selects a
//! group for unmatched traffic). Rule types: `domain_suffix`
//! (label-aligned wildcard; a leading `*.` is accepted and stripped),
//! `domain` (exact), `domain_keyword` (substring), `ip_cidr` (v4+v6),
//! `list_file` (suffix list loaded at startup, Loyalsoldier/v2ray
//! format: one domain per line, `#` comments, optional `domain:`
//! prefix treated as suffix).

use std::{
    collections::HashSet,
    net::IpAddr,
};

use std::sync::Arc;

use crate::config::RoutingSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Proxy,
    Direct,
}

/// Full routing outcome: where AND through which tunnel target.
/// `server` names a server or proxy group (None = pool default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub server: Option<Arc<str>>,
}

impl Decision {
    pub fn direct() -> Self {
        Self { action: Action::Direct, server: None }
    }
    pub fn proxy() -> Self {
        Self { action: Action::Proxy, server: None }
    }
}

/// Parse an action string: "direct", "proxy", or a server/group name
/// (any other word — treated as a named tunnel target).
fn parse_action(name: &str) -> Decision {
    match name {
        "direct" | "" => Decision::direct(),
        "proxy" => Decision::proxy(),
        other => Decision {
            action: Action::Proxy,
            server: Some(Arc::from(other)),
        },
    }
}

/// What a connection is heading toward.
#[derive(Debug, Clone)]
pub enum Target<'a> {
    Domain(&'a str),
    Ip(IpAddr),
}

#[derive(Debug)]
enum Matcher {
    /// Label-aligned suffix: `qq.com` matches `weixin.qq.com`, not `notqq.com`.
    DomainSuffix(HashSet<String>),
    /// Exact match (case-insensitive).
    DomainExact(HashSet<String>),
    /// Substring match (case-insensitive).
    DomainKeyword(HashSet<String>),
    /// CIDR ranges for real-IP connections.
    IpCidr(IpRanges),
    /// Country-code CIDR set (`<geoip_dir>/<cc>.txt`).
    GeoIp(IpRanges),
    /// Remote provider list (hot-swappable): domains + CIDRs.
    Provider {
        name: String,
        set: std::sync::Arc<std::sync::RwLock<LoadedList>>,
    },
}

/// Sorted, merged u128 intervals covering both address families
/// (v4 zero-extended; v4 and v6 ranges never collide). Binary search.
#[derive(Debug, Default)]
pub struct IpRanges {
    /// (start, end) inclusive, sorted, non-overlapping.
    spans: Vec<(u128, u128)>,
}

impl IpRanges {
    pub fn from_cidrs(cidrs: &[(IpAddr, u8)]) -> Self {
        let mut spans: Vec<(u128, u128)> = cidrs
            .iter()
            .map(|&(addr, len)| {
                let bits = ip_to_u128(addr); // v4 zero-extends into low 32 bits
                let mask = family_mask(addr, len);
                // host part must stay inside the family width: inverting
                // a zero-extended v4 mask would set every high bit and
                // make the span cover all larger addresses.
                let family = family_all_ones(addr);
                (bits & mask, bits | (!mask & family))
            })
            .collect();
        spans.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(spans.len());
        for (start, end) in spans {
            match merged.last_mut() {
                Some((_, last_end)) if start <= *last_end + 1 => {
                    *last_end = (*last_end).max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        Self { spans: merged }
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let bits = ip_to_u128(ip);
        match self.spans.partition_point(|&(start, _)| start <= bits) {
            0 => false,
            i => {
                let (start, end) = self.spans[i - 1];
                bits >= start && bits <= end
            }
        }
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// Family-aware prefix mask: v4 lengths apply to the low 32 bits
/// (zero-extended), v6 lengths to all 128.
fn family_all_ones(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(_) => 0xFFFF_FFFF,
        IpAddr::V6(_) => u128::MAX,
    }
}

fn family_mask(addr: IpAddr, len: u8) -> u128 {
    match addr {
        IpAddr::V4(_) => {
            if len >= 32 {
                u128::MAX
            } else if len == 0 {
                0
            } else {
                ((u32::MAX << (32 - len)) as u128) & 0xFFFF_FFFF
            }
        }
        IpAddr::V6(_) => {
            if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            }
        }
    }
}

#[derive(Debug)]
struct Rule {
    matcher: Matcher,
    outcome: std::sync::Arc<Decision>,
}

#[derive(Debug)]
pub struct RoutingEngine {
    inner: std::sync::Arc<std::sync::RwLock<Vec<Rule>>>,
    default: std::sync::Arc<std::sync::RwLock<Decision>>,
    /// Live provider sets (name -> swappable content).
    providers: std::sync::Arc<
        std::sync::RwLock<std::collections::HashMap<String, std::sync::Arc<std::sync::RwLock<LoadedList>>>>,
    >,
}

impl RoutingEngine {
    /// Build from parsed config. `list_file` paths are resolved relative
    /// to nothing special — absolute paths expected (same as certs).
    pub fn from_config(cfg: &RoutingSpec) -> std::io::Result<Self> {
        let engine = Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
            default: std::sync::Arc::new(std::sync::RwLock::new(Decision::proxy())),
            providers: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        };
        engine.reload(cfg)?;
        Ok(engine)
    }

    /// Rebuild all rules from a (possibly new) config. Provider sets
    /// keep their live content when the provider name already exists.
    pub fn reload(&self, cfg: &RoutingSpec) -> std::io::Result<()> {
        let mut rules = Vec::new();
        for r in &cfg.rule {
            let outcome = std::sync::Arc::new(parse_action(r.action.as_deref().unwrap_or("direct")));
            if let Some(suffixes) = &r.domain_suffix {
                rules.push(Rule {
                    matcher: Matcher::DomainSuffix(suffixes.iter().map(|s| normalize(s)).collect()),
                    outcome: outcome.clone(),
                });
            }
            if let Some(exact) = &r.domain {
                rules.push(Rule {
                    matcher: Matcher::DomainExact(exact.iter().map(|s| normalize(s)).collect()),
                    outcome: outcome.clone(),
                });
            }
            if let Some(keywords) = &r.domain_keyword {
                rules.push(Rule {
                    matcher: Matcher::DomainKeyword(keywords.iter().map(|s| normalize(s)).collect()),
                    outcome: outcome.clone(),
                });
            }
            if let Some(cidrs) = &r.ip_cidr {
                let mut parsed = Vec::new();
                for c in cidrs {
                    parsed.push(parse_cidr(c)?);
                }
                rules.push(Rule { matcher: Matcher::IpCidr(IpRanges::from_cidrs(&parsed)), outcome: outcome.clone() });
            }
            if let Some(cc) = &r.geoip {
                let dir = cfg
                    .geoip_dir
                    .as_deref()
                    .unwrap_or("/etc/magicalane/geoip");
                let path = format!("{dir}/{}.txt", cc.to_ascii_lowercase());
                let loaded = load_list_file(&path)?;
                if loaded.cidrs.is_empty() {
                    log::warn!(
                        "routing: geoip {cc:?} has no ranges ({path} missing or empty) - rule inert"
                    );
                }
                rules.push(Rule {
                    matcher: Matcher::GeoIp(IpRanges::from_cidrs(&loaded.cidrs)),
                    outcome: outcome.clone(),
                });
            }
            if let Some(path) = &r.list_file {
                let loaded = load_list_file(path)?;
                if !loaded.domains.is_empty() {
                    rules.push(Rule { matcher: Matcher::DomainSuffix(loaded.domains), outcome: outcome.clone() });
                }
                if !loaded.cidrs.is_empty() {
                    rules.push(Rule { matcher: Matcher::IpCidr(IpRanges::from_cidrs(&loaded.cidrs)), outcome: outcome.clone() });
                }
            }
        }
        // Providers: rule per provider; content fetched asynchronously
        // (starts empty, fills in once the first fetch lands).
        for p in &cfg.provider {
            let set = {
                let mut provs = self.providers.write().unwrap();
                provs.entry(p.name.clone())
                    .or_insert_with(|| std::sync::Arc::new(std::sync::RwLock::new(LoadedList::default())))
                    .clone()
            };
            rules.push(Rule {
                matcher: Matcher::Provider { name: p.name.clone(), set },
                outcome: std::sync::Arc::new(parse_action(p.action.as_deref().unwrap_or("direct"))),
            });
        }
        *self.inner.write().unwrap() = rules;
        *self.default.write().unwrap() =
            parse_action(cfg.default.as_deref().unwrap_or("proxy"));
        Ok(())
    }

    /// Swap a provider's content atomically (hot rule update).
    pub fn update_provider(&self, name: &str, text: &str) {
        let parsed = parse_list_content(text);
        let provs = self.providers.read().unwrap();
        if let Some(set) = provs.get(name) {
            let mut guard = set.write().unwrap();
            *guard = parsed;
            log::info!(
                "routing: provider {name:?} updated ({} domains, {} cidrs)",
                guard.domains.len(),
                guard.cidrs.len()
            );
        }
    }

    /// A pass-through engine: everything → default (used when no
    /// `[routing]` section exists).
    pub fn all(action: Action) -> Self {
        let decision = match action {
            Action::Proxy => Decision::proxy(),
            Action::Direct => Decision::direct(),
        };
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
            default: std::sync::Arc::new(std::sync::RwLock::new(decision)),
            providers: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    pub fn decide(&self, target: Target<'_>) -> Decision {
        match target {
            Target::Domain(d) => self.decide_domain(d),
            Target::Ip(ip) => self.decide_ip(ip),
        }
    }

    fn decide_domain(&self, domain: &str) -> Decision {
        let d = normalize(domain);
        let rules = self.inner.read().unwrap();
        for rule in rules.iter() {
            match &rule.matcher {
                Matcher::DomainSuffix(set) => {
                    if suffix_match(&d, set) {
                        return (*rule.outcome).clone();
                    }
                }
                Matcher::DomainExact(set) => {
                    if set.contains(&d) {
                        return (*rule.outcome).clone();
                    }
                }
                Matcher::DomainKeyword(set) => {
                    if set.iter().any(|k| d.contains(k.as_str())) {
                        return (*rule.outcome).clone();
                    }
                }
                Matcher::Provider { name, set } => {
                    let guard = set.read().unwrap();
                    if !guard.domains.is_empty() && suffix_match(&d, &guard.domains) {
                        log::debug!("routing: matched provider {name} for {d}");
                        return (*rule.outcome).clone();
                    }
                }
                Matcher::IpCidr(_) | Matcher::GeoIp(_) => {} // IP-only matchers
            }
        }
        self.default.read().unwrap().clone()
    }

    fn decide_ip(&self, ip: IpAddr) -> Decision {
        let rules = self.inner.read().unwrap();
        for rule in rules.iter() {
            match &rule.matcher {
                Matcher::IpCidr(r) | Matcher::GeoIp(r) if r.contains(ip) => {
                            return (*rule.outcome).clone();
                        }
                Matcher::Provider { name, set } => {
                    let guard = set.read().unwrap();
                    if !guard.cidrs.is_empty() {
                        // provider CIDRs are compiled on the fly per
                        // lookup only if present (usually domain lists)
                        let ranges = IpRanges::from_cidrs(&guard.cidrs);
                        if ranges.contains(ip) {
                            log::debug!("routing: matched provider {name} for {ip}");
                            return (*rule.outcome).clone();
                        }
                    }
                }
                _ => {}
            }
        }
        self.default.read().unwrap().clone()
    }
}

/// Normalize a domain-ish config token: lowercase, strip a leading
/// dot, and accept wildcard syntax (`*.example.com` == `example.com`
/// suffix semantics; a bare `*` is dropped by callers who need it).
fn normalize(s: &str) -> String {
    let s = s.trim_start_matches('.').to_ascii_lowercase();
    s.strip_prefix("*.").unwrap_or(&s).to_string()
}

/// Label-aligned suffix match against a set.
fn suffix_match(domain: &str, set: &HashSet<String>) -> bool {
    if set.contains(domain) {
        return true;
    }
    let mut rest = domain;
    while let Some(pos) = rest.find('.') {
        rest = &rest[pos + 1..];
        if set.contains(rest) {
            return true;
        }
    }
    false
}

/// Parse `a.b.c/len` or bare `a.b.c` (host) into (addr, prefix).
fn parse_cidr(s: &str) -> std::io::Result<(IpAddr, u8)> {
    let (addr_str, len_str) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| std::io::Error::other(format!("bad cidr address: {s}")))?;
    let max: u8 = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let len: u8 = match len_str {
        Some(l) => l
            .parse()
            .map_err(|_| std::io::Error::other(format!("bad cidr length: {s}")))?,
        None => max,
    };
    if len > max {
        return Err(std::io::Error::other(format!("cidr length too big: {s}")));
    }
    Ok((addr, len))
}

/// A loaded list file: domain suffixes and/or CIDR ranges, auto-detected
/// per line (lines with `/` parse as CIDRs, everything else as domains).
#[derive(Debug, Default)]
pub struct LoadedList {
    domains: HashSet<String>,
    cidrs: Vec<(IpAddr, u8)>,
}

fn load_list_file(path: &str) -> std::io::Result<LoadedList> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_list_content(&text))
}

/// Parse list content: domains and/or CIDRs, auto-detected per line.
pub fn parse_list_content(text: &str) -> LoadedList {
    let mut out = LoadedList::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // CIDR line: contains '/' (bare IPs also accepted via /32,//128).
        if line.contains('/') {
            match parse_cidr(line) {
                Ok(cidr) => out.cidrs.push(cidr),
                Err(e) => log::warn!("routing: skipping bad cidr {line:?}: {e}"),
            }
            continue;
        }
        // Accept `domain:example.com`, `full:example.com` (treated as
        // suffix — apex suffix covers subdomains, the common intent),
        // and bare `example.com`.
        let dom = line
            .strip_prefix("domain:")
            .or_else(|| line.strip_prefix("full:"))
            .unwrap_or(line);
        if !dom.is_empty() {
            out.domains.insert(normalize(dom));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RoutingRule, RoutingSpec};

    fn spec(rules: Vec<RoutingRule>, default: Option<&str>) -> RoutingSpec {
        RoutingSpec {
            default: default.map(|s| s.to_string()),
            aaaa: None,
            direct_dns: None,
            server_ip: None,
            geoip_dir: None,
            fakeip_filter: None,
            fakeip_cache: None,
            rule: rules,
            provider: Vec::new(),
        }
    }

    fn proxy() -> Decision {
        Decision::proxy()
    }
    fn direct() -> Decision {
        Decision::direct()
    }

    #[test]
    fn suffix_match_label_aligned() {
        let mut set = HashSet::new();
        set.insert("qq.com".to_string());
        assert!(suffix_match("qq.com", &set));
        assert!(suffix_match("weixin.qq.com", &set));
        assert!(!suffix_match("notqq.com", &set));
        assert!(!suffix_match("qq.com.evil.io", &set));
    }

    #[test]
    fn cidr_v4_and_v6() {
        let ranges = IpRanges::from_cidrs(&[
            parse_cidr("192.168.0.0/16").unwrap(),
            parse_cidr("10.0.0.5").unwrap(),
            parse_cidr("fc00::/7").unwrap(),
        ]);
        assert!(ranges.contains("192.168.1.100".parse::<IpAddr>().unwrap()));
        assert!(ranges.contains("10.0.0.5".parse::<IpAddr>().unwrap()));
        assert!(!ranges.contains("10.0.0.6".parse::<IpAddr>().unwrap()));
        assert!(ranges.contains("fd12::1".parse::<IpAddr>().unwrap()));
        assert!(!ranges.contains("2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn mixed_list_file_domains_and_cidrs() {
        let dir = std::env::temp_dir().join("mgl-routing-mixed");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cn.txt");
        std::fs::write(
            &path,
            "# mixed china list\nbaidu.com\n1.0.1.0/24\n1.0.2.0/23\nnot a cidr /line\nqq.com\n240e:0:0::/20\n",
        )
        .unwrap();
        let loaded = load_list_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.domains.len(), 2);
        assert!(loaded.domains.contains("baidu.com"));
        let ranges = IpRanges::from_cidrs(&loaded.cidrs);
        assert_eq!(loaded.cidrs.len(), 3, "bad line skipped");
        assert!(ranges.contains("1.0.1.53".parse::<IpAddr>().unwrap()));
        assert!(ranges.contains("1.0.3.99".parse::<IpAddr>().unwrap())); // /23 merge neighbor
        assert!(ranges.contains("240e:1::1".parse::<IpAddr>().unwrap()));
        assert!(!ranges.contains("240f::1".parse::<IpAddr>().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real-world snapshot from gaoyifan/china-operator-ip (the ranges
    /// covering AliDNS/114DNS/Baidu/ChinaTelecom/Unicom + their v6
    /// allocations). Asserts the geoip pipeline against REAL China
    /// allocations, not synthetic ranges.
    #[test]
    fn geoip_real_china_snapshot() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/env/fixtures/china-snapshot.txt"
        );
        let loaded = load_list_file(path).expect("snapshot fixture");
        assert!(loaded.domains.is_empty(), "pure CIDR file");
        let ranges = IpRanges::from_cidrs(&loaded.cidrs);
        assert!(ranges.len() >= 9);

        // Known China addresses (must classify as CN):
        for cn in [
            "223.5.5.5",     // AliDNS
            "114.114.114.114", // 114DNS (Jiangsu)
            "39.156.69.79",  // baidu.com
            "180.76.76.76",  // Baidu DNS
            "119.29.29.29",  // DNSPod (Tencent)
            "202.96.209.133", // Shanghai Telecom
            "240e:1::1",     // China Telecom v6
            "2408:8000::1",  // China Unicom v6
            "2001:250::1",   // CERNET
        ] {
            assert!(
                ranges.contains(cn.parse::<IpAddr>().unwrap()),
                "{cn} should be in the real China snapshot"
            );
        }
        // Known non-China (must not):
        for not_cn in [
            "8.8.8.8",
            "1.1.1.1",
            "104.244.42.1", // twitter
            "2606:4700::1", // cloudflare v6
            "2a00:1450::1", // google v6
        ] {
            assert!(
                !ranges.contains(not_cn.parse::<IpAddr>().unwrap()),
                "{not_cn} must NOT be in the China snapshot"
            );
        }
    }

    #[test]
    fn adjacent_spans_merge() {
        // 10.0.0.0/24 + 10.0.1.0/24 are contiguous -> one span
        let ranges = IpRanges::from_cidrs(&[
            parse_cidr("10.0.1.0/24").unwrap(),
            parse_cidr("10.0.0.0/24").unwrap(),
        ]);
        assert_eq!(ranges.len(), 1);
        assert!(ranges.contains("10.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(ranges.contains("10.0.1.255".parse::<IpAddr>().unwrap()));
        assert!(!ranges.contains("10.0.2.0".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn first_match_wins_with_default() {
        let r1 = RoutingRule {
            domain_suffix: Some(vec!["cn".into(), "baidu.com".into()]),
            action: Some("direct".into()),
            ..Default::default()
        };
        let r2 = RoutingRule {
            domain: Some(vec!["baidu.com".into()]),
            action: Some("proxy".into()),
            ..Default::default()
        };
        let engine = RoutingEngine::from_config(&spec(vec![r1, r2], Some("proxy"))).unwrap();
        assert_eq!(engine.decide(Target::Domain("weixin.qq.com")), proxy()); // default
        assert_eq!(engine.decide(Target::Domain("map.baidu.com")), direct()); // rule 1
        // rule 1 already matched suffix baidu.com -> Direct (first match)
        assert_eq!(engine.decide(Target::Domain("baidu.com")), direct());
        assert_eq!(engine.decide(Target::Domain("twitter.com")), proxy());
        assert_eq!(engine.decide(Target::Ip("8.8.8.8".parse().unwrap())), proxy());
    }

    #[test]
    fn named_target_and_wildcard_syntax() {
        let r1 = RoutingRule {
            // wildcard syntax accepted: "*.corp.example.com" behaves as
            // suffix "corp.example.com" (matches subdomains AND apex)
            domain_suffix: Some(vec!["*.corp.example.com".into()]),
            action: Some("work".into()),
            ..Default::default()
        };
        let r2 = RoutingRule {
            domain_keyword: Some(vec!["mirror".into()]),
            action: Some("mirror-pool".into()),
            ..Default::default()
        };
        let engine = RoutingEngine::from_config(&spec(vec![r1, r2], Some("auto-pool"))).unwrap();
        let d = engine.decide(Target::Domain("git.corp.example.com"));
        assert_eq!(d.action, Action::Proxy);
        assert_eq!(d.server.as_deref(), Some("work"));
        assert_eq!(
            engine.decide(Target::Domain("corp.example.com")).server.as_deref(),
            Some("work")
        );
        let d = engine.decide(Target::Domain("fedora-mirror.example.net"));
        assert_eq!(d.server.as_deref(), Some("mirror-pool"));
        // named default
        let d = engine.decide(Target::Domain("plain.example.org"));
        assert_eq!(d.action, Action::Proxy);
        assert_eq!(d.server.as_deref(), Some("auto-pool"));
    }

    #[test]
    fn ip_cidr_rule_directs_lan() {
        let r = RoutingRule {
            ip_cidr: Some(vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()]),
            action: Some("direct".into()),
            ..Default::default()
        };
        let engine = RoutingEngine::from_config(&spec(vec![r], Some("proxy"))).unwrap();
        assert_eq!(engine.decide(Target::Ip("192.168.5.5".parse().unwrap())), direct());
        assert_eq!(engine.decide(Target::Domain("internal.corp")), proxy());
    }

    #[test]
    fn list_file_loading() {
        let dir = std::env::temp_dir().join("mgl-routing-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("list.txt");
        std::fs::write(
            &path,
            "# comment\nbaidu.com\n domain:taobao.com\nfull:exact.example\n\nqq.com# trailing\n",
        )
        .unwrap();
        let loaded = load_list_file(path.to_str().unwrap()).unwrap();
        assert!(loaded.domains.contains("baidu.com"));
        assert!(loaded.domains.contains("taobao.com"));
        assert!(loaded.domains.contains("exact.example"));
        assert!(loaded.domains.contains("qq.com"));
        assert_eq!(loaded.domains.len(), 4);
        assert!(loaded.cidrs.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
