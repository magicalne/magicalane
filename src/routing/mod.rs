//! Routing engine: first-match rule evaluation at connection time.
//!
//! Every intercepted connection (TCP via tproxy, UDP via the relay)
//! asks the engine where to go:
//!
//!   `Proxy`  → through the tunnel connector (server-side resolution)
//!   `Direct` → DirectConnector (local resolution + direct connect)
//!
//! Rules are evaluated top to bottom; first match wins; `default`
//! catches the rest. Rule types: `domain_suffix` (label-aligned),
//! `domain` (exact), `ip_cidr` (v4+v6), `list_file` (suffix list
//! loaded at startup, Loyalsoldier/v2ray format: one domain per line,
//! `#` comments, optional `domain:` prefix treated as suffix).

use std::{
    collections::HashSet,
    net::IpAddr,
};

use crate::config::{RouteAction as CfgAction, RoutingSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Proxy,
    Direct,
}

impl From<CfgAction> for Action {
    fn from(a: CfgAction) -> Self {
        match a {
            CfgAction::Proxy => Action::Proxy,
            CfgAction::Direct => Action::Direct,
        }
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
    action: Action,
}

#[derive(Debug)]
pub struct RoutingEngine {
    inner: std::sync::Arc<std::sync::RwLock<Vec<Rule>>>,
    default: std::sync::Arc<std::sync::RwLock<Action>>,
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
            default: std::sync::Arc::new(std::sync::RwLock::new(Action::Proxy)),
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
            let action = r.action_or_direct().into();
            if let Some(suffixes) = &r.domain_suffix {
                rules.push(Rule {
                    matcher: Matcher::DomainSuffix(suffixes.iter().map(|s| normalize(s)).collect()),
                    action,
                });
            }
            if let Some(exact) = &r.domain {
                rules.push(Rule {
                    matcher: Matcher::DomainExact(exact.iter().map(|s| normalize(s)).collect()),
                    action,
                });
            }
            if let Some(cidrs) = &r.ip_cidr {
                let mut parsed = Vec::new();
                for c in cidrs {
                    parsed.push(parse_cidr(c)?);
                }
                rules.push(Rule { matcher: Matcher::IpCidr(IpRanges::from_cidrs(&parsed)), action });
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
                    action,
                });
            }
            if let Some(path) = &r.list_file {
                let loaded = load_list_file(path)?;
                if !loaded.domains.is_empty() {
                    rules.push(Rule { matcher: Matcher::DomainSuffix(loaded.domains), action });
                }
                if !loaded.cidrs.is_empty() {
                    rules.push(Rule { matcher: Matcher::IpCidr(IpRanges::from_cidrs(&loaded.cidrs)), action });
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
                action: p.action.unwrap_or(crate::config::RouteAction::Direct).into(),
            });
        }
        *self.inner.write().unwrap() = rules;
        *self.default.write().unwrap() = cfg.default_action().into();
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
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
            default: std::sync::Arc::new(std::sync::RwLock::new(action)),
            providers: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    pub fn decide(&self, target: Target<'_>) -> Action {
        match target {
            Target::Domain(d) => self.decide_domain(d),
            Target::Ip(ip) => self.decide_ip(ip),
        }
    }

    fn decide_domain(&self, domain: &str) -> Action {
        let d = normalize(domain);
        let rules = self.inner.read().unwrap();
        for rule in rules.iter() {
            match &rule.matcher {
                Matcher::DomainSuffix(set) => {
                    if suffix_match(&d, set) {
                        return rule.action;
                    }
                }
                Matcher::DomainExact(set) => {
                    if set.contains(&d) {
                        return rule.action;
                    }
                }
                Matcher::Provider { name, set } => {
                    let guard = set.read().unwrap();
                    if !guard.domains.is_empty() && suffix_match(&d, &guard.domains) {
                        log::debug!("routing: matched provider {name} for {d}");
                        return rule.action;
                    }
                }
                Matcher::IpCidr(_) | Matcher::GeoIp(_) => {} // IP-only matchers
            }
        }
        *self.default.read().unwrap()
    }

    fn decide_ip(&self, ip: IpAddr) -> Action {
        let rules = self.inner.read().unwrap();
        for rule in rules.iter() {
            match &rule.matcher {
                Matcher::IpCidr(r) | Matcher::GeoIp(r) if r.contains(ip) => return rule.action,
                Matcher::Provider { name, set } => {
                    let guard = set.read().unwrap();
                    if !guard.cidrs.is_empty() {
                        // provider CIDRs are compiled on the fly per
                        // lookup only if present (usually domain lists)
                        let ranges = IpRanges::from_cidrs(&guard.cidrs);
                        if ranges.contains(ip) {
                            log::debug!("routing: matched provider {name} for {ip}");
                            return rule.action;
                        }
                    }
                }
                _ => {}
            }
        }
        *self.default.read().unwrap()
    }
}

fn normalize(s: &str) -> String {
    s.trim_start_matches('.').to_ascii_lowercase()
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
    use crate::config::{RouteAction, RoutingRule, RoutingSpec};

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
            action: Some(RouteAction::Direct),
            ..Default::default()
        };
        let r2 = RoutingRule {
            domain: Some(vec!["baidu.com".into()]),
            action: Some(RouteAction::Proxy),
            ..Default::default()
        };
        let engine = RoutingEngine::from_config(&spec(vec![r1, r2], Some("proxy"))).unwrap();
        assert_eq!(engine.decide(Target::Domain("weixin.qq.com")), Action::Proxy); // default
        assert_eq!(engine.decide(Target::Domain("map.baidu.com")), Action::Direct); // rule 1
        // rule 1 already matched suffix baidu.com -> Direct (first match)
        assert_eq!(engine.decide(Target::Domain("baidu.com")), Action::Direct);
        assert_eq!(engine.decide(Target::Domain("twitter.com")), Action::Proxy);
        assert_eq!(engine.decide(Target::Ip("8.8.8.8".parse().unwrap())), Action::Proxy);
    }

    #[test]
    fn ip_cidr_rule_directs_lan() {
        let r = RoutingRule {
            ip_cidr: Some(vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()]),
            action: Some(RouteAction::Direct),
            ..Default::default()
        };
        let engine = RoutingEngine::from_config(&spec(vec![r], Some("proxy"))).unwrap();
        assert_eq!(engine.decide(Target::Ip("192.168.5.5".parse().unwrap())), Action::Direct);
        assert_eq!(engine.decide(Target::Domain("internal.corp")), Action::Proxy);
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
