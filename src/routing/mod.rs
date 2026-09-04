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
    net::{IpAddr, Ipv6Addr},
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
    IpCidr(Vec<(IpAddr, u8)>),
}

#[derive(Debug)]
struct Rule {
    matcher: Matcher,
    action: Action,
}

#[derive(Debug)]
pub struct RoutingEngine {
    rules: Vec<Rule>,
    default: Action,
}

impl RoutingEngine {
    /// Build from parsed config. `list_file` paths are resolved relative
    /// to nothing special — absolute paths expected (same as certs).
    pub fn from_config(cfg: &RoutingSpec) -> std::io::Result<Self> {
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
                rules.push(Rule { matcher: Matcher::IpCidr(parsed), action });
            }
            if let Some(path) = &r.list_file {
                let set = load_list_file(path)?;
                if !set.is_empty() {
                    rules.push(Rule { matcher: Matcher::DomainSuffix(set), action });
                }
            }
        }
        Ok(Self { rules, default: cfg.default_action().into() })
    }

    /// A pass-through engine: everything → default (used when no
    /// `[routing]` section exists).
    pub fn all(action: Action) -> Self {
        Self { rules: Vec::new(), default: action }
    }

    pub fn decide(&self, target: Target<'_>) -> Action {
        match target {
            Target::Domain(d) => self.decide_domain(d),
            Target::Ip(ip) => self.decide_ip(ip),
        }
    }

    fn decide_domain(&self, domain: &str) -> Action {
        let d = normalize(domain);
        for rule in &self.rules {
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
                Matcher::IpCidr(_) => {} // domains match only domain rules
            }
        }
        self.default
    }

    fn decide_ip(&self, ip: IpAddr) -> Action {
        for rule in &self.rules {
            if let Matcher::IpCidr(cidrs) = &rule.matcher {
                if cidr_contains(cidrs, ip) {
                    return rule.action;
                }
            }
        }
        self.default
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

fn cidr_contains(cidrs: &[(IpAddr, u8)], ip: IpAddr) -> bool {
    cidrs.iter().any(|&(net, len)| match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let l = len as u32;
            let mask_hi = if l == 0 { 0 } else if l >= 64 { u64::MAX } else { u64::MAX << (64 - l) };
            let mask_lo = if l <= 64 { 0 } else { u64::MAX << (128 - l) };
            let (nh, nl) = split_v6(n);
            let (ih, il) = split_v6(i);
            (nh & mask_hi) == (ih & mask_hi) && (nl & mask_lo) == (il & mask_lo)
        }
        _ => false, // family mismatch is not a match
    })
}

fn split_v6(ip: Ipv6Addr) -> (u64, u64) {
    let o = ip.octets();
    let hi = u64::from_be_bytes(o[0..8].try_into().unwrap());
    let lo = u64::from_be_bytes(o[8..16].try_into().unwrap());
    (hi, lo)
}

/// Load a suffix list file (Loyalsoldier format).
fn load_list_file(path: &str) -> std::io::Result<HashSet<String>> {
    let text = std::fs::read_to_string(path)?;
    let mut set = HashSet::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // Accept `domain:example.com`, `full:example.com` (treated as
        // exact-ish suffix — exactness handled by match length; suffix
        // of an apex covers subdomains which is the common intent),
        // and bare `example.com`.
        let dom = line
            .strip_prefix("domain:")
            .or_else(|| line.strip_prefix("full:"))
            .unwrap_or(line);
        if !dom.is_empty() && dom.contains('.') {
            set.insert(normalize(dom));
        } else if dom == "localhost" {
            set.insert("localhost".to_string());
        }
    }
    Ok(set)
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
            rule: rules,
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
        let cidrs = vec![
            parse_cidr("192.168.0.0/16").unwrap(),
            parse_cidr("10.0.0.5").unwrap(),
            parse_cidr("fc00::/7").unwrap(),
        ];
        assert!(cidr_contains(&cidrs, "192.168.1.100".parse::<IpAddr>().unwrap()));
        assert!(cidr_contains(&cidrs, "10.0.0.5".parse::<IpAddr>().unwrap()));
        assert!(!cidr_contains(&cidrs, "10.0.0.6".parse::<IpAddr>().unwrap()));
        assert!(cidr_contains(&cidrs, "fd12::1".parse::<IpAddr>().unwrap()));
        assert!(!cidr_contains(&cidrs, "2001:db8::1".parse::<IpAddr>().unwrap()));
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
        let set = load_list_file(path.to_str().unwrap()).unwrap();
        assert!(set.contains("baidu.com"));
        assert!(set.contains("taobao.com"));
        assert!(set.contains("exact.example"));
        assert!(set.contains("qq.com"));
        assert_eq!(set.len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
