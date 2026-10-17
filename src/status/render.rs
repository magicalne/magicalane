//! HTML rendering for the status page. Pure functions: everything here
//! takes plain snapshot values and returns strings — no locks, no
//! async, no I/O — so the diagnostic hints are unit-testable.

use std::time::{Duration, SystemTime};

/// Which side of the probe failed (diagnostic classification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailStage {
    /// Transport connect/handshake failed — for UDP transports this is
    /// the "UDP path is dead" signal.
    Handshake,
    /// Handshake ok, but the request through the tunnel failed —
    /// server is reachable, relay/auth/origin is not.
    Relay,
}

/// One row of the transport-probe matrix (snapshot copy).
#[derive(Debug, Clone)]
pub struct TargetRow {
    pub name: String,
    pub server: String,
    pub transport: String,
    pub endpoint: String,
    pub alive: bool,
    /// Never probed yet (staggered start): show "pending" instead of
    /// a fake "alive".
    pub pending: bool,
    pub consecutive_failures: u32,
    pub latency: Option<Duration>,
    pub handshake: Option<Duration>,
    pub exit_ip: Option<String>,
    pub last_ok: Option<SystemTime>,
    pub last_error: Option<String>,
    pub fail_stage: Option<FailStage>,
    /// Connector build failed/timed out — the row cannot probe at all
    /// (`✕ no connector` + this message).
    pub build_err: Option<String>,
}

/// One routing-pool server row.
#[derive(Debug, Clone)]
pub struct PoolRow {
    pub name: String,
    pub protocol: String,
    pub alive: bool,
    pub latency: Option<Duration>,
    pub consecutive_failures: u32,
    pub last_ok: Option<SystemTime>,
}

/// Diagnostic hint for one server group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hint {
    /// All transports down.
    LinkDown,
    /// UDP (quic/kcp) down, TCP fine.
    UdpThrottled,
    /// TCP down, UDP fine.
    TcpBlocked,
}

impl Hint {
    pub fn text(&self) -> &'static str {
        match self {
            Hint::LinkDown => "all transports down — server or path down",
            Hint::UdpThrottled => "UDP down, TCP fine — UDP likely throttled/QoS",
            Hint::TcpBlocked => "TCP down, UDP fine — TCP port blocked?",
        }
    }
}

/// `quic`/`kcp` ride UDP; `tcp` does not.
pub fn is_udp_transport(transport: &str) -> bool {
    transport.eq_ignore_ascii_case("quic") || transport.eq_ignore_ascii_case("kcp")
}

/// Classify a server group from its rows' liveness. `None` = healthy
/// (nothing to hint) or nothing to compare. Rows that merely haven't
/// been probed yet (starting) carry no signal and are excluded —
/// build-failed rows are NOT (they are down).
pub fn group_hint(rows: &[&TargetRow]) -> Option<Hint> {
    let rows: Vec<_> = rows
        .iter()
        .filter(|r| !(r.pending && r.build_err.is_none()))
        .collect();
    if rows.is_empty() || rows.iter().all(|r| r.alive) {
        return None;
    }
    let udp: Vec<_> = rows
        .iter()
        .filter(|r| is_udp_transport(&r.transport))
        .collect();
    let tcp: Vec<_> = rows
        .iter()
        .filter(|r| !is_udp_transport(&r.transport))
        .collect();
    if rows.iter().all(|r| !r.alive) {
        Some(Hint::LinkDown)
    } else if !tcp.is_empty()
        && tcp.iter().all(|r| r.alive)
        && !udp.is_empty()
        && udp.iter().all(|r| !r.alive)
    {
        Some(Hint::UdpThrottled)
    } else if !udp.is_empty()
        && udp.iter().all(|r| r.alive)
        && !tcp.is_empty()
        && tcp.iter().all(|r| !r.alive)
    {
        Some(Hint::TcpBlocked)
    } else {
        None
    }
}

/// `3s` / `4m05s` / `2h13m` — compact ages for live views.
pub fn fmt_age(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    }
}

/// `Option<SystemTime>` → "12s ago" / "—" (never future).
pub fn fmt_last_ok(t: Option<SystemTime>, now: SystemTime) -> String {
    match t.and_then(|t| now.duration_since(t).ok()) {
        Some(d) => format!("{} ago", fmt_age(d)),
        None => "—".into(),
    }
}

pub fn fmt_ms(d: Option<Duration>) -> String {
    match d {
        Some(d) => format!("{} ms", d.as_millis()),
        None => "—".into(),
    }
}

/// Minimal HTML escaping for config-controlled strings.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// One group of transport rows with its (optional) hint, in the order
/// groups should render.
#[derive(Clone)]
pub struct GroupView {
    pub server: String,
    pub rows: Vec<TargetRow>,
    pub hint: Option<Hint>,
}

/// Everything the page shows (snapshot copies; safe to hold unlocked).
pub struct Snapshot<'a> {
    pub version: &'a str,
    pub pid: u32,
    pub config_path: &'a str,
    pub uptime: Duration,
    pub listeners: &'a [String],
    pub pool_default: &'a str,
    pub pool_rows: &'a [PoolRow],
    pub groups: &'a [(String, Option<String>)],
    pub groups_hint: Option<&'static str>,
    pub target_groups: Vec<GroupView>,
    pub events: &'a [String],
    pub refresh: u64,
    pub generated_at: SystemTime,
}

/// Render the full page (inline styles, no external assets).
pub fn render_page(s: &Snapshot<'_>) -> String {
    let mut h = String::with_capacity(16 * 1024);
    h.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    h.push_str(&format!(
        "<meta http-equiv=\"refresh\" content=\"{}\">\n",
        s.refresh
    ));
    h.push_str("<title>magicalane status</title>\n<style>\n");
    h.push_str(":root{color-scheme:dark;background:#101418;color:#cfd8dc;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:1rem}\n");
    h.push_str("h1{font-size:1.1rem;margin:0 0 .2rem}h2{font-size:.95rem;margin:1.4rem 0 .4rem;color:#80cbc4;border-bottom:1px solid #263238;padding-bottom:.2rem}\n");
    h.push_str("table{border-collapse:collapse;margin:.3rem 0;width:100%}td,th{padding:.25rem .6rem;text-align:left;border-bottom:1px solid #1e272e;white-space:nowrap}\n");
    h.push_str("th{color:#78909c;font-weight:normal}.ok{color:#69f0ae}.dead{color:#ff5252}.dim{color:#78909c}.hint{color:#ffab40}.warn{color:#ffd54f}\n");
    h.push_str("pre{background:#0b0f13;padding:.6rem .8rem;border-radius:4px;overflow-x:auto;font-size:.85rem}\n");
    h.push_str(".sub{color:#78909c;font-size:.85rem}\n");
    h.push_str("</style></head><body>\n");
    h.push_str("<h1>magicalane status</h1>\n");
    h.push_str(&format!(
        "<div class=\"sub\">v{} &middot; pid {} &middot; up {} &middot; config <code>{}</code> &middot; generated {}</div>\n",
        esc(s.version),
        s.pid,
        fmt_age(s.uptime),
        esc(s.config_path),
        humantime(s.generated_at),
    ));

    // -- client instance ------------------------------------------------
    h.push_str("<h2>client instance</h2>\n<table>\n");
    for l in s.listeners {
        h.push_str(&format!(
            "<tr><td>{}</td><td class=\"dim\">listening</td></tr>\n",
            esc(l)
        ));
    }
    h.push_str("</table>\n");

    // -- routing pool ---------------------------------------------------
    h.push_str("<h2>routing pool</h2>\n");
    h.push_str(&format!(
        "<div class=\"sub\">default target: <code>{}</code></div>\n",
        esc(s.pool_default)
    ));
    h.push_str("<table><tr><th>server</th><th>transport</th><th>state</th><th>probe latency</th><th>last ok</th><th>consec. failures</th></tr>\n");
    for r in s.pool_rows {
        let (dot, cls) = if r.alive {
            ("●", "ok")
        } else {
            ("✕", "dead")
        };
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"{cls}\">{dot} {}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            esc(&r.name),
            esc(&r.protocol),
            if r.alive { "alive" } else { "DEAD" },
            fmt_ms(r.latency),
            fmt_last_ok(r.last_ok, s.generated_at),
            r.consecutive_failures
        ));
    }
    h.push_str("</table>\n");
    if !s.groups.is_empty() {
        h.push_str("<table><tr><th>group</th><th>strategy picks</th></tr>\n");
        for (name, chosen) in s.groups {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>\n",
                esc(name),
                match chosen {
                    Some(c) => esc(c),
                    None => "<span class=\"dim\">—</span>".into(),
                }
            ));
        }
        h.push_str("</table>\n");
    }
    if let Some(hint) = s.groups_hint {
        h.push_str(&format!("<div class=\"hint\">↳ {}</div>\n", esc(hint)));
    }

    // -- transport probe matrix ------------------------------------------
    if !s.target_groups.is_empty() {
        h.push_str("<h2>tunnel servers &times; transports</h2>\n");
        for g in &s.target_groups {
            h.push_str(&format!("<div><b>{}</b></div>\n", esc(&g.server)));
            h.push_str("<table><tr><th>target</th><th>transport</th><th>endpoint</th><th>state</th><th>handshake</th><th>total</th><th>exit ip</th><th>last ok</th><th>last error</th></tr>\n");
            for r in &g.rows {
                let (dot, cls, label) = if let Some(berr) = &r.build_err {
                    let _ = berr;
                    ("✕", "dead", "no connector".to_string())
                } else if r.pending {
                    ("…", "dim", "starting".to_string())
                } else if r.alive && r.consecutive_failures == 0 {
                    ("●", "ok", "alive".to_string())
                } else if r.alive {
                    // Failing but under the DEAD threshold — flaky path.
                    ("⚠", "warn", format!("failing ({})", r.consecutive_failures))
                } else {
                    (
                        "✕",
                        "dead",
                        format!("DEAD ({} fails)", r.consecutive_failures),
                    )
                };
                let err = match (&r.build_err, &r.last_error, &r.fail_stage) {
                    (Some(b), _, _) => b.clone(),
                    (None, Some(e), Some(FailStage::Handshake)) => format!("hs: {e}"),
                    (None, Some(e), Some(FailStage::Relay)) => format!("relay: {e}"),
                    (None, Some(e), None) => e.clone(),
                    _ => String::new(),
                };
                h.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td class=\"dim\">{}</td><td class=\"{cls}\">{dot} {label}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"dim\">{}</td></tr>\n",
                    esc(&r.name),
                    esc(&r.transport),
                    esc(&r.endpoint),
                    fmt_ms(r.handshake),
                    fmt_ms(r.latency),
                    r.exit_ip.as_deref().map(esc).unwrap_or_else(|| "—".into()),
                    fmt_last_ok(r.last_ok, s.generated_at),
                    esc(&err)
                ));
            }
            h.push_str("</table>\n");
            if let Some(hint) = &g.hint {
                h.push_str(&format!(
                    "<div class=\"hint\">↳ {}</div>\n",
                    esc(hint.text())
                ));
            }
        }
    }

    // -- events ----------------------------------------------------------
    if !s.events.is_empty() {
        h.push_str("<h2>recent events</h2>\n<pre>\n");
        for e in s.events.iter().rev() {
            h.push_str(e);
            h.push('\n');
        }
        h.push_str("</pre>\n");
    }

    h.push_str("</body></html>\n");
    h
}

/// Wall-clock formatting without external crates: UTC date-time is
/// genuinely useful on an events ring. (1970 base, civil-from-days.)
pub fn humantime(t: SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days (Howard Hinnant's algorithm)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02} {h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, server: &str, transport: &str, alive: bool) -> TargetRow {
        TargetRow {
            name: name.into(),
            server: server.into(),
            transport: transport.into(),
            endpoint: "10.0.0.1:4433".into(),
            alive,
            build_err: None,
            pending: false,
            consecutive_failures: if alive { 0 } else { 3 },
            latency: Some(Duration::from_millis(120)),
            handshake: Some(Duration::from_millis(80)),
            exit_ip: Some("203.0.113.9".into()),
            last_ok: Some(SystemTime::now()),
            last_error: if alive { None } else { Some("timeout".into()) },
            fail_stage: if alive {
                None
            } else {
                Some(FailStage::Handshake)
            },
        }
    }

    #[test]
    fn hints_classify_udp_vs_tcp_divergence() {
        let kr_q = row("korea-quic", "korea", "quic", false);
        let kr_k = row("korea-kcp", "korea", "kcp", false);
        let kr_t = row("korea-tcp", "korea", "tcp", true);
        assert_eq!(group_hint(&[&kr_q, &kr_t]), Some(Hint::UdpThrottled));
        assert_eq!(group_hint(&[&kr_q, &kr_k, &kr_t]), Some(Hint::UdpThrottled));

        // all down -> link
        let t2 = row("korea-tcp2", "korea", "tcp", false);
        assert_eq!(group_hint(&[&kr_q, &t2]), Some(Hint::LinkDown));

        // all alive -> nothing
        let ok_q = row("korea-quic-ok", "korea", "quic", true);
        assert_eq!(group_hint(&[&ok_q, &kr_t]), None);

        // TCP down, UDP fine
        let ok_k = row("us-kcp", "us", "kcp", true);
        let us_t = row("us-tcp", "us", "tcp", false);
        assert_eq!(group_hint(&[&ok_k, &us_t]), Some(Hint::TcpBlocked));

        // partial: one UDP alive one dead, TCP alive -> no strong claim
        assert_eq!(group_hint(&[&ok_q, &kr_q, &kr_t]), None);
    }

    #[test]
    fn page_renders_rows_and_hints() {
        let rows = vec![
            row("korea-quic", "korea", "quic", false),
            row("korea-tcp", "korea", "tcp", true),
        ];
        let hint = group_hint(&rows.iter().collect::<Vec<_>>());
        let groups = vec![GroupView {
            server: "korea".into(),
            rows: rows.clone(),
            hint,
        }];
        let snap = Snapshot {
            version: "0.1.4-test",
            pid: 42,
            config_path: "/etc/magicalane/client.toml",
            uptime: Duration::from_secs(3725),
            listeners: &["socks5+http :1080 (lan)".into()],
            pool_default: "default",
            pool_rows: &[PoolRow {
                name: "default".into(),
                protocol: "quic".into(),
                alive: true,
                latency: Some(Duration::from_millis(90)),
                consecutive_failures: 0,
                last_ok: Some(SystemTime::now()),
            }],
            groups: &[("auto".to_string(), Some("default".to_string()))],
            groups_hint: None,
            target_groups: groups,
            events: &["[probe] korea-quic is DEAD (hs: timeout)".into()],
            refresh: 5,
            generated_at: SystemTime::now(),
        };
        let html = render_page(&snap);
        assert!(html.contains("korea-quic"));
        assert!(html.contains("korea-tcp"));
        assert!(html.contains(Hint::UdpThrottled.text()));
        assert!(html.contains("routing pool"));
        assert!(html.contains("recent events"));
        assert!(html.contains("auto"));
        assert!(html.contains("1h2m"), "uptime missing");
        // meta refresh present
        assert!(html.contains("http-equiv=\"refresh\" content=\"5\""));
    }

    #[test]
    fn escapes_hostile_config_strings() {
        let mut r = row("x", "s", "tcp", true);
        r.name = "<script>alert(1)</script>".into();
        let html = render_page(&Snapshot {
            version: "t",
            pid: 1,
            config_path: "c",
            uptime: Duration::from_secs(1),
            listeners: &[],
            pool_default: "default",
            pool_rows: &[],
            groups: &[],
            groups_hint: None,
            target_groups: vec![GroupView {
                server: "s".into(),
                rows: std::slice::from_ref(&r).to_vec(),
                hint: None,
            }],
            events: &[],
            refresh: 5,
            generated_at: SystemTime::now(),
        });
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn build_failed_row_renders_and_counts_down_for_hints() {
        let mut q = row("korea-quic", "korea", "quic", false);
        // connector never landed: never probed AND build failed
        q.pending = true;
        q.build_err = Some("build: timeout".into());
        q.last_error = None;
        q.fail_stage = None;
        let t = row("korea-tcp", "korea", "tcp", true);

        // hint: UDP transport down (build failed) + TCP fine -> throttled
        let hint = group_hint(&[&q, &t]);
        assert_eq!(hint, Some(Hint::UdpThrottled));
        let html = render_page(&Snapshot {
            version: "t",
            pid: 1,
            config_path: "c",
            uptime: Duration::from_secs(1),
            listeners: &[],
            pool_default: "default",
            pool_rows: &[],
            groups: &[],
            groups_hint: None,
            target_groups: vec![GroupView {
                server: "korea".into(),
                rows: vec![q, t.clone()],
                hint,
            }],
            events: &[],
            refresh: 5,
            generated_at: SystemTime::now(),
        });
        assert!(html.contains("no connector"));
        assert!(html.contains("build: timeout"));
        assert!(html.contains(Hint::UdpThrottled.text()));
        // a starting row (pending, no build error) stays excluded
        let mut st = row("korea-kcp", "korea", "kcp", true);
        st.pending = true;
        st.build_err = None;
        assert_eq!(group_hint(&[&st, &t]), None);
    }

    #[test]
    fn ages_and_times_format() {
        assert_eq!(fmt_age(Duration::from_secs(3)), "3s");
        assert_eq!(fmt_age(Duration::from_secs(65)), "1m05s");
        assert_eq!(fmt_age(Duration::from_secs(3725)), "1h2m");
        assert_eq!(fmt_last_ok(None, SystemTime::now()), "—");
        // known epoch -> fixed rendering (checked against date -u)
        let t = std::time::UNIX_EPOCH + Duration::from_secs(1_728_658_400);
        assert_eq!(humantime(t), "2024-10-11 14:53:20Z");
        assert_eq!(humantime(std::time::UNIX_EPOCH), "1970-01-01 00:00:00Z");
    }
}
