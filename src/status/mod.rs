//! Live status page: a read-only diagnostics surface for the client.
//!
//! Serves a tiny hand-rolled HTTP responder (no new deps) on a
//! localhost-only listener: instance info, listener inventory, the
//! routing pool's live health, a per-transport probe matrix over
//! `[status.target]` entries (with UDP-vs-TCP divergence hints), and
//! a ring of recent events (probe transitions, exit-IP changes, and
//! INFO+ log lines captured by the fan-out logger).
//!
//! Hard rules: nothing here mutates routing, firewall or process
//! state; probes are one-in-flight-per-target and staggered; the
//! status listener failing must NEVER take the proxy down.

mod render;

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{StatusConfig, StatusTarget, TransparentProxyConfig};
use crate::connector::Connector as _;
use crate::tunnel::{ProxyPool, TunnelConnector};
use render::{FailStage, GroupView, PoolRow, Snapshot, TargetRow};

/// Re-export for main.rs (logger fan-out wiring).
pub use render::{esc, fmt_age, humantime};

/// Failures before a status target is shown DEAD (mirrors pool).
pub const DEAD_THRESHOLD: u32 = crate::tunnel::DEAD_THRESHOLD;

/// Bounded ring of recent events (preformatted lines, newest last).
pub struct EventRing {
    inner: Mutex<VecDeque<String>>,
    cap: usize,
}

impl EventRing {
    pub fn with_cap(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            cap,
        }
    }

    /// Append one event: `[ts] [kind] text`.
    pub fn push(&self, kind: &str, text: impl AsRef<str>) {
        let line = format!(
            "[{}] [{}] {}",
            humantime(SystemTime::now()),
            kind,
            text.as_ref()
        );
        let mut q = self.inner.lock().unwrap();
        if q.len() == self.cap {
            q.pop_front();
        }
        q.push_back(line);
    }

    /// Copy of the last `n` lines (oldest first).
    pub fn tail(&self, n: usize) -> Vec<String> {
        let q = self.inner.lock().unwrap();
        q.iter().rev().take(n).rev().cloned().collect()
    }
}

/// `log` fan-out: records INFO+ lines into the event ring, forwards
/// everything to the real env_logger. Installed by main.rs when the
/// status page is enabled, so failover/reconnect lines land on the
/// page without a journalctl dependency.
pub struct RingLogger {
    pub inner: env_logger::Logger,
    pub ring: Arc<EventRing>,
}

impl log::Log for RingLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        self.inner.enabled(metadata)
    }
    fn log(&self, record: &log::Record<'_>) {
        if record.level() <= log::Level::Info {
            self.ring
                .push("log", format!("{}: {}", record.target(), record.args()));
        }
        self.inner.log(record);
    }
    fn flush(&self) {
        self.inner.flush();
    }
}

/// Static self-description of the client process.
pub struct InstanceInfo {
    pub version: &'static str,
    pub pid: u32,
    pub config_path: String,
    pub listeners: Vec<String>,
}

/// Human listener inventory from the client config.
pub fn describe_listeners(
    socks5_port: u16,
    bind: Option<&str>,
    allow_lan: bool,
    tproxy: &TransparentProxyConfig,
) -> Vec<String> {
    let mut out = Vec::new();
    let scope = if bind.is_some() {
        format!("bind {}", bind.unwrap_or(""))
    } else if allow_lan {
        "lan".into()
    } else {
        "localhost".into()
    };
    out.push(format!("socks5+http :{socks5_port} ({scope})"));
    match tproxy.mode() {
        crate::config::TproxyMode::Off => {}
        crate::config::TproxyMode::Tproxy => {
            out.push(format!(
                "tproxy tcp :{} udp :{}{}",
                tproxy.tcp_port,
                tproxy.udp_port,
                if tproxy.gateway() { " (gateway)" } else { "" }
            ));
            if tproxy.dns_port() != 0 {
                out.push(format!(
                    "dns :{} ({})",
                    tproxy.dns_port(),
                    tproxy.dns_mode()
                ));
            }
        }
        crate::config::TproxyMode::Tun => {
            out.push("tun capture (utun/mgl0)".into());
            if tproxy.dns_port() != 0 {
                out.push(format!(
                    "dns :{} ({})",
                    tproxy.dns_port(),
                    tproxy.dns_mode()
                ));
            }
        }
    }
    out
}

/// Mutable per-target probe results (written by the probe task, read
/// by page renders).
#[derive(Default)]
struct TargetShared {
    ever_probed: bool,
    alive: bool,
    consecutive_failures: u32,
    latency: Option<Duration>,
    handshake: Option<Duration>,
    exit_ip: Option<String>,
    last_ok: Option<SystemTime>,
    last_error: Option<String>,
    fail_stage: Option<FailStage>,
}

struct TargetRuntime {
    cfg: StatusTarget,
    connector: TunnelConnector,
    shared: Arc<Mutex<TargetShared>>,
}

struct ServerState {
    started: Instant,
    info: InstanceInfo,
    pool: ProxyPool,
    targets: Vec<TargetRuntime>,
    ring: Arc<EventRing>,
    cfg: StatusConfig,
}

/// Build target connectors, bind the listener, spawn probe + server
/// tasks. Errors are returned for the caller to log — the client keeps
/// running either way.
#[allow(clippy::too_many_arguments)]
pub async fn spawn(
    cfg: StatusConfig,
    pool: &ProxyPool,
    info: InstanceInfo,
    default_password: &[u8],
    default_ca: Option<&str>,
    kcp_tuning: Option<crate::config::KcpTuning>,
    quic_tuning: Option<crate::config::QuicTuning>,
    ring: Arc<EventRing>,
) -> io::Result<()> {
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for t in &cfg.target {
        if !seen.insert(t.name.clone()) {
            log::warn!("status: duplicate target {:?} skipped", t.name);
            continue;
        }
        let pw = t
            .password
            .clone()
            .map(String::into_bytes)
            .unwrap_or_else(|| default_password.to_vec());
        let ca = t.ca_path.clone().or_else(|| default_ca.map(str::to_string));
        let connector = crate::tunnel::build_connector(
            &t.host,
            t.port,
            &t.transport,
            ca,
            t.tls.unwrap_or(true),
            &pw,
            &kcp_tuning,
            &quic_tuning,
        )
        .await
        .map_err(|e| io::Error::other(format!("status target {:?}: {e}", t.name)))?;
        targets.push(TargetRuntime {
            cfg: t.clone(),
            connector,
            shared: Arc::new(Mutex::new(TargetShared {
                alive: true,
                ..Default::default()
            })),
        });
    }

    let listener = TcpListener::bind(&cfg.bind).await?;
    let state = Arc::new(ServerState {
        started: Instant::now(),
        info,
        pool: pool.clone(),
        targets,
        ring: ring.clone(),
        cfg,
    });
    ring.push("status", format!("listening on http://{}", state.cfg.bind));
    log::info!("status: page at http://{}", state.cfg.bind);

    // Probe tasks: staggered across the interval, one in flight per
    // target forever.
    let n = state.targets.len().max(1) as u64;
    for (i, t) in state.targets.iter().enumerate() {
        let offset = Duration::from_secs(state.cfg.interval * (i as u64) / n);
        tokio::spawn(probe_task(
            t.connector.clone(),
            t.cfg.clone(),
            t.shared.clone(),
            state.cfg.interval,
            state.cfg.timeout,
            state.cfg.url.clone(),
            offset,
            state.ring.clone(),
        ));
    }

    // HTTP responder (read-only; connection-per-request, close).
    let srv_state = state.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let st = srv_state.clone();
                    tokio::spawn(async move {
                        let _ = handle_conn(stream, st).await;
                    });
                }
                Err(e) => {
                    log::warn!("status: accept: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
    Ok(())
}

/// Per-target probe loop: sleep(stagger) → probe → record → sleep(interval).
#[allow(clippy::too_many_arguments)]
async fn probe_task(
    connector: TunnelConnector,
    cfg: StatusTarget,
    shared: Arc<Mutex<TargetShared>>,
    interval: u64,
    timeout: u64,
    url: String,
    offset: Duration,
    ring: Arc<EventRing>,
) {
    tokio::time::sleep(offset).await;
    let interval = Duration::from_secs(interval.max(1));
    loop {
        let out = probe_once(&connector, &url, Duration::from_secs(timeout.max(1))).await;
        record(&cfg, &shared, out, &ring);
        tokio::time::sleep(interval).await;
    }
}

/// Staged outcome of one probe.
struct ProbeOutcome {
    ok: bool,
    handshake: Option<Duration>,
    total: Duration,
    exit_ip: Option<String>,
    stage: Option<FailStage>,
    error: Option<String>,
}

/// One probe: transport handshake (stage 1) + HTTP GET through the
/// tunnel (stage 2), bounded by `timeout`. `hs_done` disambiguates
/// where a timeout struck.
async fn probe_once(connector: &TunnelConnector, url: &str, timeout: Duration) -> ProbeOutcome {
    let t0 = Instant::now();
    let hs_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hs_flag = hs_done.clone();
    let u = match crate::httpfetch::parse_url(url) {
        Ok(u) => u,
        Err(e) => {
            return ProbeOutcome {
                ok: false,
                handshake: None,
                total: t0.elapsed(),
                exit_ip: None,
                stage: Some(FailStage::Handshake),
                error: Some(format!("bad probe url: {e}")),
            };
        }
    };
    let addr = crate::httpfetch::url_addr(&u);
    let fut = async move {
        let mut c = connector.clone();
        let stream = c
            .connect(addr)
            .await
            .map_err(|e| (FailStage::Handshake, e.to_string()))?;
        let hs = t0.elapsed();
        hs_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        let body = if u.tls {
            let tls = crate::httpfetch::tls_wrap(stream, u.host)
                .await
                .map_err(|e| (FailStage::Relay, e.to_string()))?;
            crate::httpfetch::fetch_over(tls, &u)
                .await
                .map_err(|e| (FailStage::Relay, e.to_string()))?
        } else {
            crate::httpfetch::fetch_over(stream, &u)
                .await
                .map_err(|e| (FailStage::Relay, e.to_string()))?
        };
        Ok((hs, body))
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok((hs, body))) => ProbeOutcome {
            ok: true,
            handshake: Some(hs),
            total: t0.elapsed(),
            exit_ip: parse_exit_ip(&body),
            stage: None,
            error: None,
        },
        Ok(Err((stage, msg))) => ProbeOutcome {
            ok: false,
            handshake: if stage == FailStage::Handshake {
                None
            } else {
                Some(t0.elapsed())
            },
            total: t0.elapsed(),
            exit_ip: None,
            stage: Some(stage),
            error: Some(msg),
        },
        Err(_) => {
            let stage = if hs_done.load(std::sync::atomic::Ordering::Relaxed) {
                FailStage::Relay
            } else {
                FailStage::Handshake
            };
            ProbeOutcome {
                ok: false,
                handshake: None,
                total: t0.elapsed(),
                exit_ip: None,
                stage: Some(stage),
                error: Some("timeout".into()),
            }
        }
    }
}

/// Extract the exit IP from a probe body (api.ipify.org style: the
/// whole body is the IP; be liberal and scan tokens otherwise).
fn parse_exit_ip(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if let Ok(ip) = text.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    text.split_whitespace()
        .find_map(|t| t.parse::<std::net::IpAddr>().ok().map(|i| i.to_string()))
}

/// Apply a probe outcome to the shared state; emit ring events on
/// transitions (alive↔dead, exit-IP change, first result).
fn record(
    cfg: &StatusTarget,
    shared: &Arc<Mutex<TargetShared>>,
    out: ProbeOutcome,
    ring: &Arc<EventRing>,
) {
    let mut s = shared.lock().unwrap();
    let was_alive = s.alive && s.ever_probed;
    let prev_ip = s.exit_ip.clone();
    if out.ok {
        s.alive = true;
        s.consecutive_failures = 0;
        s.latency = Some(out.total);
        s.handshake = out.handshake;
        s.exit_ip = out.exit_ip.clone();
        s.last_ok = Some(SystemTime::now());
        s.last_error = None;
        s.fail_stage = None;
    } else {
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.latency = None;
        if s.consecutive_failures >= DEAD_THRESHOLD {
            s.alive = false;
        }
        s.last_error = out.error.clone();
        s.fail_stage = out.stage.clone();
    }
    let first = !s.ever_probed;
    s.ever_probed = true;
    let now_alive = s.alive;
    drop(s);

    let stage = |o: &ProbeOutcome| -> String {
        match &o.stage {
            Some(FailStage::Handshake) => "hs".into(),
            Some(FailStage::Relay) => "relay".into(),
            None => String::new(),
        }
    };
    if first {
        ring.push(
            "probe",
            format!(
                "{} first result: {} {}",
                cfg.name,
                if out.ok { "ok" } else { "FAIL" },
                if out.ok {
                    format!(
                        "{}ms exit {}",
                        out.total.as_millis(),
                        out.exit_ip.as_deref().unwrap_or("?")
                    )
                } else {
                    format!("({}: {})", stage(&out), out.error.as_deref().unwrap_or("?"))
                }
            ),
        );
    } else if was_alive && !now_alive {
        ring.push(
            "probe",
            format!(
                "{} is DEAD ({}: {})",
                cfg.name,
                stage(&out),
                out.error.as_deref().unwrap_or("?")
            ),
        );
    } else if !was_alive && now_alive {
        ring.push(
            "probe",
            format!("{} is ALIVE ({}ms)", cfg.name, out.total.as_millis()),
        );
    }
    if out.ok && out.exit_ip.is_some() && prev_ip.is_some() && out.exit_ip != prev_ip {
        ring.push(
            "exitip",
            format!(
                "{}: {} -> {}",
                cfg.name,
                prev_ip.as_deref().unwrap_or("?"),
                out.exit_ip.as_deref().unwrap_or("?")
            ),
        );
    }
}

// ------------------------------------------------------------- serving

/// Serve exactly one HTTP/1.1 request (GET-only, close on completion).
async fn handle_conn(mut stream: TcpStream, state: Arc<ServerState>) -> io::Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    // Head only; bail on oversized or idle clients.
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => return Ok(()),
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 4096 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("");

    let (status, ctype, body) = match (method, path) {
        ("GET", "/") | ("GET", "/status") => {
            let html = render_page_state(&state);
            ("200 OK", "text/html; charset=utf-8", html.into_bytes())
        }
        ("GET", "/healthz") => ("200 OK", "text/plain; charset=utf-8", b"ok\n".to_vec()),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found\n".to_vec(),
        ),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}

/// Snapshot all shared state under short locks and render.
fn render_page_state(state: &ServerState) -> String {
    let now = SystemTime::now();
    let mut pool_rows: Vec<PoolRow> = state
        .pool
        .servers()
        .iter()
        .map(|(name, e)| {
            let h = e.state.read().unwrap();
            PoolRow {
                name: name.to_string(),
                protocol: e.connector.protocol().to_string(),
                alive: h.alive,
                latency: h.latency,
                consecutive_failures: h.consecutive_failures,
                last_ok: h.last_ok,
            }
        })
        .collect();
    pool_rows.sort_by(|a, b| a.name.cmp(&b.name));
    let all_pool_dead = !pool_rows.is_empty() && pool_rows.iter().all(|r| !r.alive);
    let pool_default = state.pool.default_name().to_string();
    let mut groups: Vec<(String, Option<String>)> = state
        .pool
        .groups()
        .iter()
        .map(|(name, g)| (name.to_string(), g.chosen().map(|c| c.to_string())))
        .collect();
    groups.sort();

    // Target matrix: group rows by `server` key, keep first-seen order.
    let mut rows: Vec<TargetRow> = Vec::with_capacity(state.targets.len());
    for t in &state.targets {
        let s = t.shared.lock().unwrap();
        rows.push(TargetRow {
            name: t.cfg.name.clone(),
            server: t.cfg.server.clone().unwrap_or_else(|| t.cfg.name.clone()),
            transport: t.cfg.transport.clone(),
            endpoint: format!("{}:{}", t.cfg.host, t.cfg.port),
            alive: s.alive,
            consecutive_failures: s.consecutive_failures,
            latency: s.latency,
            handshake: s.handshake,
            exit_ip: s.exit_ip.clone(),
            last_ok: s.last_ok,
            last_error: s.last_error.clone(),
            fail_stage: s.fail_stage.clone(),
            pending: !s.ever_probed,
        });
    }
    let mut order: Vec<String> = Vec::new();
    for r in &rows {
        if !order.contains(&r.server) {
            order.push(r.server.clone());
        }
    }
    let target_groups: Vec<GroupView> = order
        .into_iter()
        .map(|srv| {
            let grp: Vec<TargetRow> = rows.iter().filter(|r| r.server == srv).cloned().collect();
            let hint = render::group_hint(&grp.iter().collect::<Vec<_>>());
            GroupView {
                server: srv,
                rows: grp,
                hint,
            }
        })
        .collect();
    let events = state.ring.tail(50);
    let snap = Snapshot {
        version: state.info.version,
        pid: state.info.pid,
        config_path: &state.info.config_path,
        uptime: state.started.elapsed(),
        listeners: &state.info.listeners,
        pool_default: &pool_default,
        pool_rows: &pool_rows,
        groups: &groups,
        groups_hint: if all_pool_dead {
            Some("every routing-pool server is DEAD — tunnel is down")
        } else {
            None
        },
        target_groups,
        events: &events,
        refresh: state.cfg.refresh,
        generated_at: now,
    };
    render::render_page(&snap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_bounded_and_ordered() {
        let ring = EventRing::with_cap(3);
        for i in 0..5 {
            ring.push("t", format!("e{i}"));
        }
        let t = ring.tail(10);
        assert_eq!(t.len(), 3);
        assert!(t[0].contains("e2"));
        assert!(t[2].contains("e4"));
    }

    #[test]
    fn exit_ip_parses_bare_and_token_bodies() {
        assert_eq!(parse_exit_ip(b"203.0.113.7"), Some("203.0.113.7".into()));
        assert_eq!(
            parse_exit_ip(b"  2001:db8::1\n"),
            Some("2001:db8::1".into())
        );
        assert_eq!(
            parse_exit_ip(b"your ip is 198.51.100.2 thanks"),
            Some("198.51.100.2".into())
        );
        assert_eq!(parse_exit_ip(b"no ip here"), None);
    }

    #[test]
    fn config_parses_status_section() {
        let toml = r#"
            password = "pw"
            bandwidth = 65536
            verbose = false
            kind = { Client = { proxy = { host = "a", port = 1 }, socks5_port = 1080, tproxy = { mode = "off", tcp_port = 0, udp_port = 0 } } }
            [status]
            [[status.target]]
            name = "kr-q"
            server = "korea"
            transport = "quic"
            host = "kr.example.com"
            port = 4433
            [[status.target]]
            name = "kr-t"
            server = "korea"
            transport = "tcp"
            host = "kr.example.com"
            port = 443
            password = "other"
            tls = false
        "#;
        let cfg: crate::config::Config = toml::from_str(toml).unwrap();
        let st = cfg.status.expect("status section");
        assert_eq!(st.bind, "127.0.0.1:8280");
        assert_eq!(st.refresh, 5);
        assert_eq!(st.interval, 30);
        assert_eq!(st.target.len(), 2);
        assert_eq!(st.target[1].password.as_deref(), Some("other"));
        assert_eq!(st.target[1].tls, Some(false));
    }

    #[test]
    fn defaults_applied_when_section_minimal() {
        let toml = r#"
            password = "pw"
            bandwidth = 1
            verbose = false
            kind = { Client = { proxy = { host = "a", port = 1 }, socks5_port = 1080, tproxy = { mode = "off", tcp_port = 0, udp_port = 0 } } }
            [status]
        "#;
        let cfg: crate::config::Config = toml::from_str(toml).unwrap();
        assert!(cfg.status.is_some());
        assert!(cfg.status.unwrap().target.is_empty());
    }

    #[tokio::test]
    async fn probe_classifies_handshake_failure() {
        // TCP connector to a closed local port: handshake-stage failure.
        let c =
            crate::tunnel::build_connector("127.0.0.1", 1, "tcp", None, true, b"pw", &None, &None)
                .await
                .unwrap();
        let out = probe_once(&c, "http://api.ipify.org/", Duration::from_secs(2)).await;
        assert!(!out.ok);
        assert_eq!(out.stage, Some(FailStage::Handshake));
        assert!(out.error.is_some());
    }

    #[test]
    fn listeners_describe_transparency() {
        let tproxy = crate::config::TransparentProxyConfig {
            mode: Some(crate::config::TproxyMode::Tproxy),
            tcp_port: 7895,
            udp_port: 7896,
            dns_port: Some(15353),
            dns_mode: Some("fakeip".into()),
            gateway: Some(true),
        };
        let l = describe_listeners(1080, None, true, &tproxy);
        assert!(l.iter().any(|s| s.contains("socks5+http :1080 (lan)")));
        assert!(
            l.iter()
                .any(|s| s.contains("tproxy tcp :7895 udp :7896 (gateway)"))
        );
        assert!(l.iter().any(|s| s.contains("dns :15353 (fakeip)")));
    }
}
