use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub kind: Kind,
    pub password: String,
    pub bandwidth: usize,
    pub verbose: bool,
    pub tuning: Option<Tuning>,
}

/// Transport tuning knobs (see `KcpTuning` / `QuicTuning`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Tuning {
    pub kcp: Option<KcpTuning>,
    pub quic: Option<QuicTuning>,
}

/// KCP parameters (mirrors kcp's classic tune knobs).
///
/// ```toml
/// [tuning.kcp]
/// interval = 10        # internal clock ms
/// nodelay = true       # turbo mode level 1
/// resend = 2           # fast retransmit aggressiveness (0 = off)
/// nc = true            # true = disable congestion control
/// sndwnd = 512         # send window (packets)
/// rcvwnd = 512         # receive window (packets)
/// mtu = 1200
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct KcpTuning {
    #[serde(default = "d_kcp_interval")]
    pub interval: i32,
    #[serde(default = "d_true")]
    pub nodelay: bool,
    #[serde(default = "d_kcp_resend")]
    pub resend: i32,
    #[serde(default = "d_true")]
    pub nc: bool,
    #[serde(default = "d_kcp_wnd")]
    pub sndwnd: u16,
    #[serde(default = "d_kcp_wnd")]
    pub rcvwnd: u16,
    #[serde(default = "d_kcp_mtu")]
    pub mtu: usize,
}

fn d_true() -> bool {
    true
}
fn d_kcp_interval() -> i32 {
    10
}
fn d_kcp_resend() -> i32 {
    2
}
fn d_kcp_wnd() -> u16 {
    512
}
fn d_kcp_mtu() -> usize {
    1200
}

impl Default for KcpTuning {
    fn default() -> Self {
        Self {
            interval: d_kcp_interval(),
            nodelay: true,
            resend: d_kcp_resend(),
            nc: true,
            sndwnd: d_kcp_wnd(),
            rcvwnd: d_kcp_wnd(),
            mtu: d_kcp_mtu(),
        }
    }
}

/// QUIC transport parameters.
///
/// ```toml
/// [tuning.quic]
/// congestion = "bbr"        # cubic (default) | bbr | new-reno
/// send_window = 16777216    # bytes; None keeps quinn's default
/// receive_window = 16777216
/// stream_receive_window = 8388608
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct QuicTuning {
    #[serde(default)]
    pub congestion: Option<String>,
    #[serde(default)]
    pub send_window: Option<u64>,
    #[serde(default)]
    pub receive_window: Option<u64>,
    #[serde(default)]
    pub stream_receive_window: Option<u64>,
}

impl QuicTuning {
    pub fn congestion_name(&self) -> &str {
        self.congestion.as_deref().unwrap_or("bbr")
    }
}

/// Transport protocol carrying the tunnel.
///
/// - `quic` (default): QUIC with built-in TLS (quinn)
/// - `kcp`: reliable UDP, optionally wrapped in TLS (`tls` flag, default true)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Protocol {
    #[default]
    Quic,
    Kcp,
}

impl Protocol {
    pub fn from_opt(s: &Option<String>) -> Option<Self> {
        match s.as_deref() {
            None | Some("quic") => Some(Self::Quic),
            Some("kcp") => Some(Self::Kcp),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub enum Kind {
    Server {
        port: u16,
        ca: Option<String>,
        key: Option<String>,
        protocol: Option<String>,
        tls: Option<bool>,
    },
    Client {
        proxy: ProxyConfig,
        socks5_port: u16,
        tproxy: TransparentProxyConfig,
        routing: Option<RoutingSpec>,
    },
}

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub ca_path: Option<String>,
    pub protocol: Option<String>,
    pub tls: Option<bool>,
}

/// Client-side transparent interception.
///
/// ```toml
/// [kind.Client.tproxy]
/// mode = "tproxy"     # off (default) | tproxy | tun
/// tcp_port = 7895     # transparent TCP listener (tproxy mode)
/// udp_port = 7896     # transparent UDP listener (tproxy mode)
/// dns_port = 15353    # DNS module listener; udp/53 is redirected here.
///                     # 0 disables DNS interception.
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TproxyMode {
    Off,
    Tproxy,
    Tun,
}

#[derive(Debug, Deserialize)]
pub struct TransparentProxyConfig {
    pub mode: Option<TproxyMode>,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub dns_port: Option<u16>,
    /// `"tunnel"` (default) — queries relayed through the tunnel;
    /// `"fakeip"` — answered locally with fake tokens (see src/dns/fakeip.rs);
    /// `"off"` — dns_port is ignored.
    pub dns_mode: Option<String>,
}

impl TransparentProxyConfig {
    pub fn mode(&self) -> TproxyMode {
        self.mode.unwrap_or(TproxyMode::Off)
    }
    pub fn dns_port(&self) -> u16 {
        self.dns_port.unwrap_or(0)
    }
    pub fn dns_mode(&self) -> &str {
        self.dns_mode.as_deref().unwrap_or("tunnel")
    }
}

/// Split-routing configuration (`[kind.Client.routing]`).
///
/// ```toml
/// [kind.Client.routing]
/// default = "proxy"                 # unmatched → proxy | direct
/// aaaa = "auto"                     # auto | fake | empty (fakeip mode)
/// direct_dns = "223.5.5.5:53"      # resolver for direct domains
/// server_ip = "203.0.113.10"       # pin server IP (anti-pollution bootstrap)
///
/// [[kind.Client.routing.rule]]
/// domain_suffix = ["cn", "baidu.com"]
/// action = "direct"
/// ```
#[derive(Debug, Default, Deserialize)]
pub struct RoutingSpec {
    /// `"proxy"` (default) or `"direct"` for unmatched connections.
    pub default: Option<String>,
    /// AAAA strategy in fakeip mode: `auto` (default) | `fake` | `empty`.
    pub aaaa: Option<String>,
    /// Optional explicit resolver for direct-routed domains ("ip:port").
    pub direct_dns: Option<String>,
    /// Optional pinned server IP (bootstrapping without plaintext DNS).
    pub server_ip: Option<String>,
    /// Directory holding per-country CIDR lists for `geoip` rules
    /// (default "/etc/magicalane/geoip"; `geoip = "cn"` loads cn.txt).
    pub geoip_dir: Option<String>,
    /// Ordered rules; first match wins.
    #[serde(default)]
    pub rule: Vec<RoutingRule>,
}

impl RoutingSpec {
    pub fn default_action(&self) -> RouteAction {
        match self.default.as_deref() {
            Some("direct") => RouteAction::Direct,
            _ => RouteAction::Proxy,
        }
    }
}

/// One routing rule. Omitted fields don't match; a rule with several
/// match fields creates one matcher per field (each checked in order).
#[derive(Debug, Default, Deserialize)]
pub struct RoutingRule {
    /// Label-aligned suffix: `qq.com` matches `weixin.qq.com`.
    pub domain_suffix: Option<Vec<String>>,
    /// Exact domain match (case-insensitive).
    pub domain: Option<Vec<String>>,
    /// Real-IP connections in these CIDRs (v4 and v6).
    pub ip_cidr: Option<Vec<String>>,
    /// Loyalsoldier/v2ray suffix list file, one domain per line.
    /// Lines containing `/` are parsed as CIDRs, so one file may mix
    /// domains and IP ranges (auto-detected per line).
    pub list_file: Option<String>,
    /// Country code rule (`geoip = "cn"`): loads `<geoip_dir>/<cc>.txt`
    /// (plain CIDR list, chnroutes2/gaoyifan format). Matches real-IP
    /// connections; inert with a warning if the file is missing.
    pub geoip: Option<String>,
    /// `"proxy"` or `"direct"` (default when omitted: direct).
    pub action: Option<RouteAction>,
}

impl RoutingRule {
    pub fn action_or_direct(&self) -> RouteAction {
        self.action.unwrap_or(RouteAction::Direct)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteAction {
    Proxy,
    Direct,
}

