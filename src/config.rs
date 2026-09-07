use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub kind: Kind,
    pub password: String,
    /// Server-side DNS ([dns] upstream/cache_size).
    pub dns: Option<ServerDns>,
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
    Tcp,
}

impl Protocol {
    pub fn from_opt(s: &Option<String>) -> Option<Self> {
        match s.as_deref() {
            None | Some("quic") => Some(Self::Quic),
            Some("kcp") => Some(Self::Kcp),
            Some("tcp") => Some(Self::Tcp),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(clippy::large_enum_variant)]
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
        /// Additional tunnel servers (the primary in `proxy` is named
        /// "default"; groups/rules reference entries by name).
        #[serde(default)]
        server: Vec<ServerSpec>,
        /// Automatic proxy groups over servers (url-test / fallback /
        /// load-balance). No manual mode: the strategy always decides.
        #[serde(default)]
        group: Vec<GroupSpec>,
        socks5_port: u16,
        /// SOCKS5/HTTP users ("user:pass" entries); absent = no auth.
        /// NOTE: with no auth, bind defaults to 127.0.0.1 — set
        /// allow_lan (and auth!) to expose the port to the network.
        socks5_users: Option<Vec<String>>,
        /// Bind address override (wins over allow_lan).
        bind: Option<String>,
        /// true = bind 0.0.0.0 (LAN-exposed); default false (127.0.0.1).
        allow_lan: Option<bool>,
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

/// An additional tunnel server (`[[kind.Client.server]]`).
///
/// ```toml
/// [[kind.Client.server]]
/// name = "work"           # required, unique; referenced by rules/groups
/// host = "b.example.com"
/// port = 4433
/// protocol = "kcp"        # quic (default) | kcp — mixed freely
/// ip = "203.0.113.9"      # optional pin (skip DNS for this server)
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct ServerSpec {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub ca_path: Option<String>,
    pub protocol: Option<String>,
    pub tls: Option<bool>,
    /// Optional pinned IP (anti-pollution bootstrap, per server).
    pub ip: Option<String>,
}

/// An automatic proxy group (`[[kind.Client.group]]`).
///
/// ```toml
/// [[kind.Client.group]]
/// name = "auto"
/// type = "url-test"        # url-test | fallback | load-balance
/// servers = ["default", "work"]   # server or group names (no cycles)
/// url = "http://www.gstatic.com/generate_204"   # probe (default)
/// interval = 300          # seconds
/// tolerance = 50          # ms; url-test hysteresis
/// strategy = "round-robin"  # load-balance only: round-robin | sticky
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct GroupSpec {
    pub name: String,
    /// "url-test" | "fallback" | "load-balance".
    pub gtype: String,
    /// Ordered member names (servers or groups).
    pub servers: Vec<String>,
    /// Probe URL (HTTP 204-style; default gstatic).
    pub url: Option<String>,
    /// Probe interval seconds (default 300).
    pub interval: Option<u64>,
    /// url-test switch hysteresis in ms (default 50).
    pub tolerance: Option<u64>,
    /// load-balance strategy: "round-robin" (default) | "sticky".
    pub strategy: Option<String>,
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
    /// Gateway mode (default `false`): intercept FORWARDED traffic too
    /// (iptables PREROUTING), turning the client into a transparent
    /// router for LAN devices. Workstation mode intercepts only local
    /// traffic. Tunnel-server traffic is exempted by address (v4+v6);
    /// single-NIC gateways rely on the source-address exemption since
    /// server responses share the LAN interface.
    pub gateway: Option<bool>,
    /// `"tunnel"` (default) — queries relayed through the tunnel;
    /// `"fakeip"` — answered locally with fake tokens (see src/dns/fakeip.rs);
    /// `"off"` — dns_port is ignored.
    pub dns_mode: Option<String>,
}

impl TransparentProxyConfig {
    pub fn mode(&self) -> TproxyMode {
        self.mode.unwrap_or(TproxyMode::Off)
    }
    pub fn gateway(&self) -> bool {
        self.gateway.unwrap_or(false)
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
    /// Resolver(s) for direct-routed domains: a single "ip:port" or a
    /// list (racing + failover). Default: all nameservers in resolv.conf.
    pub direct_dns: Option<OneOrMany>,
    /// Optional pinned server IP (bootstrapping without plaintext DNS).
    pub server_ip: Option<String>,
    /// Directory holding per-country CIDR lists for `geoip` rules
    /// (default "/etc/magicalane/geoip"; `geoip = "cn"` loads cn.txt).
    pub geoip_dir: Option<String>,
    /// Domains that must NOT get fake tokens (STUN/NTP/games/captive
    /// portals): answered with REAL resolution instead. Suffix match,
    /// leading "*." optional: ["stun.*.*", "*.ntp.org", "localhost"].
    pub fakeip_filter: Option<Vec<String>>,
    /// Persist the fake-IP map across restarts (path). Absent = off.
    pub fakeip_cache: Option<String>,
    /// Ordered rules; first match wins.
    #[serde(default)]
    pub rule: Vec<RoutingRule>,
    /// Remote rule providers (fetched by URL, refreshed on interval).
    #[serde(default)]
    pub provider: Vec<ProviderSpec>,
}

/// A remote rule list: fetched over HTTP(S), auto-refreshed, swapped
/// atomically into the engine (no restart).
///
/// ```toml
/// [[kind.Client.routing.provider]]
/// name = "china-domains"
/// url = "https://example.com/china.txt"
/// interval = 86400        # seconds (default: daily)
/// via = "proxy"           # fetch through the tunnel (default) | "direct"
/// action = "direct"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderSpec {
    pub name: String,
    pub url: String,
    /// Refresh interval in seconds (default 86400).
    pub interval: Option<u64>,
    /// Fetch path: "proxy" (through the tunnel, default) or "direct".
    pub via: Option<String>,
    /// Action for matched entries: "direct" (default), "proxy", or a
    /// server/group name.
    pub action: Option<String>,
}

impl RoutingSpec {
    /// Names referenced by rules/providers/default (for pool
    /// validation at startup): every non-"proxy" action string and a
    /// named default. "direct" excluded (not a tunnel target).
    pub fn tunnel_targets(&self) -> Vec<String> {
        let mut out = Vec::new();
        for r in &self.rule {
            if let Some(a) = &r.action {
                if a != "direct" && a != "proxy" && !out.contains(a) {
                    out.push(a.clone());
                }
            }
        }
        for p in &self.provider {
            if let Some(a) = &p.action {
                if a != "direct" && a != "proxy" && !out.contains(a) {
                    out.push(a.clone());
                }
            }
        }
        if let Some(d) = &self.default {
            if d != "direct" && d != "proxy" && !out.contains(d) {
                out.push(d.clone());
            }
        }
        out
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
    /// Substring (keyword) match, case-insensitive.
    pub domain_keyword: Option<Vec<String>>,
    /// Country code rule (`geoip = "cn"`): loads `<geoip_dir>/<cc>.txt`
    /// (plain CIDR list, chnroutes2/gaoyifan format). Matches real-IP
    /// connections; inert with a warning if the file is missing.
    pub geoip: Option<String>,
    /// `"direct"` (default when omitted), `"proxy"`, or a SERVER /
    /// GROUP name from `[[server]]`/`[[group]]` (e.g. `"work"`):
    /// matched traffic uses that tunnel target.
    pub action: Option<String>,
}

/// A config value that accepts either a single string or a list
/// (`upstream = "1.1.1.1:53"` or `upstream = ["1.1.1.1:53", "8.8.8.8:53"]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

/// Server-side DNS configuration (`[dns]`).
///
/// ```toml
/// [dns]
/// upstream = ["1.1.1.1:53", "8.8.8.8:53"]   # racing + failover
/// cache_size = 4096                          # answer cache cap (0 = off)
/// ```
#[derive(Debug, Default, Deserialize)]
pub struct ServerDns {
    /// Racing upstream list (default: every nameserver in resolv.conf).
    pub upstream: Option<OneOrMany>,
    /// Cache entry cap (default 4096; 0 disables caching).
    pub cache_size: Option<usize>,
}

