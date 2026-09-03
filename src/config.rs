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
        self.congestion.as_deref().unwrap_or("cubic")
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

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TransparentProxyConfig {
    tcp_port: u16,
    udp_port: u16,
}
