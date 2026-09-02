use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub kind: Kind,
    pub password: String,
    pub bandwidth: usize,
    pub verbose: bool,
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
