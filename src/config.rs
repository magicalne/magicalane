use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub kind: Kind,
    pub password: String,
    pub bandwidth: usize,
    pub verbose: bool,
}

#[derive(Debug, Deserialize)]
pub enum Kind {
    Server {
        port: u16,
        ca: Option<String>,
        key: Option<String>,
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
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TransparentProxyConfig {
    tcp_port: u16,
    udp_port: u16,
}
