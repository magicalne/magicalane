use anyhow::{Context, Result};
use std::net::ToSocketAddrs;
use lib::config::{Config, Kind, Protocol};
use lib::kcp::connector::KcpConnector;
use lib::{connector, generate_key_and_cert_pem};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "magicalane", about = "A quic proxy.")]
struct Opt {
    #[structopt(long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: Opt = Opt::from_args();
    let content = std::fs::read(opt.config)?;
    let config: Config = toml::from_slice(&content)?;

    start_with_config(config).await?;
    Ok(())
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn start_with_config(config: Config) -> Result<()> {
    let password = config.password;
    let bandwidth = config.bandwidth;
    let kind = config.kind;
    let tuning = config.tuning.clone().unwrap_or_default();
    env_logger::init();
    install_crypto_provider();

    // Teardown stale tproxy rules BEFORE any network activity (F1 fix):
    // the QUIC/KCP client constructor resolves the server hostname via
    // system DNS, which would be intercepted by stale DNS redirect rules
    // from a crashed previous run (circular dependency: DNS needs the
    // tunnel, the tunnel needs DNS). Clearing first breaks the cycle.
    if let Kind::Client { tproxy, .. } = &kind {
        if tproxy.mode() == lib::config::TproxyMode::Tproxy {
            lib::tproxy::rules::teardown(&lib::tproxy::rules::RuleSpec {
                server_ip: "0.0.0.0".parse().unwrap(),
                gateway: false,
                tcp_port: tproxy.tcp_port,
                udp_port: tproxy.udp_port,
                dns_port: tproxy.dns_port(),
                                server_ip6: None,
                            });
        }
    }

    match kind {
        Kind::Server {
            port,
            ca,
            key,
            protocol,
            tls,
        } => {
            let protocol = Protocol::from_opt(&protocol)
                .with_context(|| "unknown protocol (expected \"quic\" or \"kcp\")")?;
            let tls = tls.unwrap_or(true);
            match protocol {
                Protocol::Quic => {
                    let connector = lib::dispatch::DispatchConnector::new();
                    let key_cert = match (key, ca) {
                        (Some(key), Some(cert)) => (key.into(), cert.into()),
                        (_, _) => generate_key_and_cert_pem("tls", "org", "examples")?,
                    };
                    let mut server = lib::quic::server::Server::new(
                        connector,
                        key_cert,
                        port,
                        password,
                        bandwidth,
                        tuning.quic.clone(),
                    )?;
                    server.run().await?;
                }
                Protocol::Kcp => {
                    let connector = lib::dispatch::DispatchConnector::new();
                    let key_cert = match (key, ca) {
                        (Some(key), Some(cert)) => (key.into(), cert.into()),
                        (_, _) => generate_key_and_cert_pem("tls", "org", "examples")?,
                    };
                    let mut server = lib::kcp::listener::Server::new(
                        connector,
                        key_cert,
                        port,
                        password,
                        bandwidth,
                        tls,
                        tuning.kcp.clone(),
                    )?;
                    server.run().await?;
                }
            }
        }
        Kind::Client {
            proxy,
            socks5_port,
            tproxy: tproxy_cfg,
            routing,
        } => {
            let protocol = Protocol::from_opt(&proxy.protocol)
                .with_context(|| "unknown protocol (expected \"quic\" or \"kcp\")")?;
            let tls = proxy.tls.unwrap_or(true);
            let kcp_tuning = tuning.kcp.clone();
            let quic_tuning = tuning.quic.clone();
            match protocol {
                Protocol::Quic => {
                    let ca_path = proxy.ca_path.map(std::path::PathBuf::from);
                    let quic_client = lib::quic::client::ClientActorHndler::new(
                        proxy.host.clone(),
                        proxy.port,
                        ca_path,
                        password.as_bytes().to_vec(),
                        quic_tuning,
                    )
                    .await?;
                    let connector = connector::QuicConnector::new(quic_client);
                    run_client(
                        connector,
                        socks5_port,
                        tproxy_cfg,
                        routing,
                        &proxy.host,
                        proxy.port,
                        bandwidth,
                    )
                    .await?;
                }
                Protocol::Kcp => {
                    let ca_path = proxy.ca_path.map(std::path::PathBuf::from);
                    let connector = KcpConnector::new(
                        proxy.host.clone(),
                        proxy.port,
                        ca_path,
                        password.as_bytes().to_vec(),
                        tls,
                        kcp_tuning,
                    )?;
                    connector.prewarm();
                    run_client(
                        connector,
                        socks5_port,
                        tproxy_cfg,
                        routing,
                        &proxy.host,
                        proxy.port,
                        bandwidth,
                    )
                    .await?;
                }
            }
        }
    };
    Ok(())
}

/// Full client lifecycle: socks5 server + optional transparent interception
/// with the clean-exit contract (rules applied after listeners exist,
/// removed on SIGTERM/SIGINT).
#[allow(clippy::too_many_arguments)]
async fn run_client<C, IO>(
    connector: C,
    socks5_port: u16,
    tproxy: lib::config::TransparentProxyConfig,
    routing: Option<lib::config::RoutingSpec>,
    server_host: &str,
    server_port: u16,
    bandwidth: usize,
) -> Result<()>
where
    C: lib::connector::Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use lib::config::TproxyMode;
    let mode = tproxy.mode();

    // Split-routing engine + fake-IP map + direct connector (the trio
    // that turns intercepted connections into rule-based decisions).
    let routing_cfg = routing.unwrap_or_default();
    let engine = match lib::routing::RoutingEngine::from_config(&routing_cfg) {
        Ok(e) => e,
        Err(err) => anyhow::bail!("routing config invalid: {}", err),
    };
    let fake_map = std::sync::Arc::new(lib::dns::FakeIpMap::new());
    let direct_dns = routing_cfg.direct_dns.as_deref().and_then(|s| s.parse().ok());
    let direct = lib::connector::DirectConnector::new(direct_dns);
    let router = lib::tproxy::TproxyRouter {
        fake_map: fake_map.clone(),
        routing: std::sync::Arc::new(engine),
        direct,
    };
    let aaaa = routing_cfg
        .aaaa
        .as_deref()
        .and_then(lib::dns::AaaaMode::parse)
        .unwrap_or(lib::dns::AaaaMode::Auto);
    log::info!("routing: default={:?} rules={} aaaa={aaaa:?}",
        routing_cfg.default_action(), routing_cfg.rule.len());

    // Transparent listeners must exist BEFORE rules are installed.
    let tcp_listener = match mode {
        TproxyMode::Tproxy => Some(lib::tproxy::bind(tproxy.tcp_port)?),
        _ => None,
    };
    let tcp6_listener = match mode {
        TproxyMode::Tproxy if lib::tproxy::rules::v6_plane_wanted() => lib::tproxy::bind6(tproxy.tcp_port).ok(),
        _ => None,
    };
    let udp_interceptor = match mode {
        TproxyMode::Tproxy => Some(lib::udp::bind_client(tproxy.udp_port)?),
        _ => None,
    };
    // v6 UDP interceptor ONLY when the v6 plane will install: a second
    // REUSEADDR wildcard socket breaks v4 TPROXY delivery on this
    // kernel/podman combination (packets queue without waking tokio).
    let udp6_interceptor = match mode {
        TproxyMode::Tproxy if lib::tproxy::rules::v6_plane_wanted() => {
            lib::udp::bind_client_v6(tproxy.udp_port).ok()
        }
        _ => None,
    };

    // Warm up the tunnel BEFORE starting the DNS interceptor (F1 fix):
    // the first DNS query would trigger the QUIC/KCP handshake, which
    // itself needs to resolve the server hostname via DNS — a circular
    // dependency. Opening a throwaway tunnel stream forces the handshake
    // now, while system DNS is still un-intercepted.
    if mode == TproxyMode::Tproxy && tproxy.dns_port() != 0 {
        let mut warm = connector.clone();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            warm.connect(lib::socks5::proto::Addr::SocketAddr(
                "127.0.0.1:1".parse().unwrap(),
            )),
        )
        .await;
        log::info!("tunnel warmed up for DNS interceptor");
    }

    let dns_sock = match (mode, tproxy.dns_port()) {
        (TproxyMode::Tproxy, p) if p != 0 => Some(lib::dns::bind_client(p)?),
        _ => None,
    };
    let dns6_sock = match (mode, tproxy.dns_port()) {
        (TproxyMode::Tproxy, p) if p != 0 && lib::tproxy::rules::v6_plane_wanted() => {
            lib::dns::bind_client_v6(p).ok()
        }
        _ => None,
    };

    // SOCKS5 stays available alongside transparent interception.
    let mut socks =
        lib::socks5::server::Server::new(Some(socks5_port), connector.clone(), bandwidth).await?;
    let socks_task = tokio::spawn(async move { socks.run().await });

    if let Some(l) = tcp_listener {
        tokio::spawn(lib::tproxy::serve(l, connector.clone(), router.clone(), bandwidth));
    }
    if let Some(l6) = tcp6_listener {
        tokio::spawn(lib::tproxy::serve6(l6, connector.clone(), router.clone(), bandwidth));
    }
    let udp_router = lib::udp::UdpRouter {
        fake_map: fake_map.clone(),
        routing: router.routing.clone(),
        direct: router.direct.clone(),
    };
    if let Some(u) = udp_interceptor {
        tokio::spawn(lib::udp::serve_client(u, connector.clone(), udp_router.clone()));
    }
    if let Some(u6) = udp6_interceptor {
        tokio::spawn(lib::udp::serve_client(u6, connector.clone(), udp_router.clone()));
    }

    // Rules last; removed on exit paths below.
    if mode == TproxyMode::Tproxy {
        let server_addrs: Vec<std::net::SocketAddr> = (server_host, server_port)
            .to_socket_addrs()
            .map(Iterator::collect)
            .unwrap_or_default();
        let server_ip = server_addrs
            .iter()
            .find(|a| a.is_ipv4())
            .and_then(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            });
        let server_ip6 = server_addrs.iter().find(|a| a.is_ipv6()).and_then(|a| match a.ip() {
            std::net::IpAddr::V6(v6) => Some(v6),
            _ => None,
        });
        if let Some(ip) = server_ip {
            let spec = lib::tproxy::rules::RuleSpec {
                server_ip: ip,
                server_ip6,
                gateway: false, // workstation mode; gateway rules capture
                                 // server return traffic (see rules.rs)
                tcp_port: tproxy.tcp_port,
                udp_port: tproxy.udp_port,
                dns_port: tproxy.dns_port(),
            };
            lib::tproxy::rules::apply(&spec)?;
            // DNS serve tasks start after the rules so the fake-AAAA
            // "auto" flag reflects the actually-installed v6 plane.
            let v6_active = lib::tproxy::rules::v6_installed();
            for (sock, label) in [(dns_sock, "v4"), (dns6_sock, "v6")] {
                let Some(d) = sock else { continue };
                match tproxy.dns_mode() {
                    "fakeip" => {
                        log::info!("dns[{label}]: fakeip mode (aaaa={aaaa:?}, v6_intercept={v6_active})");
                        tokio::spawn(lib::dns::serve_client_fakeip(
                            d,
                            fake_map.clone(),
                            aaaa,
                            v6_active,
                            connector.clone(),
                        ));
                    }
                    _ => {
                        log::info!("dns[{label}]: tunnel mode");
                        tokio::spawn(lib::dns::serve_client(d, connector.clone()));
                    }
                }
            }
        } else {
            anyhow::bail!("tproxy mode requires an IPv4-resolvable server address");
        }
    }

    // Wait for a termination signal, then honor the clean-exit contract.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    // SIGHUP is deliberately ignored: daemons started from podman exec -d
    // or nohup receive it when the spawning session closes.
    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
        _ = socks_task => {
            // socks server failed/exited without a signal
            if mode == TproxyMode::Tproxy {
                lib::tproxy::rules::teardown(&lib::tproxy::rules::RuleSpec {
                    server_ip: "0.0.0.0".parse().unwrap(),
                    gateway: false,
                    tcp_port: tproxy.tcp_port,
                    udp_port: tproxy.udp_port,
                    dns_port: tproxy.dns_port(),
                                        server_ip6: None,
                                    });
            }
            anyhow::bail!("socks server exited: {r:?}");
        }
    }
    log::info!("terminating: removing network state");
    if mode == TproxyMode::Tproxy {
        lib::tproxy::rules::teardown(&lib::tproxy::rules::RuleSpec {
            server_ip: "0.0.0.0".parse().unwrap(),
            gateway: false,
            tcp_port: tproxy.tcp_port,
            udp_port: tproxy.udp_port,
            dns_port: tproxy.dns_port(),
                        server_ip6: None,
                    });
    }
    std::process::exit(0);
}
