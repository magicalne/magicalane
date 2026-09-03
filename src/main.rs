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

    // Transparent listeners must exist BEFORE rules are installed.
    let tcp_listener = match mode {
        TproxyMode::Tproxy => Some(lib::tproxy::bind(tproxy.tcp_port)?),
        _ => None,
    };
    let udp_interceptor = match mode {
        TproxyMode::Tproxy => Some(lib::udp::bind_client(tproxy.udp_port)?),
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

    // SOCKS5 stays available alongside transparent interception.
    let mut socks =
        lib::socks5::server::Server::new(Some(socks5_port), connector.clone(), bandwidth).await?;
    let socks_task = tokio::spawn(async move { socks.run().await });

    if let Some(l) = tcp_listener {
        tokio::spawn(lib::tproxy::serve(l, connector.clone(), bandwidth));
    }
    if let Some(u) = udp_interceptor {
        tokio::spawn(lib::udp::serve_client(u, connector.clone()));
    }
    if let Some(d) = dns_sock {
        tokio::spawn(lib::dns::serve_client(d, connector.clone()));
    }

    // Rules last; removed on exit paths below.
    if mode == TproxyMode::Tproxy {
        let server_ip = (server_host, server_port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.find(|a| a.is_ipv4()))
            .and_then(|a| a.ip().to_string().parse::<std::net::Ipv4Addr>().ok());
        if let Some(ip) = server_ip {
            let spec = lib::tproxy::rules::RuleSpec {
                server_ip: ip,
                gateway: false, // workstation mode; gateway rules capture
                                 // server return traffic (see rules.rs)
                tcp_port: tproxy.tcp_port,
                udp_port: tproxy.udp_port,
                dns_port: tproxy.dns_port(),
            };
            lib::tproxy::rules::apply(&spec)?;
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
        });
    }
    std::process::exit(0);
}
