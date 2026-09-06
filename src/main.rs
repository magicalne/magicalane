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
    let config_path = opt.config.clone();
    let content = std::fs::read(&opt.config)?;
    let config: Config = toml::from_slice(&content)?;

    start_with_config(config, Some(config_path)).await?;
    Ok(())
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn start_with_config(config: Config, config_path: Option<String>) -> Result<()> {
    let password = config.password;
    let bandwidth = config.bandwidth;
    let server_dns = config.dns;
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
            // Layered resolver for server-side lookups: [dns] upstream
            // list (racing + failover) or every nameserver; answer cache.
            let upstreams: Vec<std::net::SocketAddr> = server_dns
                .as_ref()
                .and_then(|d| d.upstream.as_ref())
                .map(|o| {
                    o.to_vec()
                        .iter()
                        .filter_map(|s| s.parse().ok())
                        .collect()
                })
                .unwrap_or_default();
            if !upstreams.is_empty() {
                log::info!("dns: server upstreams (racing): {upstreams:?}");
            }
            let resolver = std::sync::Arc::new(lib::dns::resolve::Resolver::new(
                upstreams,
                server_dns.as_ref().and_then(|d| d.cache_size),
            ));
            let protocol = Protocol::from_opt(&protocol)
                .with_context(|| "unknown protocol (expected \"quic\" or \"kcp\")")?;
            let tls = tls.unwrap_or(true);
            match protocol {
                Protocol::Quic => {
                    let connector = lib::dispatch::DispatchConnector::with_resolver(resolver.clone());
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
                    let connector = lib::dispatch::DispatchConnector::with_resolver(resolver.clone());
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
            socks5_users,
            bind,
            allow_lan,
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
                        socks5_users,
                        bind,
                        allow_lan.unwrap_or(false),
                        tproxy_cfg,
                        routing,
                        config_path.clone(),
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
                        socks5_users,
                        bind,
                        allow_lan.unwrap_or(false),
                        tproxy_cfg,
                        routing,
                        config_path.clone(),
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
    socks5_users: Option<Vec<String>>,
    bind: Option<String>,
    allow_lan: bool,
    tproxy: lib::config::TransparentProxyConfig,
    routing: Option<lib::config::RoutingSpec>,
    config_path: Option<String>,
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
    let direct_dns: Vec<std::net::SocketAddr> = routing_cfg
        .direct_dns
        .as_ref()
        .map(|o| {
            o.to_vec()
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    if !direct_dns.is_empty() {
        log::info!("routing: direct resolvers (racing): {direct_dns:?}");
    }
    let direct = lib::connector::DirectConnector::new(Some(direct_dns));
    let direct_resolver = direct.resolver();
    let engine = std::sync::Arc::new(engine);
    spawn_provider_tasks(
        engine.clone(),
        routing_cfg.provider.clone(),
        direct.clone(),
        connector.clone(),
    );
    let router = lib::tproxy::TproxyRouter {
        fake_map: fake_map.clone(),
        routing: engine.clone(),
        direct,
    };
    let aaaa = routing_cfg
        .aaaa
        .as_deref()
        .and_then(lib::dns::AaaaMode::parse)
        .unwrap_or(lib::dns::AaaaMode::Auto);
    // fake-ip exceptions: these domains get REAL answers (STUN/NTP/…)
    let fakeip_filter: std::sync::Arc<std::sync::RwLock<Vec<String>>> =
        std::sync::Arc::new(std::sync::RwLock::new(
            routing_cfg.fakeip_filter.clone().unwrap_or_default(),
        ));
    {
        let f = fakeip_filter.read().unwrap();
        if !f.is_empty() {
            log::info!("routing: fakeip filter entries: {}", f.len());
        }
    }
    // Persistence: restore tokens, periodic save, save on shutdown.
    if let Some(path) = routing_cfg.fakeip_cache.clone() {
        let restored = fake_map.load(&path);
        log::info!("routing: fakeip cache: restored {restored} entries from {path}");
        let map = fake_map.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
                map.save(&path);
            }
        });
    }
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
    let mut socks = lib::socks5::server::Server::new(
        Some(socks5_port),
        bind.as_deref(),
        allow_lan,
        socks5_users.unwrap_or_default(),
        connector.clone(),
        bandwidth,
    )
    .await?;
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
                            fakeip_filter.clone(),
                            direct_resolver.clone(),
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
    // SIGHUP: hot reload of the ROUTING layer (rules, providers, geoip
    // lists, fakeip filter). Transport/listener changes need a restart.
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let reload_ctx = (
        config_path.clone(),
        engine.clone(),
        fakeip_filter.clone(),
        router.direct.clone(),
    );
    let connector_for_reload = connector.clone();
    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
        _ = sighup.recv() => {
            log::info!("SIGHUP: reloading routing configuration");
            let (path, engine, filter, direct) = reload_ctx;
            if let Some(path) = path {
                match std::fs::read(&path)
                    .map_err(|e| anyhow::anyhow!("read: {}", e))
                    .and_then(|b| toml::from_slice::<lib::config::Config>(&b).map_err(|e| anyhow::anyhow!("parse: {}", e)))
                {
                    Ok(cfg) => {
                        if let lib::config::Kind::Client { routing: Some(spec), .. } = &cfg.kind {
                            if let Err(e) = engine.reload(spec) {
                                log::warn!("SIGHUP: routing reload failed: {e}");
                            } else {
                                *filter.write().unwrap() =
                                    spec.fakeip_filter.clone().unwrap_or_default();
                                spawn_provider_tasks(
                                    engine.clone(),
                                    spec.provider.clone(),
                                    direct.clone(),
                                    connector_for_reload.clone(),
                                );
                                log::info!("SIGHUP: routing reloaded ({} rules' spec + {} providers)",
                                    spec.rule.len(), spec.provider.len());
                            }
                        } else {
                            log::warn!("SIGHUP: config has no routing section; nothing to reload");
                        }
                    }
                    Err(e) => log::warn!("SIGHUP: config reload failed: {e}"),
                }
            } else {
                log::warn!("SIGHUP: no config path known (embedded config?); cannot reload");
            }
            // After a reload we keep running (do not exit).
            loop {
                tokio::select! {
                    _ = sigterm.recv() => break,
                    _ = sigint.recv() => break,
                    _ = sighup.recv() => {
                        log::info!("SIGHUP: reload again");
                        let (path, engine, filter, direct) = (config_path.clone(), engine.clone(), filter.clone(), direct.clone());
                        if let Some(path) = &path {
                            if let Some(cfg) = std::fs::read(path)
                                .ok()
                                .and_then(|b| toml::from_slice::<lib::config::Config>(&b).ok())
                            {
                                if let lib::config::Kind::Client { routing: Some(spec), .. } = &cfg.kind {
                                    if engine.reload(spec).is_ok() {
                                        *filter.write().unwrap() =
                                            spec.fakeip_filter.clone().unwrap_or_default();
                                        spawn_provider_tasks(
                                            engine.clone(),
                                            spec.provider.clone(),
                                            direct.clone(),
                                            connector_for_reload.clone(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
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
    if let Some(path) = &routing_cfg.fakeip_cache {
        fake_map.save(path);
        log::info!("fakeip cache saved to {path}");
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

/// Spawn fetch tasks for every configured rule provider: immediate
/// fetch + refresh loop on the configured interval.
#[allow(clippy::too_many_arguments)]
fn spawn_provider_tasks<C, IO>(
    engine: std::sync::Arc<lib::routing::RoutingEngine>,
    providers: Vec<lib::config::ProviderSpec>,
    direct: lib::connector::DirectConnector,
    connector: C,
) where
    C: lib::connector::Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    for p in providers {
        let engine = engine.clone();
        let mut direct = direct.clone();
        let mut connector = connector.clone();
        let interval = std::time::Duration::from_secs(p.interval.unwrap_or(86400));
        let via_direct = p.via.as_deref() == Some("direct");
        let name = p.name.clone();
        let url = p.url.clone();
        tokio::spawn(async move {
            loop {
                match fetch_provider(url.as_str(), via_direct, &mut direct, &mut connector).await {
                    Ok(text) => engine.update_provider(&name, &text),
                    Err(e) => log::warn!("provider {name:?} fetch failed: {e}"),
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
}

/// One provider fetch: URL -> body text.
async fn fetch_provider<C, IO>(
    url: &str,
    via_direct: bool,
    direct: &mut lib::connector::DirectConnector,
    connector: &mut C,
) -> anyhow::Result<String>
where
    C: lib::connector::Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let u = lib::httpfetch::parse_url(url)?;
    let addr = lib::httpfetch::url_addr(&u);
    if via_direct {
        let stream = lib::connector::Connector::connect(direct, addr)
            .await
            .map_err(|e| anyhow::anyhow!("direct connect: {}", e))?;
        fetch_on(stream, &u).await
    } else {
        let stream = lib::connector::Connector::connect(connector, addr)
            .await
            .map_err(|e| anyhow::anyhow!("tunnel connect: {}", e))?;
        fetch_on(stream, &u).await
    }
}

async fn fetch_on<S>(stream: S, u: &lib::httpfetch::Url<'_>) -> anyhow::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let body = if u.tls {
        let tls = lib::httpfetch::tls_wrap(stream, u.host).await?;
        lib::httpfetch::fetch_over(tls, u).await?
    } else {
        lib::httpfetch::fetch_over(stream, u).await?
    };
    Ok(String::from_utf8_lossy(&body).into_owned())
}
