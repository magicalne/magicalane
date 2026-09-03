//! TUN mode: transparent interception via a TUN device instead of iptables.
//!
//! Creates a TUN interface (mgl0), routes all traffic through it (with the
//! server as an exception), and processes IP packets in userspace via
//! smoltcp. TCP connections are terminated by smoltcp and relayed through
//! the tunnel connector; UDP datagrams are routed through the UDP relay.
//!
//! Clean-exit contract: routes are tagged with a reserved protocol number
//! and removed exactly on shutdown; the TUN device itself is destroyed
//! when the process exits (fd lifecycle).

pub mod routes;

use std::sync::Arc;

use log::info;

/// TUN device configuration.
pub const TUN_NAME: &str = "mgl0";
pub const TUN_ADDR: &str = "198.18.0.1";
pub const TUN_PEER: &str = "198.18.0.2";
pub const TUN_MASK: &str = "255.255.255.252";
/// Route protocol tag for clean-exit (reserved for local use: 96-99 in Linux).
pub const ROUTE_PROTO: u32 = 96;

/// Start the TUN proxy: create the device, install routes, and serve.
pub async fn serve<C, IO>(
    connector: C,
    bandwidth: usize,
    server_ip: std::net::Ipv4Addr,
) -> anyhow::Result<()>
where
    C: crate::connector::Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 1. Create TUN device
    let mut tun_config = tun::Configuration::default();
    tun_config.tun_name(TUN_NAME)
        .address(TUN_ADDR.parse::<std::net::Ipv4Addr>().unwrap())
        .netmask(TUN_MASK.parse::<std::net::Ipv4Addr>().unwrap())
        .destination(TUN_PEER.parse::<std::net::Ipv4Addr>().unwrap())
        .up();
    let dev = tun::create_as_async(&tun_config)
        .map_err(|_e| anyhow::anyhow!("TUN device creation failed"))?;
    info!("TUN device {TUN_NAME} created ({TUN_ADDR}/{TUN_MASK})");

    // 2. Install routes (clean-exit: tagged with ROUTE_PROTO)
    let routes = routes::RouteSpec {
        server_ip,
        dev: TUN_NAME.to_string(),
        gateway: TUN_PEER.to_string(),
    };
    routes::apply(&routes)?;
    info!("TUN routes installed (default via {TUN_NAME}, server exception {server_ip})");

    // 3. Serve: read IP packets, process with smoltcp, relay through tunnel
    let tun_arc = Arc::new(dev);
    serve_packets(tun_arc, connector, bandwidth).await
}

/// Main packet processing loop.
async fn serve_packets<C, IO>(
    _dev: Arc<tun::AsyncDevice>,
    _connector: C,
    _bandwidth: usize,
) -> anyhow::Result<()>
where
    C: crate::connector::Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // TODO: smoltcp integration
    // For now, just log that we're running
    info!("TUN proxy running (smoltcp integration pending)");
    futures::future::pending::<()>().await;
    Ok(())
}

/// Stop the TUN proxy and clean up (called from signal handler).
pub fn stop(server_ip: std::net::Ipv4Addr) {
    let spec = routes::RouteSpec {
        server_ip,
        dev: TUN_NAME.to_string(),
        gateway: TUN_PEER.to_string(),
    };
    routes::teardown(&spec);
    info!("TUN routes removed");
}
