//! TUN route management (clean-exit contract). Interface addressing +
//! default route with the server exception; all applied via the same
//! raw fork/execve runner as the tproxy rules.

use std::io;

use log::info;

use crate::tproxy::rules::run_ok;

/// Apply device addressing + routes. Idempotent.
pub fn tun_apply(
    dev: &str,
    v4: &str,
    v6: &str,
    server_ip: std::net::Ipv4Addr,
) -> io::Result<()> {
    tun_teardown(dev, server_ip);
    // Device addressing (kernel needs an address to source/route).
    for (addr, fam) in [(v4, "4"), (v6, "-6")] {
        run_ok("ip", &[fam, "addr", "add", addr, "dev", dev]);
    }
    run_ok("ip", &["link", "set", dev, "up"]);
    // The tproxy plane's fake-range local routes (local 198.18.0.0/15
    // dev lo) live in the LOCAL table: they (and their kernel dst
    // cache) pin token destinations to loopback and REFUSE TUN-mode
    // connections. Remove them and flush the cache.
    run_ok("ip", &["route", "del", "local", "198.18.0.0/15", "dev", "lo"]);
    run_ok("ip", &["-6", "route", "del", "local", "fc00::/18", "dev", "lo"]);
    run_ok("ip", &["route", "flush", "cache"]);
    run_ok("ip", &["-6", "route", "flush", "cache"]);
    // Server + local subnet exceptions via the main table (more
    // specific than any default route).
    run_ok("ip", &[
        "route", "add", &server_ip.to_string(), "via", "255.255.255.255", "dev", "eth0",
        "onlink",
    ]);
    // Default via the TUN, metric 50 (wins over the kernel's eth0
    // default at metric 100 in the lab; any lower-than-existing metric
    // works — use metric 1 for real deployments).
    run_ok("ip", &["route", "add", "default", "dev", dev, "metric", "1"]);
    run_ok("ip", &["-6", "route", "add", "default", "dev", dev, "metric", "1"]);
    info!("tun routes applied ({dev} default metric 1, server {server_ip} via eth0)");
    Ok(())
}

/// Remove what we added. Idempotent; safe when nothing exists.
pub fn tun_teardown(dev: &str, _server_ip: std::net::Ipv4Addr) {
    run_ok("ip", &["route", "del", "default", "dev", dev]);
    run_ok("ip", &["-6", "route", "del", "default", "dev", dev]);
    run_ok("ip", &["link", "set", dev, "down"]);
    info!("tun routes removed ({dev})");
}
