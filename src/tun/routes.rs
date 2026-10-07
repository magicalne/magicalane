//! TUN route management (clean-exit contract). Interface addressing +
//! default-route capture with per-server exceptions; all applied via
//! the same raw fork/execve runner as the tproxy rules.
//!
//! Platform notes:
//! - Linux: `ip` commands; a metric-1 default route via the device.
//! - macOS: `ifconfig`/`route` commands; capture uses the classic
//!   `0.0.0.0/1` + `128.0.0.0/1` split (more specific than the
//!   existing default route, so the original gateway stays untouched
//!   and teardown is a plain delete). IPv6 capture is `2000::/3`
//!   (global unicast), leaving link-local and our fake range alone.

use std::io;

use log::info;

use crate::tproxy::rules::run_ok;

/// Apply device addressing + routes. Idempotent.
#[cfg(target_os = "linux")]
pub fn tun_apply(
    dev: &str,
    v4: &str,
    v6: &str,
    server_ips: &[std::net::Ipv4Addr],
) -> io::Result<()> {
    tun_teardown(dev, server_ips);
    // Device addressing (kernel needs an address to source/route).
    for (addr, fam) in [(v4, "4"), (v6, "-6")] {
        run_ok("ip", &[fam, "addr", "add", addr, "dev", dev]);
    }
    run_ok("ip", &["link", "set", dev, "up"]);
    // The tproxy plane's fake-range local routes (local 198.18.0.0/15
    // dev lo) live in the LOCAL table: they (and their kernel dst
    // cache) pin token destinations to loopback and REFUSE TUN-mode
    // connections. Remove them and flush the cache.
    run_ok(
        "ip",
        &["route", "del", "local", "198.18.0.0/15", "dev", "lo"],
    );
    run_ok(
        "ip",
        &["-6", "route", "del", "local", "fc00::/18", "dev", "lo"],
    );
    run_ok("ip", &["route", "flush", "cache"]);
    run_ok("ip", &["-6", "route", "flush", "cache"]);
    // Server + local subnet exceptions via the main table (more
    // specific than any default route).
    for ip in server_ips {
        run_ok(
            "ip",
            &[
                "route",
                "add",
                &ip.to_string(),
                "via",
                "255.255.255.255",
                "dev",
                "eth0",
                "onlink",
            ],
        );
    }
    // Default via the TUN, metric 1 (wins over the kernel's eth0
    // default at metric 100 in the lab and on typical hosts).
    run_ok(
        "ip",
        &["route", "add", "default", "dev", dev, "metric", "1"],
    );
    run_ok(
        "ip",
        &["-6", "route", "add", "default", "dev", dev, "metric", "1"],
    );
    info!(
        "tun routes applied ({dev} default metric 1, {} server exception(s) via eth0)",
        server_ips.len()
    );
    Ok(())
}

/// Remove what we added. Idempotent; safe when nothing exists.
#[cfg(target_os = "linux")]
pub fn tun_teardown(dev: &str, server_ips: &[std::net::Ipv4Addr]) {
    run_ok("ip", &["route", "del", "default", "dev", dev]);
    run_ok("ip", &["-6", "route", "del", "default", "dev", dev]);
    for ip in server_ips {
        run_ok(
            "ip",
            &["route", "del", &ip.to_string(), "dev", "eth0", "onlink"],
        );
    }
    run_ok("ip", &["link", "set", dev, "down"]);
    info!("tun routes removed ({dev})");
}

/// Apply device addressing + routes (macOS). Capture via 0/1+128/1 so
/// the original default route is never modified; server exceptions go
/// as host routes via the ORIGINAL gateway (parsed from the routing
/// table before we touch anything).
#[cfg(target_os = "macos")]
pub fn tun_apply(
    dev: &str,
    v4: &str,
    v6: &str,
    server_ips: &[std::net::Ipv4Addr],
) -> io::Result<()> {
    tun_teardown(dev, server_ips);
    // The real gateway must be captured BEFORE our capture halves
    // reroute lookups (route get default would then answer "utun").
    let gw = default_gateway();
    // Addressing: v4 point-to-point (destination inside the fake
    // range), v6 /128 alias, big MTU for the userspace stack.
    run_ok("ifconfig", &[dev, v4, "198.18.255.253", "up"]);
    run_ok("ifconfig", &[dev, "inet6", &format!("{v6}/128"), "add"]);
    run_ok("ifconfig", &[dev, "mtu", "65535"]);
    // Server exceptions via the original gateway (skip if we could
    // not determine it — loopback servers do not need an exception).
    for ip in server_ips {
        if let Some(gw) = gw.as_deref() {
            run_ok("route", &["-n", "add", "-host", &ip.to_string(), gw]);
        }
    }
    // Capture: the two IPv4 halves + IPv6 global unicast. More
    // specific than the existing default route, so it is overridden
    // without being modified.
    run_ok(
        "route",
        &["-n", "add", "-inet", "0.0.0.0/1", "-interface", dev],
    );
    run_ok(
        "route",
        &["-n", "add", "-inet", "128.0.0.0/1", "-interface", dev],
    );
    run_ok(
        "route",
        &["-n", "add", "-inet6", "2000::/3", "-interface", dev],
    );
    info!(
        "tun routes applied ({dev} capture 0/1+128/1+2000::/3, {} server exception(s){})",
        server_ips.len(),
        gw.map(|g| format!(" via {g}")).unwrap_or_default()
    );
    Ok(())
}

/// Remove what we added (macOS). Idempotent; safe when nothing exists.
#[cfg(target_os = "macos")]
pub fn tun_teardown(dev: &str, server_ips: &[std::net::Ipv4Addr]) {
    run_ok("route", &["-n", "delete", "-inet", "0.0.0.0/1"]);
    run_ok("route", &["-n", "delete", "-inet", "128.0.0.0/1"]);
    run_ok("route", &["-n", "delete", "-inet6", "2000::/3"]);
    for ip in server_ips {
        run_ok("route", &["-n", "delete", "-host", &ip.to_string()]);
    }
    info!("tun routes removed ({dev})");
}

/// Original default gateway (macOS), captured before capture routes
/// exist. `route -n get default` -> "gateway: x.x.x.x".
#[cfg(target_os = "macos")]
fn default_gateway() -> Option<String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gateway:") {
            let gw = rest.trim();
            if !gw.is_empty() && !gw.contains("utun") {
                return Some(gw.to_string());
            }
        }
    }
    None
}
