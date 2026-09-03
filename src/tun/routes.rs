//! TUN route management (clean-exit contract).
//! Routes are tagged with a reserved protocol number (96) so teardown
//! is exact-match; the TUN device itself is destroyed when the fd closes.

use std::{io, net::Ipv4Addr, process::{Command, Stdio}};

use log::info;

use super::ROUTE_PROTO;

#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub server_ip: Ipv4Addr,
    pub dev: String,
    pub gateway: String,
}

fn run(cmd: &str, args: &[&str]) -> io::Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .stderr(Stdio::null())
        .output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(io::Error::other(format!(
            "{cmd} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )))
    }
}

fn run_ok(cmd: &str, args: &[&str]) {
    let _ = run(cmd, args);
}

/// Install routes: server exception + default via TUN.
/// Tagged with ROUTE_PROTO for exact-match teardown.
pub fn apply(spec: &RouteSpec) -> io::Result<()> {
    teardown(spec);

    // Exception: server reachable via the main routing table
    run(
        "ip",
        &[
            "route", "add",
            &spec.server_ip.to_string(),
            "dev", "eth0",
            "proto", &ROUTE_PROTO.to_string(),
        ],
    )?;

    // Default: everything else goes through the TUN
    run(
        "ip",
        &[
            "route", "replace", "default",
            "via", &spec.gateway,
            "dev", &spec.dev,
            "metric", "100",
            "proto", &ROUTE_PROTO.to_string(),
        ],
    )?;

    info!("TUN routes applied (proto {ROUTE_PROTO})");
    Ok(())
}

/// Remove exactly what we added (by proto tag).
pub fn teardown(_spec: &RouteSpec) {
    // Remove all routes tagged with our proto
    run_ok("ip", &["route", "del", "default", "proto", &ROUTE_PROTO.to_string()]);
    // The server exception has a specific prefix
    run_ok(
        "ip",
        &[
            "route", "del",
            &_spec.server_ip.to_string(),
            "proto", &ROUTE_PROTO.to_string(),
        ],
    );
    info!("TUN routes removed");
}

/// Whether TUN routes are currently installed.
pub fn is_installed() -> bool {
    run("ip", &["route", "show", "proto", &ROUTE_PROTO.to_string()])
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}
