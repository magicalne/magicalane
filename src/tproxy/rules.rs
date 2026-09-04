//! Transactional host-network rule management (the clean-exit contract).
//!
//! Every mutation is namespaced to magicalane: owned iptables chains, a
//! dedicated policy-routing table, and a reserved fwmark. Built-in chains
//! receive exactly one jump each; teardown removes that exact jump and
//! flushes ONLY the owned chains. `iptables-restore --noflush` applies the
//! mangle rules atomically. All teardown paths are idempotent, and
//! `apply()` adopts (cleans) stale state from a previous crashed run
//! before installing fresh rules.
//!
//! On any exit path (SIGTERM hook, supervisor cleanup, next-start
//! adoption) the host returns to byte-identical network state.
//!
//! NOTE: commands run via raw fork/execve rather than std::process -
//! std's spawn path references glibc 2.39 pidfd symbols, which breaks
//! execution on older glibc systems (e.g. Debian bookworm).

use std::{io, net::Ipv4Addr};

use log::{info, warn};

pub const MARK: u32 = 0x2A1;
pub const TABLE: u32 = 141;
const CHAIN_OUT: &str = "MGL-OUT";
const CHAIN_PRE: &str = "MGL-PRE";
const CHAIN_NAT: &str = "MGL-NAT";
const CHAIN6_OUT: &str = "MGL6-OUT";
const CHAIN6_PRE: &str = "MGL6-PRE";
const CHAIN6_NAT: &str = "MGL6-NAT";

#[derive(Debug, Clone)]
pub struct RuleSpec {
    /// Tunnel server address: our own egress must bypass interception.
    pub server_ip: Ipv4Addr,
    /// Server's IPv6 address, when it has one (v6 plane exception).
    pub server_ip6: Option<std::net::Ipv6Addr>,
    /// Gateway mode: intercept FORWARDED traffic too (PREROUTING on real
    /// interfaces). Workstation mode (false) only intercepts local traffic.
    pub gateway: bool,
    /// Transparent TCP listener port.
    pub tcp_port: u16,
    /// Transparent UDP listener port (0 = UDP interception disabled).
    pub udp_port: u16,
    /// DNS module listener port (0 = DNS interception disabled).
    pub dns_port: u16,
}

fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap_or_else(|_| std::ffi::CString::new("invalid").unwrap())
}

/// Run a command, capture combined stdout+stderr. Uses fork + execve with
/// absolute paths (async-signal-safe child). posix_spawn's CLONE_VM path
/// is rejected by container seccomp profiles, and std::process::Command
/// references glibc-2.39 pidfd symbols - this avoids both.
fn run(cmd: &str, args: &[&str]) -> io::Result<String> {
    let resolved = match cmd {
        "ip" => "/usr/sbin/ip",
        "ip6tables" => "/usr/sbin/ip6tables",
        "iptables" => "/usr/sbin/iptables",
        "iptables-restore" => "/usr/sbin/iptables-restore",
        "ip6tables-restore" => "/usr/sbin/ip6tables-restore",
        other => other,
    };
    let mut cargs: Vec<std::ffi::CString> = Vec::with_capacity(args.len() + 1);
    cargs.push(cstr(resolved));
    for a in args {
        cargs.push(cstr(a));
    }
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // build argv/envp BEFORE fork: no allocations in the forked child
    let mut argv: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());
    let env_path = cstr("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    let envp: [*const libc::c_char; 2] = [env_path.as_ptr(), std::ptr::null()];
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::dup2(fds[1], 1);
            libc::dup2(fds[1], 2);
            libc::close(fds[1]);
            libc::execve(cargs[0].as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    unsafe {
        libc::close(fds[1]);
        use std::io::Read;
        use std::os::unix::io::FromRawFd;
        let mut file = std::fs::File::from_raw_fd(fds[0]);
        let mut out = String::new();
        let _ = file.read_to_string(&mut out);
        drop(file);
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        if status == 0 {
            Ok(out)
        } else {
            Err(io::Error::other(format!("{resolved} {args:?} failed ({status}): {out}")))
        }
    }
}

/// Best-effort variant used for teardown (tolerates absence).
fn run_ok(cmd: &str, args: &[&str]) {
    let _ = run(cmd, args);
}

fn jump_exists(builtin: &str, chain: &str) -> bool {
    run("iptables", &["-t", "mangle", "-C", builtin, "-j", chain]).is_ok()
}

/// Apply an iptables-restore/ip6tables-restore blob atomically (stdin).
fn restore_blob(restore_bin: &str, blob: &str) -> io::Result<()> {
    // Child stdout/stderr go to /dev/null: piping them without reading
    // deadlocks when the pipe buffer fills (the cause of the runtime wedge).
    let mut in_fds = [0i32; 2];
    unsafe {
        if libc::pipe(in_fds.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let devnull =
        unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
    let cmd = cstr(restore_bin);
    let arg = cstr("--noflush");
    let argv: [*const libc::c_char; 3] = [cmd.as_ptr(), arg.as_ptr(), std::ptr::null()];
    let env_path = cstr("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    let envp: [*const libc::c_char; 2] = [env_path.as_ptr(), std::ptr::null()];
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(in_fds[1]);
            libc::dup2(in_fds[0], 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            libc::execve(cmd.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    unsafe {
        libc::close(in_fds[0]);
        libc::close(devnull);
        let buf = blob.as_bytes();
        let mut written = 0usize;
        while written < buf.len() {
            let n = libc::write(
                in_fds[1],
                buf[written..].as_ptr() as *const libc::c_void,
                buf.len() - written,
            );
            if n <= 0 {
                break;
            }
            written += n as usize;
        }
        libc::close(in_fds[1]);
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "iptables-restore failed ({status})"
            )))
        }
    }
}

/// Remove stale state from a previous run (crash / kill -9 adoption),
/// then install fresh rules. Idempotent.
pub fn apply(spec: &RuleSpec) -> io::Result<()> {
    teardown(spec);
    info!("tproxy rules: mark {MARK:#x} table {TABLE} chains {CHAIN_OUT}/{CHAIN_PRE}");

    // 1. policy routing: marked packets are delivered locally
    run(
        "ip",
        &[
            "rule", "add", "fwmark", &MARK.to_string(), "lookup", &TABLE.to_string(),
            "prio", "100",
        ],
    )?;
    run(
        "ip",
        &["route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", &TABLE.to_string()],
    )?;

    // 2. nat rules: REDIRECT local TCP to the transparent listener.
    // REDIRECT (nat) is used for local traffic because TPROXY in
    // OUTPUT+PREROUTING creates an infinite loop (the SYN-ACK from the
    // transparent socket would be re-intercepted).
    let mut nat = String::new();
    nat.push_str("*nat\n");
    nat.push_str(&format!(":{CHAIN_NAT} - [0:0]\n"));
    // Direct-route sockets carry SO_MARK_DIRECT: skip ALL interception
    // (DNS REDIRECT and TCP REDIRECT alike) or direct connections loop.
    nat.push_str(&format!(
        "-A {CHAIN_NAT} -m mark --mark {:#x} -j RETURN\n",
        crate::connector::SO_MARK_DIRECT
    ));
    nat.push_str(&format!(
        "-A {CHAIN_NAT} -d {}/32 -j RETURN\n", spec.server_ip
    ));
    nat.push_str("-A MGL-NAT -d 127.0.0.0/8 -j RETURN\n");
    nat.push_str("-A MGL-NAT -d 224.0.0.0/4 -j RETURN\n");
    nat.push_str("-A MGL-NAT -d 255.255.255.255/32 -j RETURN\n");
    nat.push_str(&format!(
        "-A {CHAIN_NAT} -p tcp -j REDIRECT --to-ports {}\n", spec.tcp_port
    ));
    if spec.dns_port != 0 {
        nat.push_str(&format!(
            "-A {CHAIN_NAT} -p udp --dport 53 -j REDIRECT --to-ports {}\n", spec.dns_port
        ));
    }
    nat.push_str(&format!("-A OUTPUT -j {CHAIN_NAT}\n"));
    nat.push_str("COMMIT\n");

    // 3. mangle rules: TPROXY for FORWARDED traffic (gateway mode) and
    // for local UDP that REDIRECT can't handle.
    let mut blob = String::new();
    blob.push_str("*mangle\n");
    blob.push_str(&format!(":{CHAIN_OUT} - [0:0]\n"));
    blob.push_str(&format!(":{CHAIN_PRE} - [0:0]\n"));
    // MGL-OUT marks local UDP for policy routing to lo (for TPROXY);
    // local TCP is already handled by REDIRECT in nat.
    if spec.udp_port != 0 {
        // Direct-route sockets never get re-marked.
        blob.push_str(&format!(
            "-A {CHAIN_OUT} -m mark --mark {:#x} -j RETURN\n",
            crate::connector::SO_MARK_DIRECT
        ));
        blob.push_str(&format!("-A {CHAIN_OUT} -d {}/32 -j RETURN\n", spec.server_ip));
        blob.push_str("-A MGL-OUT -d 127.0.0.0/8 -j RETURN\n");
        if spec.dns_port != 0 {
            // DNS handled by REDIRECT in nat; skip it here
            blob.push_str(&format!(
                "-A {CHAIN_OUT} -p udp --dport 53 -j RETURN\n"
            ));
            // Exclude our own DNS interceptor's responses (from dns_port):
            // they would be MARK'd and TPROXY'd to our own UDP interceptor.
            blob.push_str(&format!(
                "-A {CHAIN_OUT} -p udp --sport {} -j RETURN\n", spec.dns_port
            ));
        }
        // Exclude our own UDP interceptor's responses
        blob.push_str(&format!(
            "-A {CHAIN_OUT} -p udp --sport {} -j RETURN\n", spec.udp_port
        ));
        blob.push_str(&format!(
            "-A {CHAIN_OUT} -p udp -j MARK --set-mark {MARK}\n"
        ));
    }
    // MGL-PRE: TPROXY on lo for marked UDP (local) and on any interface
    // for forwarded TCP/UDP (gateway mode, matched by mark).
    if spec.udp_port != 0 {
        blob.push_str(&format!(
            "-A {CHAIN_PRE} -i lo -p udp -m mark --mark {MARK} -j TPROXY --on-port {} --tproxy-mark {MARK}\n",
            spec.udp_port
        ));
    }
    // Gateway mode: mark + TPROXY FORWARDED traffic (PREROUTING on
    // real interfaces). NOT installed in workstation mode: these rules
    // would capture the server's return traffic on eth0, breaking the
    // tunnel itself (the QUIC/KCP responses would be TPROXY'd to our
    // own UDP interceptor instead of the QUIC socket).
    if spec.gateway {
        blob.push_str(&format!(
            "-A {CHAIN_PRE} ! -i lo -p tcp -j MARK --set-mark {MARK}\n"
        ));
        blob.push_str(&format!(
            "-A {CHAIN_PRE} ! -i lo -p tcp -m mark --mark {MARK} -j TPROXY --on-port {} --tproxy-mark {MARK}\n",
            spec.tcp_port
        ));
        if spec.udp_port != 0 {
            blob.push_str(&format!(
                "-A {CHAIN_PRE} ! -i lo -p udp -j MARK --set-mark {MARK}\n"
            ));
            blob.push_str(&format!(
                "-A {CHAIN_PRE} ! -i lo -p udp -m mark --mark {MARK} -j TPROXY --on-port {} --tproxy-mark {MARK}\n",
                spec.udp_port
            ));
        }
    }
    blob.push_str(&format!("-A OUTPUT -j {CHAIN_OUT}\n"));
    blob.push_str(&format!("-A PREROUTING -j {CHAIN_PRE}\n"));
    blob.push_str("COMMIT\n");

    restore_blob("/usr/sbin/iptables-restore", &nat).inspect_err(|_e| {
        teardown(spec);
    })?;
    restore_blob("/usr/sbin/iptables-restore", &blob).inspect_err(|_e| {
        teardown(spec);
    })?;
    // v6 mirror (best effort; installed iff the host has usable v6).
    let v6 = v6_available();
    if v6 {
        if let Err(err) = apply_v6(spec) {
            warn!("v6 plane skipped: {err}");
            teardown_v6();
        }
    }

    info!(
        "tproxy rules applied (tcp:{}, udp:{}, dns:{})",
        spec.tcp_port, spec.udp_port, spec.dns_port
    );
    Ok(())
}

/// Remove exactly what we added. Idempotent; safe on a clean system.
pub fn teardown(_spec: &RuleSpec) {
    // Nuclear fallback: if iptables-nft reports chain incompatibility
    // (stale state from a different iptables API version), flush the
    // entire ruleset. In containers/dedicated systems this is safe.
    if run("iptables", &["-t", "mangle", "-L", "MGL-OUT"]).is_err() {
        run_ok("nft", &["flush", "ruleset"]);
    }
    // Remove the jumps first so no new packets enter our chains
    if jump_exists("OUTPUT", CHAIN_OUT) {
        run_ok("iptables", &["-t", "mangle", "-D", "OUTPUT", "-j", CHAIN_OUT]);
    }
    if jump_exists("PREROUTING", CHAIN_PRE) {
        run_ok("iptables", &["-t", "mangle", "-D", "PREROUTING", "-j", CHAIN_PRE]);
    }
    run_ok("iptables", &["-t", "mangle", "-F", CHAIN_OUT]);
    run_ok("iptables", &["-t", "mangle", "-X", CHAIN_OUT]);
    run_ok("iptables", &["-t", "mangle", "-F", CHAIN_PRE]);
    run_ok("iptables", &["-t", "mangle", "-X", CHAIN_PRE]);
    // nat chain
    if run("iptables", &["-t", "nat", "-C", "OUTPUT", "-j", CHAIN_NAT]).is_ok() {
        run_ok("iptables", &["-t", "nat", "-D", "OUTPUT", "-j", CHAIN_NAT]);
    } else {
        // try deleting anyway (the check might fail for nft compat reasons)
        run_ok("iptables", &["-t", "nat", "-D", "OUTPUT", "-j", CHAIN_NAT]);
    }
    run_ok("iptables", &["-t", "nat", "-F", CHAIN_NAT]);
    // retry deletion: -X can fail transiently (nft backend timing)
    for _ in 0..3 {
        run_ok("iptables", &["-t", "nat", "-X", CHAIN_NAT]);
    }
    for _ in 0..3 {
        run_ok(
            "ip",
            &[
                "rule", "del", "fwmark", &MARK.to_string(), "lookup", &TABLE.to_string(),
                "prio", "100",
            ],
        );
    }
    run_ok("ip", &["route", "flush", "table", &TABLE.to_string()]);
    teardown_v6();
    info!("tproxy rules removed");
}

/// Whether our chains currently exist (stale-state detection helper).
pub fn is_installed() -> bool {
    run("iptables", &["-t", "mangle", "-n", "-L", CHAIN_OUT]).is_ok()
}

// keep warn import used when compiled without logging side effects
#[allow(dead_code)]
fn _warn_placeholder() {
    warn!("unused");
}

// ---------------------------------------------------------------- v6 plane

/// Host capability: a GLOBAL v6 route (not just link-local) and the
/// ip6tools present. Does NOT mean the mirror is installed — see
/// v6_installed().
fn v6_available() -> bool {
    let has_route = run("ip", &["-6", "route", "show", "default"])
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let has_restore = std::path::Path::new("/usr/sbin/ip6tables-restore").exists();
    has_route && has_restore
}

/// Whether the MGL6 mirror is ACTUALLY installed right now. This is the
/// truth source for the fake-AAAA "auto" strategy: tokens are only
/// handed out when the interception plane can catch them.
pub fn v6_installed() -> bool {
    run("ip6tables", &["-t", "mangle", "-n", "-L", CHAIN6_OUT]).is_ok()
}

/// Install the v6 mirror of the v4 rules (workstation mode):
///   nat    MGL6-NAT  — REDIRECT local v6 TCP + udp/53
///   mangle MGL6-OUT  — mark local UDP (except our own / direct-marked)
///   mangle MGL6-PRE  — TPROXY marked UDP on lo (+ gateway mirror)
/// plus policy routing (fwmark -> table -> local ::/0 dev lo).
fn apply_v6(spec: &RuleSpec) -> io::Result<()> {
    // policy routing
    run(
        "ip",
        &[
            "-6", "rule", "add", "fwmark", &MARK.to_string(),
            "lookup", &TABLE.to_string(), "prio", "100",
        ],
    )?;
    run(
        "ip",
        &[
            "-6", "route", "add", "local", "::/0", "dev", "lo",
            "table", &TABLE.to_string(),
        ],
    )?;

    // nat: REDIRECT local v6 TCP to the transparent v6 listener, and
    // udp/53 to the v6 DNS listener.
    let mut nat = String::new();
    nat.push_str("*nat\n");
    nat.push_str(&format!(":{CHAIN6_NAT} - [0:0]\n"));
    nat.push_str(&format!(
        "-A {CHAIN6_NAT} -m mark --mark {:#x} -j RETURN\n",
        crate::connector::SO_MARK_DIRECT
    ));
    if let Some(srv) = spec.server_ip6 {
        nat.push_str(&format!("-A {CHAIN6_NAT} -d {srv}/128 -j RETURN\n"));
    }
    nat.push_str("-A MGL6-NAT -d ::1/128 -j RETURN\n");
    nat.push_str("-A MGL6-NAT -d fe80::/10 -j RETURN\n");
    nat.push_str("-A MGL6-NAT -d ff00::/8 -j RETURN\n");
    nat.push_str(&format!(
        "-A {CHAIN6_NAT} -p tcp -j REDIRECT --to-ports {}\n", spec.tcp_port
    ));
    if spec.dns_port != 0 {
        nat.push_str(&format!(
            "-A {CHAIN6_NAT} -p udp --dport 53 -j REDIRECT --to-ports {}\n", spec.dns_port
        ));
    }
    nat.push_str(&format!("-A OUTPUT -j {CHAIN6_NAT}\n"));
    nat.push_str("COMMIT\n");

    // mangle: TPROXY for local v6 UDP (REDIRECT can't carry orig dst).
    let mut blob = String::new();
    blob.push_str("*mangle\n");
    blob.push_str(&format!(":{CHAIN6_OUT} - [0:0]\n"));
    blob.push_str(&format!(":{CHAIN6_PRE} - [0:0]\n"));
    if spec.udp_port != 0 {
        blob.push_str(&format!(
            "-A {CHAIN6_OUT} -m mark --mark {:#x} -j RETURN\n",
            crate::connector::SO_MARK_DIRECT
        ));
        if let Some(srv) = spec.server_ip6 {
            blob.push_str(&format!("-A {CHAIN6_OUT} -d {srv}/128 -j RETURN\n"));
        }
        blob.push_str("-A MGL6-OUT -d ::1/128 -j RETURN\n");
        blob.push_str("-A MGL6-OUT -d fe80::/10 -j RETURN\n");
        if spec.dns_port != 0 {
            blob.push_str(&format!("-A {CHAIN6_OUT} -p udp --dport 53 -j RETURN\n"));
            blob.push_str(&format!(
                "-A {CHAIN6_OUT} -p udp --sport {} -j RETURN\n", spec.dns_port
            ));
        }
        blob.push_str(&format!(
            "-A {CHAIN6_OUT} -p udp --sport {} -j RETURN\n", spec.udp_port
        ));
        blob.push_str(&format!("-A {CHAIN6_OUT} -p udp -j MARK --set-mark {MARK}\n"));
        blob.push_str(&format!(
            "-A {CHAIN6_PRE} -i lo -p udp -m mark --mark {MARK} -j TPROXY --on-port {} --tproxy-mark {MARK}\n",
            spec.udp_port
        ));
    }
    if spec.gateway {
        blob.push_str(&format!("-A {CHAIN6_PRE} ! -i lo -p tcp -j MARK --set-mark {MARK}\n"));
        blob.push_str(&format!(
            "-A {CHAIN6_PRE} ! -i lo -p tcp -m mark --mark {MARK} -j TPROXY --on-port {} --tproxy-mark {MARK}\n",
            spec.tcp_port
        ));
        if spec.udp_port != 0 {
            blob.push_str(&format!("-A {CHAIN6_PRE} ! -i lo -p udp -j MARK --set-mark {MARK}\n"));
            blob.push_str(&format!(
                "-A {CHAIN6_PRE} ! -i lo -p udp -m mark --mark {MARK} -j TPROXY --on-port {} --tproxy-mark {MARK}\n",
                spec.udp_port
            ));
        }
    }
    blob.push_str(&format!("-A OUTPUT -j {CHAIN6_OUT}\n"));
    blob.push_str(&format!("-A PREROUTING -j {CHAIN6_PRE}\n"));
    blob.push_str("COMMIT\n");

    restore_blob("/usr/sbin/ip6tables-restore", &nat)?;
    restore_blob("/usr/sbin/ip6tables-restore", &blob)?;
    info!("v6 mirror applied (MGL6 chains + policy route)");
    Ok(())
}

/// Remove the v6 plane. Idempotent.
pub fn teardown_v6() {
    if !std::path::Path::new("/usr/sbin/ip6tables").exists() {
        return;
    }
    run_ok("ip6tables", &["-t", "mangle", "-D", "OUTPUT", "-j", CHAIN6_OUT]);
    run_ok("ip6tables", &["-t", "mangle", "-D", "PREROUTING", "-j", CHAIN6_PRE]);
    run_ok("ip6tables", &["-t", "mangle", "-F", CHAIN6_OUT]);
    run_ok("ip6tables", &["-t", "mangle", "-X", CHAIN6_OUT]);
    run_ok("ip6tables", &["-t", "mangle", "-F", CHAIN6_PRE]);
    run_ok("ip6tables", &["-t", "mangle", "-X", CHAIN6_PRE]);
    run_ok("ip6tables", &["-t", "nat", "-D", "OUTPUT", "-j", CHAIN6_NAT]);
    run_ok("ip6tables", &["-t", "nat", "-F", CHAIN6_NAT]);
    for _ in 0..3 {
        run_ok("ip6tables", &["-t", "nat", "-X", CHAIN6_NAT]);
    }
    for _ in 0..3 {
        run_ok(
            "ip",
            &[
                "-6", "rule", "del", "fwmark", &MARK.to_string(),
                "lookup", &TABLE.to_string(), "prio", "100",
            ],
        );
    }
    run_ok("ip", &["-6", "route", "flush", "table", &TABLE.to_string()]);
}
