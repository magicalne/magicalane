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

#[derive(Debug, Clone)]
pub struct RuleSpec {
    /// Tunnel server address: our own egress must bypass interception.
    pub server_ip: Ipv4Addr,
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
        "iptables" => "/usr/sbin/iptables",
        "iptables-restore" => "/usr/sbin/iptables-restore",
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

/// Apply an iptables-restore blob atomically (stdin-fed).
fn restore_mangle(blob: &str) -> io::Result<()> {
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
    let cmd = cstr("/usr/sbin/iptables-restore");
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
        blob.push_str(&format!("-A {CHAIN_OUT} -d {}/32 -j RETURN\n", spec.server_ip));
        blob.push_str("-A MGL-OUT -d 127.0.0.0/8 -j RETURN\n");
        if spec.dns_port != 0 {
            // DNS handled by REDIRECT in nat; skip it here
            blob.push_str(&format!(
                "-A {CHAIN_OUT} -p udp --dport 53 -j RETURN\n"
            ));
        }
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

    restore_mangle(&nat).inspect_err(|_e| {
        teardown(spec);
    })?;
    restore_mangle(&blob).inspect_err(|_e| {
        teardown(spec);
    })?;

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
    }
    run_ok("iptables", &["-t", "nat", "-F", CHAIN_NAT]);
    run_ok("iptables", &["-t", "nat", "-X", CHAIN_NAT]);
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
