//! Transparent UDP interception (tproxy mode).
//!
//! A transparent UDP socket with `IP_RECVORIGDSTADDR` receives packets
//! redirected by the rule manager. Each (source, original-destination)
//! pair is a *flow* with idle timeout; each flow owns one tunnel stream
//! carrying u16-framed datagrams:
//!
//!   client -> server: [u16 len]["ip:port" of original dst][u16 len][datagram]...
//!   server -> client: [u16 len][datagram]...
//!
//! On the server, `UdpFramedStream` reads the first frame (destination),
//! then exchanges datagrams with a plain UDP socket bound to it.

use std::os::unix::io::AsRawFd;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::{Buf, BufMut, BytesMut};
use log::{debug, info, warn};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
    sync::mpsc,
};

use crate::{
    connector::DirectConnector,
    dns::FakeIpMap,
    routing::{Action, RoutingEngine, Target},
    socks5::proto::Addr,
};

pub const UDP_MAGIC_HOST: &[u8] = b"magicalane-udp";
pub const UDP_MAGIC_PORT: u16 = 1;

pub fn magic_addr() -> crate::socks5::proto::Addr {
    crate::socks5::proto::Addr::DomainName(UDP_MAGIC_HOST.to_vec(), UDP_MAGIC_PORT)
}

const FLOW_IDLE: Duration = Duration::from_secs(60);
const MAX_DGRAM: usize = 65507;
/// Hard cap on concurrent UDP flows. Legitimate LAN usage is hundreds
/// (every device's QUIC/HTTP3, DNS, games); anything past a few
/// thousand is a runaway class (e.g. a self-relaying loop) — dropping
/// new flows bounds the damage instead of eating every fd and ~2GB of
/// heap like the 2026-10 production storm (issue #23).
const MAX_FLOWS: usize = 4096;

// ---------------------------------------------------------------- local nets

/// The directed-broadcast address of one IPv4 interface, or None.
/// Pure core of the getifaddrs walk (unit-tested):
/// - if the interface is a broadcast interface (IFF_BROADCAST) and the
///   kernel provides `ifa_broadaddr`, use it;
/// - else compute `addr | !netmask` - but only for prefixes shorter
///   than /31: on an RFC 3021 `/31` the computation yields the PEER
///   address, not a broadcast (dropping it would break the link), and
///   a `/32` has no broadcast at all (the guard skips it too).
fn broadcast_for(
    addr: Ipv4Addr,
    mask: u32,
    flags: u32,
    broadaddr: Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    const IFF_BROADCAST: u32 = libc::IFF_BROADCAST as u32;
    let prefix_hosts = !mask; // 255 for /24, 1 for /31, 0 for /32
    if prefix_hosts <= 1 {
        return None; // /31 (peer) and /32 (host) have no broadcast
    }
    if flags & IFF_BROADCAST != 0 {
        if let Some(b) = broadaddr {
            return Some(b);
        }
    }
    let computed = Ipv4Addr::from(u32::from(addr) | !mask);
    (computed != addr).then_some(computed)
}

/// Enumerate local interface addresses via getifaddrs(3): every IP plus
/// each IPv4 subnet's directed-broadcast address. FAILS CLOSED: an
/// enumeration error propagates to the caller (the interceptor refuses
/// to start) - with an empty list the self-destination guard could
/// never match, and the self-relay storm would be back.
pub fn local_nets() -> io::Result<(Vec<IpAddr>, Vec<Ipv4Addr>)> {
    let mut ips = Vec::new();
    let mut broadcasts = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                        ips.push(IpAddr::V4(ip));
                        let mask = if !ifa.ifa_netmask.is_null() {
                            let nm = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                            u32::from_be(nm.sin_addr.s_addr)
                        } else {
                            0
                        };
                        // The broadcast/dst union member differs by
                        // platform: glibc exposes the raw union as
                        // `ifa_ifu` (broadcast iff IFF_BROADCAST, else a
                        // p2p dst), while macOS/BSD libc expose
                        // `ifa_dstaddr` directly. Same IFF_BROADCAST
                        // guard applies on both.
                        #[cfg(target_os = "linux")]
                        let broad_or_dst: *mut libc::sockaddr = ifa.ifa_ifu;
                        #[cfg(not(target_os = "linux"))]
                        let broad_or_dst: *mut libc::sockaddr = ifa.ifa_dstaddr;
                        let broad = if !broad_or_dst.is_null()
                            && ifa.ifa_flags as u32 & (libc::IFF_BROADCAST as u32) != 0
                            && (*broad_or_dst).sa_family as i32 == libc::AF_INET
                        {
                            let ba = &*(broad_or_dst as *const libc::sockaddr_in);
                            Some(Ipv4Addr::from(u32::from_be(ba.sin_addr.s_addr)))
                        } else {
                            None
                        };
                        if let Some(b) = broadcast_for(ip, mask, ifa.ifa_flags as u32, broad) {
                            broadcasts.push(b);
                        }
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        ips.push(IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    Ok((ips, broadcasts))
}

/// Why a datagram was refused at interception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropReason {
    /// dst is (a local IP, our own listen port): relaying it means the
    /// direct/tunnel sender targets our own interceptor → infinite
    /// self-relay chain (each hop = new flow, new fd, 64KiB buffer).
    SelfDestined,
    /// multicast / (directed-)broadcast dst: never legitimate to relay
    /// (connect() to broadcast fails EPERM anyway — the old behavior
    /// minted a doomed flow task per LAN mDNS packet, forever).
    NonUnicast,
    /// flow table full (MAX_FLOWS): refuse new flows, keep existing.
    FlowCap,
}

impl DropReason {
    fn as_str(self) -> &'static str {
        match self {
            DropReason::SelfDestined => "self-destined",
            DropReason::NonUnicast => "non-unicast",
            DropReason::FlowCap => "flow-cap",
        }
    }
}

/// Pure decision core (unit-tested): should a datagram with original
/// destination `dst` be dropped instead of becoming a flow? `existing`
/// says whether a flow for this (src,dst) key already exists — the
/// flow cap only refuses NEW flows, so a full table never starves
/// established sessions (they keep renewing; the idle reaper trims).
fn drop_reason(
    dst: &SocketAddr,
    listen_port: u16,
    local_ips: &[IpAddr],
    broadcasts: &[Ipv4Addr],
    existing: bool,
    flows_len: usize,
) -> Option<DropReason> {
    let ip = dst.ip();
    if dst.port() == listen_port && local_ips.contains(&ip) {
        return Some(DropReason::SelfDestined);
    }
    if ip.is_multicast()
        || ip == IpAddr::V4(Ipv4Addr::BROADCAST)
        || matches!(ip, IpAddr::V4(v4) if broadcasts.contains(&v4))
    {
        return Some(DropReason::NonUnicast);
    }
    if !existing && flows_len >= MAX_FLOWS {
        return Some(DropReason::FlowCap);
    }
    None
}

// ---------------------------------------------------------------- raw recvmsg

/// Receive one datagram with MSG_DONTWAIT, returning (n, src, orig_dst).
/// The original destination comes from the IP_RECVORIGDSTADDR cmsg.
fn recvmsg_origdst(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut cmsg_space = [0u8; 128];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = &mut name as *mut _ as *mut libc::c_void;
    hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = cmsg_space.len() as _;
    let n = unsafe { libc::recvmsg(fd, &mut hdr, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let src = match name.ss_family as i32 {
        libc::AF_INET => {
            let sin = unsafe { *(&name as *const _ as *const libc::sockaddr_in) };
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))),
                u16::from_be(sin.sin_port),
            )
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { *(&name as *const _ as *const libc::sockaddr_in6) };
            SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)),
                u16::from_be(sin6.sin6_port),
            )
        }
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported, "non-ip udp")),
    };
    // cmsg walk: IP_RECVORIGDSTADDR (v4) / IPV6_RECVORIGDSTADDR (v6);
    // data = sockaddr_in / sockaddr_in6 (the original destination).
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
    let mut dst = None;
    unsafe {
        let mut ptr = libc::CMSG_FIRSTHDR(&hdr);
        while !ptr.is_null() {
            let cmsg = &*ptr;
            if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == IP_RECVORIGDSTADDR {
                let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let sin = &*data;
                dst = Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))),
                    u16::from_be(sin.sin_port),
                ));
            }
            if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == IPV6_RECVORIGDSTADDR {
                let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let sin6 = &*data;
                dst = Some(SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)),
                    u16::from_be(sin6.sin6_port),
                ));
            }
            ptr = libc::CMSG_NXTHDR(&hdr, ptr);
        }
    }
    let dst = dst.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no orig dst cmsg"))?;
    Ok((n as usize, src, dst))
}

// ---------------------------------------------------------------- client side

type FlowKey = (SocketAddr, SocketAddr);

pub struct UdpInterceptor {
    sock: Arc<UdpSocket>,
    flows: StdMutex<HashMap<FlowKey, mpsc::Sender<Vec<u8>>>>,
    last_used: StdMutex<HashMap<FlowKey, Instant>>,
    /// Our own listen port + the host's addresses: datagrams addressed
    /// to (local ip, this port) are aimed at the interceptor itself and
    /// must be dropped, never relayed (self-relay storm, issue #23).
    listen_port: u16,
    /// Whether this is the v6 sibling (filters refreshed snapshots).
    v6: bool,
    /// Live local-address snapshot. Refreshed by the idle-reaper task
    /// (every FLOW_IDLE/2) so DHCP renewals, reconfigurations, and v6
    /// temporary-address rotation keep the self-destination guard
    /// valid for the process lifetime — a bind-time-only snapshot
    /// would silently stop matching new local addresses (review).
    local_ips: StdMutex<Vec<IpAddr>>,
    /// Directed-broadcast addresses of local subnets (drop, never relay).
    broadcasts: StdMutex<Vec<Ipv4Addr>>,
    /// Drops per reason since process start (for rate-limited logging).
    dropped: StdMutex<[u64; 3]>,
}

impl UdpInterceptor {
    /// Re-enumerate local interfaces and swap the snapshots in place.
    /// Called at bind time and by the reaper loop; on enumeration
    /// failure keeps the previous snapshot (stale beats empty — an
    /// empty list would disable the self-destination guard).
    fn refresh_local_nets(&self) {
        let (ips, broadcasts) = match local_nets() {
            Ok(v) => v,
            Err(err) => {
                warn!("udp: local interface refresh failed, keeping snapshot: {err}");
                return;
            }
        };
        if self.v6 {
            *self.local_ips.lock().unwrap() = ips.into_iter().filter(|ip| ip.is_ipv6()).collect();
        } else {
            *self.local_ips.lock().unwrap() = ips;
            *self.broadcasts.lock().unwrap() = broadcasts;
        }
    }

    /// Classify `dst` for a datagram whose flow key exists per
    /// `existing`; on drop, log rate-limited (first, then every 1000th)
    /// and return the reason.
    fn consider(&self, dst: &SocketAddr, existing: bool) -> Option<DropReason> {
        let flows_len = self.flows.lock().unwrap().len();
        let local_ips = self.local_ips.lock().unwrap();
        let broadcasts = self.broadcasts.lock().unwrap();
        let reason = drop_reason(
            dst,
            self.listen_port,
            &local_ips,
            &broadcasts,
            existing,
            flows_len,
        )?;
        let idx = match reason {
            DropReason::SelfDestined => 0,
            DropReason::NonUnicast => 1,
            DropReason::FlowCap => 2,
        };
        let mut dropped = self.dropped.lock().unwrap();
        dropped[idx] += 1;
        if dropped[idx] == 1 || dropped[idx] % 1000 == 0 {
            warn!(
                "udp: dropped {} datagram to {dst} (total {})",
                reason.as_str(),
                dropped[idx]
            );
        }
        Some(reason)
    }
}

pub fn bind_client(port: u16) -> io::Result<Arc<UdpInterceptor>> {
    const IP_TRANSPARENT: libc::c_int = 19;
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;
    unsafe {
        for opt in [IP_TRANSPARENT, IP_RECVORIGDSTADDR] {
            let rc = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                opt,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if rc != 0 {
                warn!(
                    "udp: setsockopt {opt} failed: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    socket.bind(&addr.into())?;
    let sock = Arc::new(UdpSocket::from_std(socket.into())?);
    info!("udp interceptor listening on {addr}");
    // fail closed: without the address list the self-destination guard
    // cannot work (self-relay storm, issue #23)
    let int = UdpInterceptor {
        sock,
        flows: StdMutex::new(HashMap::new()),
        last_used: StdMutex::new(HashMap::new()),
        listen_port: port,
        v6: false,
        local_ips: StdMutex::new(Vec::new()),
        broadcasts: StdMutex::new(Vec::new()),
        dropped: StdMutex::new([0; 3]),
    };
    int.refresh_local_nets();
    if int.local_ips.lock().unwrap().is_empty() {
        return Err(io::Error::other(
            "local interface enumeration returned no addresses",
        ));
    }
    Ok(Arc::new(int))
}

/// v6 sibling of `bind_client` (IPV6_TRANSPARENT + IPV6_RECVORIGDSTADDR,
/// v6-only socket so v4 traffic keeps using the v4 interceptor). Listens
/// on port+1: two REUSEADDR sockets on the same wildcard port confuse
/// the kernel's TPROXY socket lookup.
pub fn bind_client_v6(port: u16) -> io::Result<Arc<UdpInterceptor>> {
    // Listen on port+1: two REUSEADDR sockets on the same wildcard port
    // break the kernel TPROXY socket lookup (packets queue silently).
    let port = port + 1;
    const IPV6_TRANSPARENT: libc::c_int = 72;
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;
    unsafe {
        for opt in [IPV6_TRANSPARENT, IPV6_RECVORIGDSTADDR, libc::IPV6_V6ONLY] {
            let rc = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                opt,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if rc != 0 {
                warn!(
                    "udp6: setsockopt {opt} failed: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }
    let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port);
    socket.bind(&addr.into())?;
    let sock = Arc::new(UdpSocket::from_std(socket.into())?);
    info!("udp6 interceptor listening on {addr}");
    let int = UdpInterceptor {
        sock,
        flows: StdMutex::new(HashMap::new()),
        last_used: StdMutex::new(HashMap::new()),
        listen_port: port,
        v6: true,
        local_ips: StdMutex::new(Vec::new()),
        broadcasts: StdMutex::new(Vec::new()),
        dropped: StdMutex::new([0; 3]),
    };
    int.refresh_local_nets();
    // A v6-only host (no v6 addresses at all) still binds — v4 traffic
    // uses the v4 interceptor; the v6 self-destined guard simply has
    // nothing to match.
    Ok(Arc::new(int))
}

impl UdpInterceptor {
    async fn recv_one(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        use tokio::io::Interest;
        loop {
            self.sock.readable().await?;
            let fd = self.sock.as_raw_fd();
            // try_io clears the readiness flag when the raw recvmsg
            // reports WouldBlock — a bare readable()+recvmsg loop spins
            // forever on stale readiness (TPROXY sockets especially).
            let sock = &*self.sock;
            match sock.try_io(Interest::READABLE, || recvmsg_origdst(fd, buf)) {
                Ok(v) => return Ok(v),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Err(err),
            }
        }
    }
}

/// Everything the UDP path needs to route a datagram flow.
#[derive(Clone)]
pub struct UdpRouter {
    pub fake_map: Arc<FakeIpMap>,
    pub routing: Arc<RoutingEngine>,
    pub direct: DirectConnector,
}

/// Serve intercepted UDP until the socket dies.
pub async fn serve_client(
    interceptor: Arc<UdpInterceptor>,
    pool: crate::tunnel::ProxyPool,
    router: UdpRouter,
) {
    let sock = interceptor.sock.clone();
    let reaper = Arc::downgrade(&interceptor);
    tokio::spawn(async move {
        // idle flow reaper + local-interface refresher
        loop {
            tokio::time::sleep(FLOW_IDLE / 2).await;
            let Some(int) = reaper.upgrade() else { break };
            let now = Instant::now();
            int.flows.lock().unwrap().retain(|k, _| {
                int.last_used
                    .lock()
                    .unwrap()
                    .get(k)
                    .map(|t| now.duration_since(*t) < FLOW_IDLE)
                    .unwrap_or(false)
            });
            int.last_used
                .lock()
                .unwrap()
                .retain(|_, t| now.duration_since(*t) < FLOW_IDLE * 2);
            // Keep the self-destination guard valid for the process
            // lifetime: local addresses change (DHCP, reconfiguration,
            // v6 temporary-address rotation) and a bind-time-only
            // snapshot would silently stop matching new ones (review).
            int.refresh_local_nets();
        }
    });

    let mut buf = vec![0u8; 65536];
    loop {
        let (n, src, dst) = match interceptor.recv_one(&mut buf).await {
            Ok(v) => v,
            Err(err) => {
                warn!("udp recv error: {err}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let key = (src, dst);
        // Flow-table lookup first: whether this datagram belongs to an
        // EXISTING flow decides the flow-cap question (the cap refuses
        // only new flows — a full table must not starve established
        // sessions; the idle reaper trims them).
        let sender = {
            let flows = interceptor.flows.lock().unwrap();
            match flows.get(&key) {
                Some(tx) => tx.clone(),
                None => {
                    // New flow: refuse datagrams that must never become
                    // one — self-destined (addressed to this interceptor;
                    // relaying = infinite loop, each hop a new task + fd
                    // + 64KiB buffer until fd exhaustion — the production
                    // GB/day RSS ratchet, issue #23), non-unicast, and
                    // beyond the flow cap. Checked BEFORE any map insert
                    // so a dropped class leaves no state behind.
                    // (Self/non-unicast also apply to existing flows:
                    // such a flow can never legitimately exist.)
                    drop(flows);
                    if interceptor.consider(&dst, false).is_some() {
                        continue;
                    }
                    let mut flows = interceptor.flows.lock().unwrap();
                    if let Some(tx) = flows.get(&key) {
                        // raced in while unlocked: treat as existing
                        tx.clone()
                    } else {
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
                        let pool = pool.clone();
                        let sock = sock.clone();
                        let router = router.clone();
                        tokio::spawn(flow_task(key, rx, pool, sock, router));
                        flows.insert(key, tx.clone());
                        tx
                    }
                }
            }
        };
        interceptor
            .last_used
            .lock()
            .unwrap()
            .insert(key, Instant::now());
        let payload = buf[..n].to_vec();
        if sender.try_send(payload).is_err() {
            // flow is backed up or gone; drop the flow (will be recreated)
            interceptor.flows.lock().unwrap().remove(&key);
        }
    }
}

async fn flow_task(
    key: (SocketAddr, SocketAddr),
    rx: mpsc::Receiver<Vec<u8>>,
    pool: crate::tunnel::ProxyPool,
    sock: Arc<UdpSocket>,
    router: UdpRouter,
) {
    let (src, dst) = key;
    // Fake tokens map back to domains; then the rules decide the path.
    let (target, decision) = if let Some(domain) = router.fake_map.lookup(dst.ip()) {
        debug!("udp: fake {} -> {domain}", dst.ip());
        let decision = router.routing.decide(Target::Domain(&domain));
        (Addr::DomainName(domain.into_bytes(), dst.port()), decision)
    } else {
        let decision = router.routing.decide(Target::Ip(dst.ip()));
        (Addr::SocketAddr(dst), decision)
    };

    match decision.action {
        Action::Direct => {
            udp_direct_flow(src, dst, target, rx, sock, router.direct).await;
        }
        Action::Proxy => {
            udp_tunnel_flow(src, dst, target, rx, pool, decision.server, sock).await;
        }
    }
}

/// Direct path: resolve locally (marked probe) + a marked UDP socket,
/// relaying datagrams without touching the tunnel.
async fn udp_direct_flow(
    src: SocketAddr,
    dst: SocketAddr,
    target: Addr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    sock: Arc<UdpSocket>,
    direct: DirectConnector,
) {
    let addrs: Vec<SocketAddr> = match &target {
        Addr::SocketAddr(a) => vec![*a],
        Addr::DomainName(host, port) => {
            let host = String::from_utf8_lossy(host).into_owned();
            match direct.resolve(&host, *port).await {
                Ok(a) => a
                    .into_iter()
                    .map(|a| SocketAddr::new(a.ip(), *port))
                    .collect(),
                Err(err) => {
                    debug!("udp direct {host} resolve failed: {err}");
                    return;
                }
            }
        }
    };
    let first = match addrs.first() {
        Some(a) => *a,
        None => return,
    };
    let bind: SocketAddr = if first.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    // Marked socket: the interception rules must pass direct UDP.
    let out = match crate::connector::udp_socket_marked(bind).await {
        Ok(s) => s,
        Err(err) => {
            debug!("udp direct bind failed: {err}");
            return;
        }
    };
    if let Err(err) = out.connect(first).await {
        debug!("udp direct connect {first} failed: {err}");
        return;
    }
    debug!("udp flow {dst}: direct via {first}");

    let mut recv_buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(dg) = maybe else { break };
                if out.send(&dg).await.is_err() {
                    break;
                }
            }
            read = out.recv(&mut recv_buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = sock.send_to(&recv_buf[..n], src).await;
                    }
                }
            }
        }
    }
    debug!("udp direct flow {src} -> {dst} ended");
}

/// Tunnel path: unchanged framing, but the destination frame can be a
/// domain (the server resolves it server-side).
async fn udp_tunnel_flow(
    src: SocketAddr,
    dst: SocketAddr,
    target: Addr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    pool: crate::tunnel::ProxyPool,
    server: Option<std::sync::Arc<str>>,
    sock: Arc<UdpSocket>,
) {
    let mut stream = match pool.connect(server.as_deref(), magic_addr(), None).await {
        Ok(s) => s,
        Err(err) => {
            debug!("udp flow to {dst} connect failed: {err}");
            return;
        }
    };
    // first frame: destination as ascii (ip:port or domain:port)
    let dst_ascii = match &target {
        Addr::SocketAddr(a) => format!("{a}"),
        Addr::DomainName(host, port) => {
            format!("{}:{port}", String::from_utf8_lossy(host))
        }
    };
    let mut hello = Vec::with_capacity(2 + dst_ascii.len());
    hello.put_u16(dst_ascii.len() as u16);
    hello.extend_from_slice(dst_ascii.as_bytes());
    if stream.write_all(&hello).await.is_err() {
        return;
    }
    let _ = stream.flush().await;

    let mut read_buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            Some(dg) = rx.recv() => {
                let mut frame = Vec::with_capacity(2 + dg.len());
                frame.put_u16(dg.len() as u16);
                frame.extend_from_slice(&dg);
                if stream.write_all(&frame).await.is_err() {
                    break;
                }
            }
            read = stream.read(&mut read_buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // response frames: [u16 len][datagram] - may coalesce
                        let mut pending = &read_buf[..n];
                        while pending.len() >= 2 {
                            let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                            if pending.len() < 2 + len {
                                break; // partial frame; wait for more
                            }
                            let dg = &pending[2..2 + len];
                            let _ = sock.send_to(dg, src).await;
                            pending = &pending[2 + len..];
                        }
                    }
                }
            }
        }
    }
    debug!("udp flow {src} -> {dst} ended");
}

// ---------------------------------------------------------------- server side

/// Server-side UDP relay "connection": reads the destination from the
/// first frame, then pipes u16-framed datagrams to/from that address.
pub struct UdpFramedStream {
    wbuf: BytesMut,
    rbuf: BytesMut,
    dst: Option<SocketAddr>,
    sock: Option<std::sync::Arc<UdpSocket>>,
    /// datagrams to send upstream (populated by poll_write, drained in poll_flush)
    outq: Vec<Vec<u8>>,
    read_pending: Option<tokio::task::JoinHandle<io::Result<Vec<u8>>>>,
    /// Domain dst being resolved (fake-IP flows carry domains).
    pending_resolve: Option<tokio::task::JoinHandle<io::Result<SocketAddr>>>,
}

impl UdpFramedStream {
    pub fn new() -> Self {
        Self {
            wbuf: BytesMut::new(),
            rbuf: BytesMut::new(),
            dst: None,
            sock: None,
            outq: Vec::new(),
            read_pending: None,
            pending_resolve: None,
        }
    }

    /// Parse complete frames from wbuf; first frame sets the destination.
    fn drain_wbuf(&mut self) {
        while self.wbuf.len() >= 2 {
            let len = u16::from_be_bytes([self.wbuf[0], self.wbuf[1]]) as usize;
            if self.wbuf.len() < 2 + len {
                break;
            }
            let mut frame = self.wbuf.split_to(2 + len);
            frame.advance(2);
            let payload = frame.to_vec();
            if self.dst.is_none() && self.pending_resolve.is_none() {
                let text = String::from_utf8_lossy(&payload).to_string();
                match text.parse::<SocketAddr>() {
                    Ok(a) => {
                        self.dst = Some(a);
                        info!("udp relay flow to {a}");
                    }
                    Err(_) => {
                        // domain:port — resolve server-side; datagrams
                        // arriving meanwhile stay buffered in outq.
                        info!("udp relay flow to {text} (resolving)");
                        self.pending_resolve = Some(tokio::spawn(async move {
                            let addr = tokio::net::lookup_host(&text)
                                .await
                                .map_err(|e| io::Error::other(e.to_string()))?
                                .next()
                                .ok_or_else(|| {
                                    io::Error::new(io::ErrorKind::NotFound, "no addr")
                                })?;
                            Ok(addr)
                        }));
                    }
                }
            } else if payload.len() <= MAX_DGRAM {
                self.outq.push(payload);
            }
        }
    }

    /// Poll a pending domain resolution to completion.
    fn poll_resolve(&mut self, cx: &mut Context<'_>) {
        if let Some(handle) = self.pending_resolve.as_mut() {
            if let std::task::Poll::Ready(res) =
                std::future::Future::poll(std::pin::Pin::new(handle), cx)
            {
                self.pending_resolve = None;
                match res {
                    Ok(Ok(a)) => {
                        info!("udp relay domain resolved: {a}");
                        self.dst = Some(a);
                    }
                    Ok(Err(e)) => warn!("udp relay domain resolve failed: {e}"),
                    Err(e) => warn!("udp relay resolve task: {e}"),
                }
            }
        }
    }
}

impl Default for UdpFramedStream {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpFramedStream {
    /// Try to push queued upstream datagrams out; returns Ok(true) if all
    /// sent, Ok(false) if the socket is currently full.
    fn flush_outq(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        while let Some(dst) = self.dst {
            let Some(sock) = self.sock.clone() else { break };
            let Some(dg) = self.outq.first().cloned() else {
                break;
            };
            match sock.try_send_to(&dg, dst) {
                Ok(_) => {
                    self.outq.remove(0);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let waker = cx.waker().clone();
                    tokio::spawn(async move {
                        let _ = sock.writable().await;
                        waker.wake();
                    });
                    return Ok(false);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    fn bind_socket(&mut self) -> io::Result<std::sync::Arc<UdpSocket>> {
        if let Some(s) = &self.sock {
            return Ok(s.clone());
        }
        let std_sock = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
        std_sock.set_nonblocking(true)?;
        let sock = std::sync::Arc::new(UdpSocket::from_std(std_sock)?);
        self.sock = Some(sock.clone());
        Ok(sock)
    }
}

impl AsyncRead for UdpFramedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.drain_wbuf();
        self.poll_resolve(cx);
        if let Err(e) = self.flush_outq(cx) {
            return Poll::Ready(Err(e));
        }

        loop {
            if self.rbuf.has_remaining() {
                let n = self.rbuf.remaining().min(buf.remaining());
                let data = self.rbuf.split_to(n);
                buf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            if self.read_pending.is_none() {
                let Some(_dst) = self.dst else {
                    return Poll::Pending; // client has not sent dst yet
                };
                let sock = match self.bind_socket() {
                    Ok(s) => s,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                // The socket just came into existence (possibly after an
                // async dst resolution): flush anything buffered in outq
                // NOW or single-datagram flows deadlock (the top-level
                // flush ran before bind, and no further writes may come).
                if let Err(e) = self.flush_outq(cx) {
                    return Poll::Ready(Err(e));
                }
                self.read_pending = Some(tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    let (n, _) = tokio::time::timeout(FLOW_IDLE, sock.recv_from(&mut b))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "udp idle"))??;
                    b.truncate(n);
                    Ok(b)
                }));
            }
            match self.read_pending.as_mut() {
                Some(handle) => {
                    match std::future::Future::poll(std::pin::Pin::new(handle), cx) {
                        std::task::Poll::Ready(Ok(Ok(dg))) => {
                            self.read_pending = None;
                            self.rbuf.put_u16(dg.len() as u16);
                            self.rbuf.extend_from_slice(&dg);
                            // loop to deliver from rbuf
                        }
                        std::task::Poll::Ready(Ok(Err(e))) => {
                            self.read_pending = None;
                            return Poll::Ready(Err(e));
                        }
                        std::task::Poll::Ready(Err(e)) => {
                            self.read_pending = None;
                            return Poll::Ready(Err(io::Error::other(e)));
                        }
                        std::task::Poll::Pending => return Poll::Pending,
                    }
                }
                None => unreachable!(),
            }
        }
    }
}

impl AsyncWrite for UdpFramedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.wbuf.extend_from_slice(buf);
        this.drain_wbuf();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.drain_wbuf();
        this.poll_resolve(cx);
        match this.flush_outq(cx) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_ips() -> Vec<IpAddr> {
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 89, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6("fd00::1".parse().unwrap()),
        ]
    }

    fn broadcasts() -> Vec<Ipv4Addr> {
        vec![
            Ipv4Addr::new(10, 89, 0, 255),
            Ipv4Addr::new(192, 168, 0, 255),
        ]
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Regression (2026-10-13, issue #23): a datagram addressed to our
    /// own interceptor port on a local IP used to be relayed "direct"
    /// back to the same port — a self-sustaining chain that minted a
    /// flow task (fd + 64KiB buffer) per hop until fd exhaustion,
    /// ~28k hops per storm, GBs of transient heap retained by glibc
    /// arenas. It must be dropped at interception instead.
    #[test]
    fn self_destined_datagram_is_dropped() {
        let ips = local_ips();
        let bcasts = broadcasts();
        // our port on our IP (the storm case, v4 and v6)
        assert_eq!(
            drop_reason(&sa("10.89.0.5:7896"), 7896, &ips, &bcasts, false, 0),
            Some(DropReason::SelfDestined)
        );
        assert_eq!(
            drop_reason(&sa("[fd00::1]:7896"), 7896, &ips, &bcasts, false, 0),
            Some(DropReason::SelfDestined)
        );
        // same IP but a different port = some other local service:
        // relaying to it is legitimate (hairpin to the LAN web UI etc.)
        assert_eq!(
            drop_reason(&sa("10.89.0.5:80"), 7896, &ips, &bcasts, false, 0),
            None
        );
        // our port on a foreign IP = an upstream service that happens to
        // use the same port number; must NOT be dropped
        assert_eq!(
            drop_reason(&sa("8.8.8.8:7896"), 7896, &ips, &bcasts, false, 0),
            None
        );
    }

    /// Regression (issue #23 acceptance): LAN mDNS/WSD broadcast and
    /// multicast datagrams must never become flows — the old code
    /// spawned a doomed direct flow per packet (connect to broadcast =
    /// EPERM, retried every packet forever: "udp direct connect
    /// 192.168.0.255:5353 failed" every ~5s in production logs).
    #[test]
    fn broadcast_and_multicast_are_dropped() {
        let ips = local_ips();
        let bcasts = broadcasts();
        for dst in [
            "224.0.0.251:5353",      // mDNS multicast
            "239.255.255.250:1900",  // SSDP multicast
            "255.255.255.255:58866", // limited broadcast
            "192.168.0.255:5353",    // directed broadcast (prod case)
            "10.89.0.255:5353",      // directed broadcast, other subnet
            "[ff02::fb]:5353",       // mDNS v6 multicast
        ] {
            assert_eq!(
                drop_reason(&sa(dst), 7896, &ips, &bcasts, false, 0),
                Some(DropReason::NonUnicast),
                "{dst} must be dropped as non-unicast"
            );
        }
        // plain unicast passes
        assert_eq!(
            drop_reason(&sa("1.1.1.1:53"), 7896, &ips, &bcasts, false, 0),
            None
        );
    }

    /// Regression (issue #23 review): the flow cap must only refuse NEW
    /// flows — established flows keep renewing so a full table never
    /// starves active sessions until the reaper trims.
    #[test]
    fn flow_cap_refuses_only_new_flows() {
        let ips = local_ips();
        let bcasts = broadcasts();
        assert_eq!(
            drop_reason(&sa("1.1.1.1:53"), 7896, &ips, &bcasts, false, MAX_FLOWS),
            Some(DropReason::FlowCap),
            "new flow at cap must be refused"
        );
        assert_eq!(
            drop_reason(&sa("1.1.1.1:53"), 7896, &ips, &bcasts, true, MAX_FLOWS),
            None,
            "existing flow at cap must keep flowing"
        );
        assert_eq!(
            drop_reason(&sa("1.1.1.1:53"), 7896, &ips, &bcasts, false, MAX_FLOWS - 1),
            None
        );
        // self-destined wins even when there is flow budget left
        assert_eq!(
            drop_reason(&sa("10.89.0.5:7896"), 7896, &ips, &bcasts, false, 0),
            Some(DropReason::SelfDestined)
        );
        // ...and regardless of existence (such a flow must never live)
        assert_eq!(
            drop_reason(&sa("10.89.0.5:7896"), 7896, &ips, &bcasts, true, 0),
            Some(DropReason::SelfDestined)
        );
    }

    /// Regression (issue #23 review): the directed-broadcast derivation
    /// must not misclassify RFC 3021 /31 peers (or /32 hosts) as
    /// broadcasts — that would DROP legitimate point-to-point traffic.
    #[test]
    fn broadcast_for_handles_rfc3021_and_host_routes() {
        use std::net::Ipv4Addr as I4;
        // /24: classic directed broadcast
        assert_eq!(
            broadcast_for(
                I4::new(192, 168, 0, 1),
                u32::from(I4::new(255, 255, 255, 0)),
                0,
                None
            ),
            Some(I4::new(192, 168, 0, 255))
        );
        // /31 (RFC 3021 point-to-point): addr|!mask is the PEER — never a
        // broadcast, regardless of kernel-provided broadaddr
        assert_eq!(
            broadcast_for(
                I4::new(10, 0, 0, 0),
                u32::from(I4::new(255, 255, 255, 254)),
                0,
                None
            ),
            None
        );
        assert_eq!(
            broadcast_for(
                I4::new(10, 0, 0, 0),
                u32::from(I4::new(255, 255, 255, 254)),
                libc::IFF_BROADCAST as u32,
                Some(I4::new(10, 0, 0, 1))
            ),
            None,
            "/31 must not yield a broadcast even with a bogus broadaddr"
        );
        // /32 host route: no broadcast
        assert_eq!(
            broadcast_for(
                I4::new(10, 0, 0, 5),
                u32::from(I4::new(255, 255, 255, 255)),
                0,
                None
            ),
            None
        );
        // IFF_BROADCAST + kernel broadaddr wins over the computation
        assert_eq!(
            broadcast_for(
                I4::new(10, 1, 0, 1),
                u32::from(I4::new(255, 255, 255, 0)),
                libc::IFF_BROADCAST as u32,
                Some(I4::new(10, 9, 9, 9))
            ),
            Some(I4::new(10, 9, 9, 9))
        );
    }

    /// local_nets parses real interfaces (smoke: loopback must appear).
    #[test]
    fn local_nets_contains_loopback() {
        let (ips, _) = local_nets().expect("getifaddrs must work on this host");
        assert!(
            ips.iter().any(|ip| ip.is_loopback()),
            "no loopback in {ips:?}"
        );
    }

    /// Regression (issue #23 review): the local-address snapshot must be
    /// REFRESHABLE, not bind-time-only — DHCP/reconfiguration/v6
    /// temporary-address rotation add addresses later, and without a
    /// refresh the self-destination guard silently stops matching them
    /// (storm window until MAX_FLOWS). The reaper calls this every
    /// FLOW_IDLE/2; this test pins the refresh mechanism itself.
    #[tokio::test]
    async fn snapshot_refresh_recovers_after_addresses_change() {
        let int = bind_client(0).expect("bind succeeds on a healthy host");
        // simulate an interface change wiping the snapshot
        int.local_ips.lock().unwrap().clear();
        assert!(int.local_ips.lock().unwrap().is_empty());
        int.refresh_local_nets();
        let ips = int.local_ips.lock().unwrap();
        assert!(
            ips.iter().any(|ip| ip.is_loopback()),
            "refresh must repopulate local addresses"
        );
    }

    /// Fail-closed bind (issue #23 review): a healthy host must yield a
    /// non-empty snapshot — the bind errors rather than running blind.
    #[tokio::test]
    async fn bind_fails_closed_without_local_addresses() {
        let int = bind_client(0).expect("bind succeeds on a healthy host");
        assert!(!int.local_ips.lock().unwrap().is_empty());
    }
}
