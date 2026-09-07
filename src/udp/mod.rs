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

// ---------------------------------------------------------------- raw recvmsg

/// Receive one datagram with MSG_DONTWAIT, returning (n, src, orig_dst).
/// The original destination comes from the IP_RECVORIGDSTADDR cmsg.
fn recvmsg_origdst(fd: std::os::unix::io::RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
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
    hdr.msg_controllen = cmsg_space.len();
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
            if cmsg.cmsg_level == libc::SOL_IPV6 && cmsg.cmsg_type == IPV6_RECVORIGDSTADDR {
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
                warn!("udp: setsockopt {opt} failed: {}", io::Error::last_os_error());
            }
        }
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    socket.bind(&addr.into())?;
    let sock = Arc::new(UdpSocket::from_std(socket.into())?);
    info!("udp interceptor listening on {addr}");
    Ok(Arc::new(UdpInterceptor {
        sock,
        flows: StdMutex::new(HashMap::new()),
        last_used: StdMutex::new(HashMap::new()),
    }))
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
                libc::SOL_IPV6,
                opt,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if rc != 0 {
                warn!("udp6: setsockopt {opt} failed: {}", io::Error::last_os_error());
            }
        }
    }
    let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port);
    socket.bind(&addr.into())?;
    let sock = Arc::new(UdpSocket::from_std(socket.into())?);
    info!("udp6 interceptor listening on {addr}");
    Ok(Arc::new(UdpInterceptor {
        sock,
        flows: StdMutex::new(HashMap::new()),
        last_used: StdMutex::new(HashMap::new()),
    }))
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
        // idle flow reaper
        loop {
            tokio::time::sleep(FLOW_IDLE / 2).await;
            let Some(int) = reaper.upgrade() else { break };
            let now = Instant::now();
            int.flows.lock().unwrap().retain(|k, _| {
                
                int
                    .last_used
                    .lock()
                    .unwrap()
                    .get(k)
                    .map(|t| now.duration_since(*t) < FLOW_IDLE)
                    .unwrap_or(false)
            });
            int.last_used.lock().unwrap().retain(|_, t| now.duration_since(*t) < FLOW_IDLE * 2);
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
        interceptor
            .last_used
            .lock()
            .unwrap()
            .insert(key, Instant::now());
        let sender = {
            let mut flows = interceptor.flows.lock().unwrap();
            match flows.get(&key) {
                Some(tx) => tx.clone(),
                None => {
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
                    let pool = pool.clone();
                    let sock = sock.clone();
                    let router = router.clone();
                    tokio::spawn(flow_task(key, rx, pool, sock, router));
                    flows.insert(key, tx.clone());
                    tx
                }
            }
        };
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
                Ok(a) => a.into_iter().map(|a| SocketAddr::new(a.ip(), *port)).collect(),
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
                                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addr"))?;
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
            let Some(dg) = self.outq.first().cloned() else { break };
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

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
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
