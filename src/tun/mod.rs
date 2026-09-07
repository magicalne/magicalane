//! TUN mode: full transparent interception without iptables.
//!
//! A TUN device (mgl0) plus a default route with the server exception —
//! all IP packets then arrive here and are terminated by an embedded
//! TCP/IP stack (smoltcp):
//!
//! - TCP: each SYN creates a listening socket on the ORIGINAL
//!   destination; the handshake completes in the stack and the
//!   established stream is relayed through the routing engine (fake-IP
//!   domains -> rules -> tunnel or direct) exactly like tproxy mode.
//! - UDP dst:53 (any destination IP): answered locally by the fake-IP
//!   engine — no DNS query ever leaves the host.
//! - other UDP: per-flow sockets relayed through the routing engine
//!   (same tunnel wire format as the tproxy UDP relay).
//!
//! Clean-exit: routes are removed on shutdown; the device itself is
//! destroyed when the process exits (fd lifetime).

pub mod routes;

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::io::{AsRawFd, FromRawFd, RawFd},
    sync::Arc,
    task::{Context, Poll as TaskPoll, Waker},
};

use log::{debug, info, warn};
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{
        tcp::{Socket as TcpSocket, SocketBuffer as TcpBuffer},
        udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket},
    },
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};

use crate::{
    connector::Connector,
    dns,
    proxy::Proxy,
    routing::{Action, Target},
    tproxy::TproxyRouter,
};

pub const TUN_NAME: &str = "mgl0";
pub const TUN_ADDR: &str = "198.18.255.254";
pub const TUN_ADDR6: &str = "fc00:ffff:ffff:fffe::1";

type FlowKey = (SocketAddr, SocketAddr); // (app src, original dst)

// ---------------------------------------------------------------- device

fn open_tun(name: &str) -> io::Result<std::mem::ManuallyDrop<std::fs::File>> {
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // ifreq as raw bytes (field layout varies across libc versions).
    const IFNAMSIZ: usize = 16;
    let mut ifr = [0u8; IFNAMSIZ + 2 + std::mem::size_of::<libc::c_short>()];
    for (i, b) in name.bytes().take(IFNAMSIZ - 1).enumerate() {
        ifr[i] = b;
    }
    // flags: i16 at offset IFNAMSIZ (aligned)
    let flags: i16 = IFF_TUN | IFF_NO_PI;
    ifr[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, ifr.as_mut_ptr()) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(std::mem::ManuallyDrop::new(unsafe {
        std::fs::File::from_raw_fd(fd)
    }))
}

struct TunPhy {
    fd: RawFd,
    rx_queue: Vec<Vec<u8>>,
}

struct PhyRx {
    buf: Vec<u8>,
}
impl RxToken for PhyRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf)
    }
}
struct PhyTx {
    fd: RawFd,
}
impl TxToken for PhyTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let mut off = 0;
        while off < buf.len() {
            let n = unsafe {
                libc::write(self.fd, buf[off..].as_ptr() as *const libc::c_void, buf.len() - off)
            };
            if n <= 0 {
                break; // WouldBlock: drop (TCP retransmits)
            }
            off += n as usize;
        }
        r
    }
}

impl Device for TunPhy {
    type RxToken<'a> = PhyRx;
    type TxToken<'a> = PhyTx;

    fn receive(&mut self, _t: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_queue.is_empty() {
            return None;
        }
        Some((PhyRx { buf: self.rx_queue.remove(0) }, PhyTx { fd: self.fd }))
    }
    fn transmit(&mut self, _t: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(PhyTx { fd: self.fd })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 65535;
        c
    }
}

// ------------------------------------------------------------ byte queue

/// Byte queue with waker for the app-facing read side of TCP flows.
#[derive(Default)]
pub struct ByteQueue {
    q: std::collections::VecDeque<u8>,
    closed: bool,
    waker: Option<Waker>,
}

impl ByteQueue {
    fn push(&mut self, data: &[u8]) {
        self.q.extend(data.iter().copied());
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }
    fn close(&mut self) {
        self.closed = true;
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }
}

/// Async stream bridging an established smoltcp TCP socket to a relay.
pub struct TunStream {
    from_stack: Arc<std::sync::Mutex<ByteQueue>>,
    to_stack: tokio::sync::mpsc::Sender<Vec<u8>>,
    write_space: Arc<Notify>,
}



impl AsyncRead for TunStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> TaskPoll<io::Result<()>> {
        let mut q = self.from_stack.lock().unwrap();
        if q.q.is_empty() {
            if q.closed {
                return TaskPoll::Ready(Ok(()));
            }
            q.waker = Some(cx.waker().clone());
            return TaskPoll::Pending;
        }
        let n = q.q.len().min(buf.remaining());
        let mut tmp = vec![0u8; n];
        for b in tmp.iter_mut() {
            *b = q.q.pop_front().unwrap();
        }
        buf.put_slice(&tmp);
        TaskPoll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> TaskPoll<io::Result<usize>> {
        use tokio::sync::mpsc::error::TrySendError;
        match self.to_stack.try_send(buf.to_vec()) {
            Ok(()) => TaskPoll::Ready(Ok(buf.len())),
            Err(TrySendError::Full(_)) => {
                // Woken by the engine loop after it drains the channel.
                // Re-check after registering interest: notified() future
                // pinned poll is unavailable here, so wake immediately —
                // the engine loop's notify_one() covers the real wakeup.
                self.write_space.notify_one();
                cx.waker().wake_by_ref();
                TaskPoll::Pending
            }
            Err(TrySendError::Closed(_)) => TaskPoll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tun stack gone",
            ))),
        }
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> TaskPoll<io::Result<()>> {
        TaskPoll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> TaskPoll<io::Result<()>> {
        TaskPoll::Ready(Ok(()))
    }
}

struct TcpFlow {
    handle: SocketHandle,
    dst: SocketAddr,
    from_stack: Arc<std::sync::Mutex<ByteQueue>>,
    to_stack: tokio::sync::mpsc::Receiver<Vec<u8>>,
    write_space: Arc<Notify>,
}

struct UdpFlow {
    handle: SocketHandle,
    /// datagrams from the app (tapped) -> relay task
    to_relay: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// datagrams from the relay -> stack
    from_relay: tokio::sync::mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    last_seen: std::time::Instant,
}

// ---------------------------------------------------------------- serve

pub async fn serve(
    pool: crate::tunnel::ProxyPool,
    router: TproxyRouter,
    bandwidth: usize,
    server_ips: Vec<Ipv4Addr>,
) -> anyhow::Result<()> {
    let _file = open_tun(TUN_NAME)?;
    let fd = _file.as_raw_fd();
    routes::tun_apply(TUN_NAME, TUN_ADDR, TUN_ADDR6, &server_ips)?;
    info!("tun: {TUN_NAME} up ({TUN_ADDR}/{TUN_ADDR6}); default route via {TUN_NAME}");

    let async_fd = tokio::io::unix::AsyncFd::new(unsafe { std::fs::File::from_raw_fd(libc::dup(fd)) })?;
    let mut phy = TunPhy { fd, rx_queue: Vec::new() };

    let cfg = IfaceConfig::new(HardwareAddress::Ip);
    let mut iface = Interface::new(cfg, &mut phy, smoltcp::time::Instant::from_millis(0));
    iface.update_ip_addrs(|a| {
        a.push(IpCidr::new(IpAddress::Ipv4(Ipv4Addr::new(198, 18, 255, 254)), 32)).ok();
        a.push(IpCidr::new(
            IpAddress::Ipv6("fc00:ffff:ffff:fffe::1".parse::<Ipv6Addr>().unwrap()),
            128,
        ))
        .ok();
    });
    // Accept packets addressed to ANY destination (we ARE the router).
    iface.set_any_ip(true);

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_flows: HashMap<FlowKey, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<FlowKey, UdpFlow> = HashMap::new();
    let fake_map = router.fake_map.clone();

    let mut tick: u64 = 0;
    loop {
        // ---- input: TUN readable (packets) — everything else rides the
        // 20ms tick (channel drains, timers, maintenance).
        {
            let mut pending: Vec<Vec<u8>> = Vec::new();
            tokio::select! {
                ready = async_fd.readable() => {
                    let mut guard = match ready {
                        Ok(g) => g,
                        Err(e) => return Err(anyhow::anyhow!("tun fd: {}", e)),
                    };
                    loop {
                        let mut buf = vec![0u8; 65535];
                        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                        if n <= 0 {
                            break;
                        }
                        buf.truncate(n as usize);
                        pending.push(buf);
                    }
                    guard.clear_ready();
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
            for pkt in pending {
                dispatch_ingress(
                    &pkt,
                    &mut phy,
                    &mut sockets,
                    &mut tcp_flows,
                    &mut udp_flows,
                    &fake_map,
                    &router,
                    &pool,
                    bandwidth,
                );
            }
        }

        // ---- pump app->stack channel data into TCP sockets
        let keys: Vec<FlowKey> = tcp_flows.keys().cloned().collect();
        for k in keys {
            let Some(flow) = tcp_flows.get_mut(&k) else { continue };
            let mut woke = false;
            while let Ok(data) = flow.to_stack.try_recv() {
                let sock = sockets.get_mut::<TcpSocket>(flow.handle);
                if sock.can_send() {
                    if sock.send_slice(&data).is_err() {
                        break;
                    }
                    woke = true;
                } else {
                    // socket send buffer full: hold the datagram back
                    // (re-inject by closing over the value — simplest:
                    // drop; TCP relays retransmit at their layer? No —
                    // data loss! Instead stash into a pending vec.
                    PENDING_TX.lock().unwrap().push((k, data));
                    break;
                }
            }
            if woke {
                flow.write_space.notify_one();
            }
        }
        // retry held writes
        let held: Vec<(FlowKey, Vec<u8>)> = std::mem::take(&mut *PENDING_TX.lock().unwrap());
        for (k, data) in held {
            let can = tcp_flows
                .get(&k)
                .map(|f| sockets.get_mut::<TcpSocket>(f.handle).can_send())
                .unwrap_or(false);
            if can {
                let flow = tcp_flows.get_mut(&k).unwrap();
                let sock = sockets.get_mut::<TcpSocket>(flow.handle);
                let _ = sock.send_slice(&data);
                flow.write_space.notify_one();
            } else {
                PENDING_TX.lock().unwrap().push((k, data));
            }
        }

        // ---- run the stack
        let now = smoltcp::time::Instant::from_millis((tick * 20) as i64);
        iface.poll(now, &mut phy, &mut sockets);
        if tick % 25 == 0 {
            iface.poll_maintenance(now);
        }

        // ---- TCP sockets -> app channels; close detection
        let keys: Vec<FlowKey> = tcp_flows.keys().cloned().collect();
        for k in keys {
            let Some(flow) = tcp_flows.get_mut(&k) else { continue };
            {
                let sock = sockets.get_mut::<TcpSocket>(flow.handle);
                let mut q = flow.from_stack.lock().unwrap();
                while sock.can_recv() && q.q.len() <= (1 << 20) {
                    let mut tmp = [0u8; 16384];
                    match sock.recv_slice(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => q.push(&tmp[..n]),
                    }
                }
            }
            let sock = sockets.get_mut::<TcpSocket>(flow.handle);
            let state = sock.state();
            let closed = state == smoltcp::socket::tcp::State::Closed
                || (!sock.is_active() && flow.from_stack.lock().unwrap().q.is_empty());
            if closed {
                let flow = tcp_flows.remove(&k).unwrap();
                flow.from_stack.lock().unwrap().close();
                sockets.remove(flow.handle);
                debug!("tun: tcp {} -> {} closed", k.0, flow.dst);
            }
        }

        // ---- UDP: relay channels both ways
        let keys: Vec<FlowKey> = udp_flows.keys().cloned().collect();
        for k in keys {
            let Some(flow) = udp_flows.get_mut(&k) else { continue };
            // relay -> stack
            while let Ok((back_src, data)) = flow.from_relay.try_recv() {
                let sock = sockets.get_mut::<UdpSocket>(flow.handle);
                let ep = to_smoltcp_ep(back_src);
                if sock.send_slice(&data, ep).is_err() {
                    warn!("tun: udp send_slice failed (buffer full)");
                }
            }
            // stack -> relay (datagrams the socket received)
            {
                let sock = sockets.get_mut::<UdpSocket>(flow.handle);
                while sock.can_recv() {
                    let mut tmp = vec![0u8; 65535];
                    match sock.recv_slice(&mut tmp) {
                        Ok((n, meta)) => {
                            let _src = SocketAddr::new(
                                match meta.endpoint.addr {
                                    IpAddress::Ipv4(v4) => IpAddr::V4(v4),
                                    IpAddress::Ipv6(v6) => IpAddr::V6(v6),
                                },
                                meta.endpoint.port,
                            );
                            tmp.truncate(n);
                            if let Some(tx) = &flow.to_relay {
                                if tx.try_send(tmp.clone()).is_err() {
                                    break; // relay busy
                                }
                            }
                            // DNS flows have no relay task: the engine
                            // answered locally (to_relay None).
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        udp_flows.retain(|k, f| {
            let alive = f.last_seen.elapsed() < std::time::Duration::from_secs(30);
            if !alive {
                debug!("tun: udp {k:?} reaped");
            }
            alive
        });

        tick += 1;
    }
}

static PENDING_TX: std::sync::Mutex<Vec<(FlowKey, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());

fn to_smoltcp_ep(a: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(
        match a.ip() {
            IpAddr::V4(v4) => IpAddress::Ipv4(v4),
            IpAddr::V6(v6) => IpAddress::Ipv6(v6),
        },
        a.port(),
    )
}

/// Snoop one inbound packet: feed smoltcp + create flows / spawn relays.
#[allow(clippy::too_many_arguments)]
fn dispatch_ingress(
    pkt: &[u8],
    phy: &mut TunPhy,
    sockets: &mut SocketSet,
    tcp_flows: &mut HashMap<FlowKey, TcpFlow>,
    udp_flows: &mut HashMap<FlowKey, UdpFlow>,
    fake_map: &Arc<dns::FakeIpMap>,
    router: &TproxyRouter,
    pool: &crate::tunnel::ProxyPool,
    bandwidth: usize,
) {
    let Some((src_ip, dst_ip, proto, off)) = parse_ip(pkt) else {
        return;
    };
    match proto {
        6 => {
            if pkt.len() < off + 20 {
                phy.rx_queue.push(pkt.to_vec());
                return;
            }
            let sport = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            let dport = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
            let flags = pkt[off + 13];
            let key = (SocketAddr::new(src_ip, sport), SocketAddr::new(dst_ip, dport));
            if flags & 0x12 == 0x02 && !tcp_flows.contains_key(&key) {
                // New connection: listening socket on the ORIGINAL dst.
                let rx = TcpBuffer::new(vec![0u8; 128 * 1024]);
                let tx = TcpBuffer::new(vec![0u8; 128 * 1024]);
                let mut sock = TcpSocket::new(rx, tx);
                if sock.listen(to_smoltcp_ep(key.1)).is_err() {
                    warn!("tun: listen {} failed", key.1);
                    return;
                }
                let handle = sockets.add(sock);
                let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
                let from_stack = Arc::new(std::sync::Mutex::new(ByteQueue::default()));
                let write_space = Arc::new(Notify::new());
                debug!("tun: tcp flow {} -> {}", key.0, key.1);
                spawn_tcp_relay(
                    key,
                    TunStream {
                        from_stack: from_stack.clone(),
                        to_stack: tx,
                        write_space: write_space.clone(),
                    },
                    router.clone(),
                    pool.clone(),
                    bandwidth,
                );
                tcp_flows.insert(
                    key,
                    TcpFlow {
                        handle,
                        dst: key.1,
                        from_stack,
                        to_stack: rx,
                        write_space,
                    },
                );
            }
        }
        17 => {
            if pkt.len() < off + 8 {
                return;
            }
            let sport = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            let dport = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
            let src = SocketAddr::new(src_ip, sport);
            let dst = SocketAddr::new(dst_ip, dport);
            let key = (src, dst);
            let ulen = u16::from_be_bytes([pkt[off + 4], pkt[off + 5]]) as usize;
            let payload = pkt.get(off + 8..off + ulen.min(pkt.len() - off)).unwrap_or(&[]);

            if dport == 53 {
                // Local fake-IP DNS: answer immediately via a flow socket.
                if let Some(resp) = answer_dns_locally(fake_map, payload) {
                    ensure_udp_flow(sockets, udp_flows, &key, dst, None, dummy_from_relay());
                    let handle = udp_flows.get(&key).map(|f| f.handle).unwrap();
                    let sock = sockets.get_mut::<UdpSocket>(handle);
                    if sock.send_slice(&resp, to_smoltcp_ep(src)).is_err() {
                        warn!("tun: dns answer send failed");
                    }
                    if let Some(f) = udp_flows.get_mut(&key) {
                        f.last_seen = std::time::Instant::now();
                    }
                }
                // not fed to smoltcp: handled entirely here
                return;
            }

            // General UDP: create/refresh the flow; feed smoltcp (the
            // socket bound to `dst` receives the datagram), then the
            // engine loop forwards it to the relay task.
            if !udp_flows.contains_key(&key) {
                let (to_relay_tx, to_relay_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
                let (from_relay_tx, from_relay_rx) =
                    tokio::sync::mpsc::channel::<(SocketAddr, Vec<u8>)>(64);
                spawn_udp_relay(key, to_relay_rx, from_relay_tx, router.clone(), pool.clone());
                ensure_udp_flow(
                    sockets,
                    udp_flows,
                    &key,
                    dst,
                    Some(to_relay_tx),
                    from_relay_rx,
                );
            }
            if let Some(f) = udp_flows.get_mut(&key) {
                f.last_seen = std::time::Instant::now();
            }
            phy.rx_queue.push(pkt.to_vec());
        }
        _ => {}
    }
    // Everything (TCP incl. the SYN) goes through smoltcp too.
    if proto == 6 {
        phy.rx_queue.push(pkt.to_vec());
    }
}

/// A throwaway receiver for DNS-only flows (no relay task).
fn dummy_from_relay() -> tokio::sync::mpsc::Receiver<(SocketAddr, Vec<u8>)> {
    tokio::sync::mpsc::channel(1).1
}

fn ensure_udp_flow(
    sockets: &mut SocketSet,
    udp_flows: &mut HashMap<FlowKey, UdpFlow>,
    key: &FlowKey,
    bind_dst: SocketAddr,
    to_relay: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    from_relay: tokio::sync::mpsc::Receiver<(SocketAddr, Vec<u8>)>,
) {
    if udp_flows.contains_key(key) {
        return;
    }
    let mut sock = UdpSocket::new(
        PacketBuffer::new(
            vec![PacketMetadata::EMPTY; 16],
            vec![0u8; 65535 * 2],
        ),
        PacketBuffer::new(
            vec![PacketMetadata::EMPTY; 16],
            vec![0u8; 65535 * 2],
        ),
    );
    if sock.bind(to_smoltcp_ep(bind_dst)).is_err() {
        warn!("tun: udp bind {bind_dst} failed");
    }
    let handle = sockets.add(sock);
    udp_flows.insert(
        *key,
        UdpFlow {
            handle,
            to_relay,
            from_relay,
            last_seen: std::time::Instant::now(),
        },
    );
    let _ = udp_flows.get(key);
}

fn spawn_tcp_relay(
    key: FlowKey,
    stream: TunStream,
    mut router: TproxyRouter,
    pool: crate::tunnel::ProxyPool,
    bandwidth: usize,
) {
    tokio::spawn(async move {
        let dst = key.1;
        let (addr, decision) = route_dst(&router, dst);
        match decision.action {
            Action::Proxy => {
                match pool
                    .connect(decision.server.as_deref(), addr, None)
                    .await
                {
                    Ok(remote) => {
                        debug!("tun: relay {dst} tunneled");
                        let proxy = Proxy::new(stream, remote, bandwidth);
                        let _ = std::pin::pin!(proxy).await;
                    }
                    Err(e) => debug!("tun: relay {dst} tunnel failed: {e}"),
                }
            }
            Action::Direct => match router.direct.connect(addr).await {
                Ok(remote) => {
                    debug!("tun: relay {dst} direct");
                    let proxy = Proxy::new(stream, remote, bandwidth);
                    let _ = std::pin::pin!(proxy).await;
                }
                Err(e) => debug!("tun: relay {dst} direct failed: {e}"),
            },
        }
    });
}

fn spawn_udp_relay(
    key: FlowKey,
    mut to_relay: tokio::sync::mpsc::Receiver<Vec<u8>>,
    from_relay: tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
    router: TproxyRouter,
    pool: crate::tunnel::ProxyPool,
) {
    use bytes::BufMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::spawn(async move {
        let dst = key.1;
        let (addr, decision) = route_dst(&router, dst);
        let target_text = match &addr {
            crate::socks5::proto::Addr::SocketAddr(a) => format!("{a}"),
            crate::socks5::proto::Addr::DomainName(h, p) => {
                format!("{}:{p}", String::from_utf8_lossy(h))
            }
        };
        // UDP relays use the TUNNEL only (direct UDP flows over TCP make
        // no sense; direct UDP is future work via a marked UDP socket).
        let mut stream = match pool
            .connect(decision.server.as_deref(), crate::udp::magic_addr(), None)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                debug!("tun udp {dst}: tunnel connect failed: {e}");
                return;
            }
        };
        let action = decision.action;
        // hello: destination (domain for fake tokens, ip otherwise)
        if action == Action::Proxy {
            let mut hello = Vec::with_capacity(2 + target_text.len());
            hello.put_u16(target_text.len() as u16);
            hello.extend_from_slice(target_text.as_bytes());
            if stream.write_all(&hello).await.is_err() {
                return;
            }
        }
        let src = key.0;
        let mut read_buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                maybe = to_relay.recv() => {
                    let Some(dg) = maybe else { break };
                    if action == Action::Proxy {
                        let mut frame = Vec::with_capacity(2 + dg.len());
                        frame.put_u16(dg.len() as u16);
                        frame.extend_from_slice(&dg);
                        if stream.write_all(&frame).await.is_err() {
                            break;
                        }
                    } else {
                        // DirectConnector gives a TcpStream; UDP-over-TCP
                        // is not meaningful — direct UDP flows use the
                        // marked UDP socket instead (rare; skip for now).
                        let _ = (dg, &src);
                    }
                }
                read = stream.read(&mut read_buf) => {
                    match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut pending = &read_buf[..n];
                            while pending.len() >= 2 {
                                let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                                if pending.len() < 2 + len { break; }
                                let dg = pending[2..2 + len].to_vec();
                                if from_relay.try_send((src, dg)).is_err() {
                                    break;
                                }
                                pending = &pending[2 + len..];
                            }
                        }
                    }
                }
            }
        }
    });
}

/// Fake-token lookup + routing decision for an original destination.
fn route_dst(
    router: &TproxyRouter,
    dst: SocketAddr,
) -> (crate::socks5::proto::Addr, crate::routing::Decision) {
    if let Some(domain) = router.fake_map.lookup(dst.ip()) {
        let decision = router.routing.decide(Target::Domain(&domain));
        (
            crate::socks5::proto::Addr::DomainName(domain.into_bytes(), dst.port()),
            decision,
        )
    } else {
        let decision = router.routing.decide(Target::Ip(dst.ip()));
        (crate::socks5::proto::Addr::SocketAddr(dst), decision)
    }
}

// ---------------------------------------------------------------- parsing

fn parse_ip(pkt: &[u8]) -> Option<(IpAddr, IpAddr, u8, usize)> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            if pkt.len() < ihl + 8 {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
            Some((src, dst, pkt[9], ihl))
        }
        6 => {
            if pkt.len() < 48 {
                return None;
            }
            let src = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&pkt[8..24]).ok()?,
            ));
            let dst = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&pkt[24..40]).ok()?,
            ));
            Some((src, dst, pkt[6], 40))
        }
        _ => None,
    }
}

fn answer_dns_locally(fake_map: &Arc<dns::FakeIpMap>, query: &[u8]) -> Option<Vec<u8>> {
    let q = dns::proto::parse_query(query)?;
    match q.qtype {
        dns::proto::QTYPE_A => {
            let ip = fake_map.assign_v4(&q.domain);
            Some(dns::proto::build_a_response(&q, ip))
        }
        dns::proto::QTYPE_AAAA => {
            let ip = fake_map.assign_v6(&q.domain);
            Some(dns::proto::build_aaaa_response(&q, ip))
        }
        _ => Some(dns::proto::build_empty_response(&q)),
    }
}

/// Remove routes (the device dies with the fd / process).
pub fn stop(server_ips: &[Ipv4Addr]) {
    routes::tun_teardown(TUN_NAME, server_ips);
}
