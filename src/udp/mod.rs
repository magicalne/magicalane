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

use crate::connector::Connector;

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
/// v6-only socket so v4 traffic keeps using the v4 interceptor).
pub fn bind_client_v6(port: u16) -> io::Result<Arc<UdpInterceptor>> {
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
        loop {
            self.sock.readable().await?;
            let fd = self.sock.as_raw_fd();
            match recvmsg_origdst(fd, buf) {
                Ok(v) => return Ok(v),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Err(err),
            }
        }
    }
}

/// Serve intercepted UDP until the socket dies.
pub async fn serve_client<C, IO>(interceptor: Arc<UdpInterceptor>, connector: C)
where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
                    let connector = connector.clone();
                    let sock = sock.clone();
                    tokio::spawn(flow_task(key, rx, connector, sock));
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

async fn flow_task<C, IO>(
    key: (SocketAddr, SocketAddr),
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut connector: C,
    sock: Arc<UdpSocket>,
) where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (src, dst) = key;
    let mut stream = match connector.connect(magic_addr()).await {
        Ok(s) => s,
        Err(err) => {
            debug!("udp flow to {dst} connect failed: {err}");
            return;
        }
    };
    // first frame: destination as ascii
    let dst_ascii = format!("{dst}");
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
            if self.dst.is_none() {
                let text = String::from_utf8_lossy(&payload).to_string();
                match text.parse::<SocketAddr>() {
                    Ok(a) => {
                        self.dst = Some(a);
                        info!("udp relay flow to {a}");
                    }
                    Err(_) => {
                        warn!("udp relay: bad dst frame {text:?}");
                        return;
                    }
                }
            } else if payload.len() <= MAX_DGRAM {
                self.outq.push(payload);
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
