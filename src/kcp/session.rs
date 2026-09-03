use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use futures::task::AtomicWaker;
use kcp::{Error as KcpError, Kcp};
use log::{debug, trace};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::{Notify, mpsc},
};

use super::{KCP_IDLE_TIMEOUT_SECS, KCP_MAX_WRITE, KCP_TICK_MS};
use crate::config::KcpTuning;

/// Collects datagrams produced by the kcp state machine; the driver task
/// drains this queue onto the UDP socket via the shared `OutputBuf` handle.
#[derive(Clone)]
struct OutputBuf(Arc<StdMutex<VecDeque<Vec<u8>>>>);

impl OutputBuf {
    fn drain(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().drain(..).collect()
    }
    fn push(&self, pkt: Vec<u8>) {
        self.0.lock().unwrap().push_back(pkt);
    }
}

struct OutputQueue {
    buf: OutputBuf,
}

impl std::io::Write for OutputQueue {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.push(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(()).map(|_| ())
    }
}

struct Inner {
    kcp: Kcp<OutputQueue>,
    sndwnd: usize,
    /// Decoded application payload waiting to be read.
    rbuf: BytesMut,
    /// A zero-length (EOF) message was received.
    eof: bool,
    /// The application shut down / EOF frame was sent.
    wrote_eof: bool,
    write_closed: bool,
}

pub struct Shared {
    inner: StdMutex<Inner>,
    /// Datagrams produced by the kcp machine, drained by the driver.
    outbuf: OutputBuf,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
    /// Notifies the driver that outputs need flushing soon (writes happened).
    wake: Arc<Notify>,
    /// Session is dead: idle timeout, dead link, or kcp error.
    closed: AtomicBool,
}

impl Shared {
    pub fn new(conv: u32, tuning: &KcpTuning) -> Self {
        let outbuf = OutputBuf(Arc::new(StdMutex::new(VecDeque::new())));
        let mut kcp = Kcp::new(
            conv,
            OutputQueue {
                buf: outbuf.clone(),
            },
        );
        kcp.set_mtu(tuning.mtu).ok();
        kcp.set_wndsize(tuning.sndwnd, tuning.rcvwnd);
        kcp.set_nodelay(tuning.nodelay, tuning.interval, tuning.resend, tuning.nc);
        Self {
            inner: StdMutex::new(Inner {
                kcp,
                sndwnd: tuning.sndwnd as usize,
                rbuf: BytesMut::new(),
                eof: false,
                wrote_eof: false,
                write_closed: false,
            }),
            outbuf,
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
            wake: Arc::new(Notify::new()),
            closed: AtomicBool::new(false),
        }
    }

    /// Move everything the kcp receive queue holds into `rbuf`.
    /// Returns true when new bytes became readable.
    fn fill_rbuf(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let mut added = false;
        while inner.rbuf.len() < 4 * KCP_MAX_WRITE {
            match inner.kcp.peeksize() {
                Err(KcpError::RecvQueueEmpty) => break,
                Err(err) => {
                    trace!("kcp peeksize: {:?}", err);
                    break;
                }
                Ok(n) => {
                    let mut seg = vec![0u8; n];
                    // peeksize() == 0 means the zero-length EOF message.
                    let got = match inner.kcp.recv(&mut seg) {
                        Ok(n) => n,
                        Err(KcpError::RecvQueueEmpty) => break,
                        Err(err) => {
                            debug!("kcp recv: {:?}", err);
                            break;
                        }
                    };
                    if got == 0 {
                        inner.eof = true;
                        break;
                    }
                    inner.rbuf.extend_from_slice(&seg[..got]);
                    added = true;
                }
            }
        }
        added
    }

    fn is_eof(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.eof || self.closed.load(Ordering::Acquire)
    }
}

/// A bidirectional reliable stream over one KCP conversation.
pub struct KcpStream {
    shared: Arc<Shared>,
}

impl KcpStream {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        if shared.fill_rbuf() {
            let mut inner = shared.inner.lock().unwrap();
            let n = inner.rbuf.len().min(buf.remaining());
            let data = inner.rbuf.split_to(n);
            buf.put_slice(&data);
            shared.read_waker.wake(); // more may remain
            return Poll::Ready(Ok(()));
        }
        let mut inner = shared.inner.lock().unwrap();
        if inner.rbuf.is_empty() {
            if inner.eof {
                return Poll::Ready(Ok(()));
            }
            if shared.closed.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }
            shared.read_waker.register(cx.waker());
            return Poll::Pending;
        }
        let n = inner.rbuf.len().min(buf.remaining());
        let data = inner.rbuf.split_to(n);
        buf.put_slice(&data);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.shared;
        let mut inner = shared.inner.lock().unwrap();
        if shared.closed.load(Ordering::Acquire) || inner.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "kcp session closed",
            )));
        }
        if inner.kcp.wait_snd() >= inner.sndwnd {
            shared.write_waker.register(cx.waker());
            return Poll::Pending;
        }
        let mut off = 0;
        while off < buf.len() {
            let end = (off + KCP_MAX_WRITE).min(buf.len());
            match inner.kcp.send(&buf[off..end]) {
                Ok(_) => off = end,
                Err(KcpError::UserBufTooBig) => {
                    if off == 0 {
                        shared.write_waker.register(cx.waker());
                        return Poll::Pending;
                    }
                    break;
                }
                Err(err) => {
                    return Poll::Ready(Err(io::Error::other(err)));
                }
            }
        }
        let now = now_ms();
        let _ = inner.kcp.update(now);
        let _ = inner.kcp.flush();
        drop(inner);
        shared.wake.notify_one();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        let inner = shared.inner.lock().unwrap();
        if inner.kcp.wait_snd() == 0 {
            Poll::Ready(Ok(()))
        } else {
            shared.write_waker.register(cx.waker());
            Poll::Pending
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        send_eof(shared);
        Poll::Ready(Ok(()))
    }
}

/// Queue the zero-length EOF message (idempotent).
pub(crate) fn send_eof(shared: &Arc<Shared>) {
    let mut inner = shared.inner.lock().unwrap();
    if !inner.wrote_eof && !inner.write_closed {
        let _ = inner.kcp.send(&[]);
        inner.wrote_eof = true;
    }
    inner.write_closed = true;
    let now = now_ms();
    let _ = inner.kcp.update(now);
    let _ = inner.kcp.flush();
    drop(inner);
    shared.wake.notify_one();
}

fn now_ms() -> u32 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u32
}

/// Drive one KCP session: feed it input packets, tick its timers, and drain
/// its output queue onto the UDP socket. Exits when the application side is
/// gone (no `KcpStream` handles left, after sending EOF and lingering), or
/// on idle timeout / dead link.
pub async fn drive_session(
    shared: Arc<Shared>,
    socket: Arc<UdpSocket>,
    initial_peer: SocketAddr,
    mut rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    on_exit: impl FnOnce(),
) {
    let mut peer = initial_peer;
    let mut last_active = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(KCP_TICK_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let notify = shared.wake.clone();

    let result = loop {
        tokio::select! {
            pkt = rx.recv() => {
                match pkt {
                    Some((from, data)) => {
                        peer = from;
                        last_active = Instant::now();
                        let added = process_packet(&shared, &data);
                        let outputs = tick_once(&shared);
                        if added {
                            shared.read_waker.wake();
                        }
                        if let Err(err) = send_all(&socket, &peer, outputs).await {
                            debug!("kcp send error: {:?}", err);
                        }
                        wake_writers(&shared);
                    }
                    None => break Ok::<(), ()>(()), // listener dropped the route
                }
            }
            _ = tick.tick() => {
                let outputs = tick_once(&shared);
                if let Err(err) = send_all(&socket, &peer, outputs).await {
                    debug!("kcp send error: {:?}", err);
                }
                wake_writers(&shared);
                let quiet = {
                    let inner = shared.inner.lock().unwrap();
                    inner.eof && inner.rbuf.is_empty() && inner.kcp.wait_snd() == 0
                };
                if quiet && Arc::strong_count(&shared) == 1 {
                    // peer signalled EOF and everything is delivered
                    break Ok::<(), ()>(());
                }
            }
            _ = notify.notified() => {
                let outputs = tick_once(&shared);
                if let Err(err) = send_all(&socket, &peer, outputs).await {
                    debug!("kcp send error: {:?}", err);
                }
                wake_writers(&shared);
            }
        }

        // Application dropped all KcpStream handles: send EOF, then linger
        // briefly so the final data + EOF can be ACKed.
        if Arc::strong_count(&shared) == 1 {
            send_eof(&shared);
            linger_and_exit(&shared, &socket, &peer).await;
            break Ok(());
        }

        if last_active.elapsed() > Duration::from_secs(KCP_IDLE_TIMEOUT_SECS) {
            debug!("kcp session idle timeout");
            shared.closed.store(true, Ordering::Release);
            shared.read_waker.wake();
            shared.write_waker.wake();
            break Ok(());
        }

        {
            let inner = shared.inner.lock().unwrap();
            if inner.kcp.is_dead_link() {
                debug!("kcp dead link");
                shared.closed.store(true, Ordering::Release);
                shared.read_waker.wake();
                shared.write_waker.wake();
                break Ok(());
            }
        }
    };
    let _ = result;
    shared.closed.store(true, Ordering::Release);
    shared.read_waker.wake();
    shared.write_waker.wake();
    on_exit();
}

async fn linger_and_exit(shared: &Arc<Shared>, socket: &Arc<UdpSocket>, peer: &SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(KCP_TICK_MS)).await;
        let outputs = tick_once(shared);
        let done = {
            let inner = shared.inner.lock().unwrap();
            inner.kcp.wait_snd() == 0 && inner.wrote_eof
        };
        if let Err(err) = send_all(socket, peer, outputs).await {
            debug!("kcp send error: {:?}", err);
        }
        if done && shared.is_eof() {
            break;
        }
    }
}

/// Feed one datagram into the kcp machine; returns whether new bytes became
/// readable. Helper keeps all lock guards inside a plain function.
fn process_packet(shared: &Arc<Shared>, data: &[u8]) -> bool {
    {
        let mut inner = shared.inner.lock().unwrap();
        if let Err(err) = inner.kcp.input(data) {
            trace!("kcp input: {:?}", err);
        }
    }
    shared.fill_rbuf()
}

/// One timer step: update the kcp state machine and collect its outputs.
/// Kept as a function so no lock guard can leak across an await point.
fn tick_once(shared: &Shared) -> Vec<Vec<u8>> {
    {
        let mut inner = shared.inner.lock().unwrap();
        let _ = inner.kcp.update(now_ms());
    }
    shared.outbuf.drain()
}

async fn send_all(
    socket: &Arc<UdpSocket>,
    peer: &SocketAddr,
    outputs: Vec<Vec<u8>>,
) -> io::Result<()> {
    for pkt in outputs {
        socket.send_to(&pkt, peer).await?;
    }
    Ok(())
}

fn wake_writers(shared: &Arc<Shared>) {
    if shared.inner.lock().unwrap().kcp.wait_snd() == 0 {
        shared.write_waker.wake();
    }
}
