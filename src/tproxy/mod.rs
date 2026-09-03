//! Transparent TCP interception (tproxy mode).
//!
//! Listens with `IP_TRANSPARENT` on `tcp_port`; packets redirected by the
//! rule manager arrive with their ORIGINAL destination, recoverable via
//! `getsockname()` on the accepted socket. Each accepted connection is
//! relayed through the configured transport connector, exactly like a
//! socks5 CONNECT would be.

pub mod rules;

use std::os::unix::io::FromRawFd;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use log::{info, warn};
use tokio::{net::TcpListener, spawn};

use crate::{connector::Connector, proxy::Proxy, socks5::proto::Addr};

/// Bind the transparent TCP listener using raw libc syscalls (identical
/// to the proven isolation test; avoids socket2 abstraction differences).
/// The socket must exist before the firewall rules are installed.
pub fn bind(port: u16) -> io::Result<TcpListener> {
    const IP_TRANSPARENT: libc::c_int = 19;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let on: libc::c_int = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR,
            &on as *const _ as *const libc::c_void, 4);
        if libc::setsockopt(fd, libc::IPPROTO_IP, IP_TRANSPARENT,
            &on as *const _ as *const libc::c_void, 4) != 0 {
            warn!("IP_TRANSPARENT failed: {}", io::Error::last_os_error());
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 }, // 0.0.0.0
            sin_zero: [0; 8],
        };
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, 16) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::listen(fd, 1024) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        let std_listener = std::net::TcpListener::from_raw_fd(fd);
        let listener = TcpListener::from_std(std_listener)?;
        info!("tproxy TCP listener on 0.0.0.0:{port}");
        Ok(listener)
    }
}

/// Serve accepted transparent connections until the listener errors out.
pub async fn serve<C, IO>(listener: TcpListener, connector: C, bandwidth: usize)
where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                // getsockname on a TPROXY accepted socket = original dst;
                // for REDIRECT'd connections it returns the listener addr,
                // so fall back to SO_ORIGINAL_DST in that case.
                let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
                let dst = match stream.local_addr() {
                    Ok(a) if a.port() != port => a, // TPROXY: getsockname is orig dst
                    Ok(_) => match original_dst(&stream) {
                        Ok(a) => a, // REDIRECT: SO_ORIGINAL_DST
                        Err(err) => {
                            warn!("tproxy accept without dst: {err}");
                            continue;
                        }
                    },
                    Err(err) => {
                        warn!("tproxy accept without local addr: {err}");
                        continue;
                    }
                };
                let connector = connector.clone();
                log::info!("tproxy accepted conn, original dst {dst}");
                spawn(async move {
                    match relay(stream, dst, connector, bandwidth).await {
                        Ok(()) => log::info!("tproxy relay {dst} done"),
                        Err(err) => log::warn!("tproxy relay {dst} error: {err}"),
                    }
                });
            }
            Err(err) => {
                warn!("tproxy accept error: {err}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

async fn relay<C, IO>(
    client: tokio::net::TcpStream,
    dst: SocketAddr,
    mut connector: C,
    bandwidth: usize,
) -> io::Result<()>
where
    C: Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    log::info!("tproxy relay {dst}: opening tunnel");
    let addr = Addr::SocketAddr(dst);
    let tunnel = connector
        .connect(addr)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let proxy = Proxy::new(client, tunnel, bandwidth);
    let _ = std::pin::pin!(proxy).await;
    Ok(())
}

/// Get the original destination of a REDIRECT'd connection via
/// SO_ORIGINAL_DST (the conntrack entry created by nat REDIRECT).
pub fn original_dst(
    stream: &tokio::net::TcpStream,
) -> io::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr))),
        u16::from_be(addr.sin_port),
    ))
}
