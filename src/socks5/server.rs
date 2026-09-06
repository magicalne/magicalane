use crate::connector::Connector;

use super::{Result, conn::Connection};
use log::{debug, info, trace};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};

pub struct Server<C> {
    listener: TcpListener,
    connector: C,
    bandwidth: usize,
    /// user:pass entries; empty = no auth.
    users: Vec<(String, String)>,
}

impl<C> Server<C> {
    /// `bind`: explicit address; None -> 127.0.0.1 unless allow_lan.
    pub async fn new(
        port: Option<u16>,
        bind: Option<&str>,
        allow_lan: bool,
        users: Vec<String>,
        connector: C,
        bandwidth: usize,
    ) -> Result<Self> {
        let port = port.unwrap_or(1080);
        let host = bind
            .map(|s| s.to_string())
            .unwrap_or_else(|| if allow_lan { "0.0.0.0".into() } else { "127.0.0.1".into() });
        let socket_addr = (host.as_str(), port);
        let listener = TcpListener::bind(&socket_addr).await?;
        info!(
            "Socks/HTTP server bind to {:?} (auth: {})",
            &socket_addr,
            if users.is_empty() { "off" } else { "on" }
        );
        let users = users
            .iter()
            .filter_map(|s| {
                let (u, p) = s.split_once(':')?;
                Some((u.to_string(), p.to_string()))
            })
            .collect();
        Ok(Self {
            listener,
            connector,
            bandwidth,
            users,
        })
    }
}
impl<IO, C> Server<C>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Connector<Connection = IO> + Send + Clone + 'static,
{
    pub async fn run(&mut self) -> Result<()> {
        while let Ok((stream, addr)) = self.listener.accept().await {
            trace!("Accept addr: {:?}", addr);
            let connector = self.connector.clone();
            let users = self.users.clone();
            let bandwidth = self.bandwidth;
            // Mixed port: peek the first byte — 0x05 => SOCKS5,
            // anything else that looks like an HTTP method => HTTP proxy.
            let mut first = [0u8; 1];
            let is_socks = match stream.peek(&mut first).await {
                Ok(_) => first[0] == 0x05,
                Err(_) => continue,
            };
            if !is_socks {
                let connection = crate::httpin::handle(stream, connector, users.clone(), bandwidth);
                tokio::spawn(async move {
                    if let Err(err) = connection.await {
                        debug!("HTTP connection error: {:?}", err);
                    }
                });
                continue;
            }
            let connection = Connection::new(stream, connector, users, bandwidth);
            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    debug!("Connection error: {:?}", err);
                }
            });
        }
        Ok(())
    }
}
