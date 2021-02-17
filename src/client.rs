use std::{
    fs,
    io::{self},
    net::ToSocketAddrs,
};
use std::convert::Infallible;
use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use futures_util::future::try_join;
use hyper::{Body, Client, Method, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use quinn::Endpoint;
use quinn::generic::{ClientConfig, RecvStream, SendStream};
use quinn_proto::crypto::rustls::TlsSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};
use nix::sys::socket;
use nix::sys::socket::sockopt::SndBuf;
use nix::sys::socket::sockopt::RcvBuf;
use std::os::unix::io::AsRawFd;
use crate::protocol::{Kind, Protocol};
use crate::copy;

type HttpClient = Client<hyper::client::HttpConnector>;

pub struct MLEClient {
    client_config: MLEClientConfig,
    quic_config: ClientConfig<TlsSession>
}

impl MLEClient {
    pub async fn run(&self) -> Result<()> {
        run(self.client_config.clone(), self.quic_config.clone()).await
    }
}

async fn run(config: MLEClientConfig, quic_config: ClientConfig<TlsSession>) -> Result<()> {
    //http proxy
    let addr = SocketAddr::from(([127, 0, 0, 1], config.http_proxy_port));
    let http_client = HttpClient::new();
    let (endpoint, socket_addr) =
        make_client_endpoint(&config.server_host, config.server_port, quic_config)?;
    let make_service = make_service_fn(move |_| {
        let client = http_client.clone();
        let endpoint = endpoint.clone();
        let socket_addr = socket_addr;
        let server_host = config.server_host.clone();
        let password = config.password.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req|
                http_proxy(
                    client.clone(),
                    req,
                    endpoint.clone(),
                    socket_addr,
                    server_host.clone(),
                    password.clone()
                )))
        }
    });
    let http_proxy_server = Server::bind(&addr).serve(make_service);
    info!("Listening on http://{}", addr);
    if let Err(e) = http_proxy_server.await {
        error!("server error: {}", e);
    }
    Ok(())
}

async fn http_proxy(
    client: HttpClient,
    req: Request<Body>,
    endpoint: Endpoint,
    socket_addr: SocketAddr,
    server_host: String,
    password: String)
    -> Result<Response<Body>, hyper::Error> {
    info!("req: {:?}", req);
    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        tokio::task::spawn(async move {
            let host = req.uri().host().clone().unwrap().into();
            let port = req.uri().port_u16().unwrap();
            debug!("[host:port] {:?}:{:?}", &host, port);
            match req.into_body().on_upgrade().await {
                Ok(upgraded) => {
                    if let Err(e) = http_tunnel(
                        upgraded,
                        host,
                        port,
                        &endpoint,
                        &socket_addr,
                        &server_host,
                        password
                    ).await {
                        error!("server io error: {}", e);
                    };
                }
                Err(e) => error!("upgrade error: {}", e),
            }
        });
        Ok(Response::new(Body::empty()))
    } else {
        client.request(req).await
    }
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn http_tunnel(
    upgraded: Upgraded,
    host: String,
    port: u16,
    endpoint: &Endpoint,
    socket_addr: &SocketAddr,
    server_host: &str,
    password: String
)
    -> Result<()> {
    // Connect to remote server
    // let password = config.password.clone();

    // Proxying data
    let amounts = {
        let (mut client_rd, mut client_wr) = tokio::io::split(upgraded);
        let mut buf = Vec::with_capacity(1024);
        let n = client_rd.read_buf(&mut buf).await?;
        debug!("read from client {:?} bytes", n);

        let (mut proxy_wr, mut proxy_rd) = run_quic_conn(endpoint, socket_addr, server_host).await?;
        let protocol = Protocol::new(Kind::TCP, password, host, port, Some(buf[0..n].to_owned()));
        buf = protocol.encode()?.to_vec();
        debug!("quic protocol: {:?}", &buf.to_vec());
        proxy_wr.write(&buf).await?;
        debug!("send to proxy server");
        buf.clear();
        let n = proxy_rd.read_buf(&mut buf).await?;
        debug!("read from proxy {} bytes", n);
        client_wr.write_all(&buf[..n]).await?;
        debug!("write back to client");
        let client_to_server = tokio::io::copy(&mut client_rd, &mut proxy_wr);
        let server_to_client = tokio::io::copy(&mut proxy_rd, &mut client_wr);
        // let client_to_server = copy(&mut client_rd, &mut proxy_wr);
        // let server_to_client = copy(&mut proxy_rd, &mut client_wr);
        try_join(client_to_server, server_to_client).await
    };

    // Print message when done
    match amounts {
        Ok((from_client, from_server)) => {
            info!(
                "client wrote {} bytes and received {} bytes",
                from_client, from_server
            );
        }
        Err(e) => {
            warn!("tunnel error: {}", e);
        }
    };
    Ok(())
}

pub struct MLEClientConfig {
    server_host: String,
    server_port: u16,
    http_proxy_port: u16,
    password: String,
    local: bool

}

impl MLEClientConfig {
    pub fn new(
        server_host: String,
        server_port: u16,
        http_proxy_port: u16,
        password: String,
        local: bool
    )
        -> Result<Self> {
        Ok(MLEClientConfig {
            server_host,
            server_port,
            http_proxy_port,
            password,
            local
        })
    }

    pub fn build(self) -> Result<MLEClient> {
        let quic_config = quic_config(self.local)?;
        Ok(MLEClient {
            client_config: self,
            quic_config
        })
    }
}

impl Clone for MLEClientConfig {
    fn clone(&self) -> Self {
        Self {
            server_host: self.server_host.clone(),
            server_port: self.server_port,
            http_proxy_port: self.http_proxy_port,
            password: self.password.clone(),
            local: self.local
        }
    }
}

fn make_client_endpoint(server_host: &str, server_port: u16, quic_config: ClientConfig<TlsSession>)
    -> Result<(Endpoint, SocketAddr)> {
    let remote = (server_host, server_port)
        .to_socket_addrs()?
        .filter(|add| add.is_ipv4())
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
    debug!("client connect to remote addr: {:?}", &remote);
    let mut endpoint = quinn::Endpoint::builder();
    endpoint.default_client_config(quic_config);
    debug!("quic client config finished.");
    let socket = std::net::UdpSocket::bind("[::]:0")
        .map_err(|_| anyhow!("couldn't bind to udp"))?;
    let fd = socket.as_raw_fd();
    let recv_buf_size = socket::getsockopt(fd, RcvBuf)?;
    let send_buf_size = socket::getsockopt(fd, SndBuf)?;
    println!("RcvBuf: {:?}, SndBuf: {:?}", recv_buf_size, send_buf_size);
    let buf_size = 50 * 1024 * 1024 as usize;
    socket::setsockopt(fd, RcvBuf, &(buf_size))
        .expect("setsockopt for RcvBuf failed");
    let recv_buf_size = socket::getsockopt(fd, RcvBuf)?;
    let send_buf_size = socket::getsockopt(fd, SndBuf)?;
    socket::setsockopt(fd, SndBuf, &(buf_size))
        .expect("setsockopt for SndBuf failed");
    println!("now RcvBuf: {:?}, SndBuf: {:?}", recv_buf_size, send_buf_size);
    let (endpoint, _) = endpoint.with_socket(socket)?;
    debug!("client bind local endpoint");
    Ok((endpoint, remote))
}

async fn run_quic_conn(endpoint: &Endpoint, socket_addr: &SocketAddr, server_name: &str)
    -> Result<(SendStream<TlsSession>, RecvStream<TlsSession>)> {

    let new_conn = endpoint
        .connect(socket_addr, server_name)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    debug!("client create a new connection");
    let quinn::NewConnection {
        connection: conn, ..
    } = { new_conn };
    conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))
}

fn quic_config(local: bool) -> Result<ClientConfig<TlsSession>> {
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(crate::ALPN_QUIC);
    client_config.enable_keylog();
    if local {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        info!("cert dir: {:?}", &dirs);
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                client_config.add_certificate_authority(quinn::Certificate::from_der(&cert)?)?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }
    Ok(client_config.build())
}
