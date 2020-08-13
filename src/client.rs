use std::{
    fs,
    io::{self},
    net::ToSocketAddrs,
};
use anyhow::{anyhow, Result};
use tracing::{error, info, debug};
use tracing_subscriber::fmt::format::debug_fn;
use std::convert::Infallible;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use futures_util::future::try_join;
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Client, Method, Request, Response, Server};
use quinn_proto::crypto::rustls::TlsSession;
use quinn::generic::{ClientConfig, SendStream, RecvStream};
use crate::protocol::{Protocol, Kind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type HttpClient = Client<hyper::client::HttpConnector>;

pub struct MLEClient {
    config: MLEClientConfig,
}

impl MLEClient {
    pub async fn run(&self) -> Result<()> {
        run(self.config.clone()).await
    }
}

async fn run(config: MLEClientConfig) -> Result<()> {
    //http proxy
    let addr = SocketAddr::from(([127, 0, 0, 1], config.http_proxy_port));
    let http_client = HttpClient::new();
    let make_service = make_service_fn(move |_| {
        let client = http_client.clone();
        let config = config.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req|
                http_proxy(client.clone(), req, config.clone())))
        }
    });
    let http_proxy_server = Server::bind(&addr).serve(make_service);
    info!("Listening on http://{}", addr);
    if let Err(e) = http_proxy_server.await {
        error!("server error: {}", e);
    }
    Ok(())
}

async fn http_proxy(client: HttpClient, req: Request<Body>, config: MLEClientConfig)
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
                        config
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
async fn http_tunnel(upgraded: Upgraded, host: String, port: u16, config: MLEClientConfig)
    -> Result<()> {
    // Connect to remote server
    let password = config.password.clone();

    // Proxying data
    let amounts = {
        let (mut client_rd, mut client_wr) = tokio::io::split(upgraded);
        let mut buf = Vec::with_capacity(1024);
        let n = client_rd.read_buf(&mut buf).await?;
        debug!("read from client: {:?} len: {:?}", String::from_utf8_lossy(&buf[..n]), n);

        let (mut proxy_wr, mut proxy_rd) = quic_conn(config).await?;
        let protocol = Protocol::new(Kind::TCP, password, host, port, Some(buf[0..n].to_owned()));
        buf = protocol.encode()?.to_vec();
        debug!("quic protocol: {:?}", &buf.to_vec());
        proxy_wr.write(&buf).await?;
        debug!("send to proxy server");
        buf.clear();
        let n = proxy_rd.read_buf(&mut buf).await?;
        debug!("read from proxy {} bytes", n);
        client_wr.write_all(&mut buf[..n]).await?;
        debug!("write back to client");
        let client_to_server = tokio::io::copy(&mut client_rd, &mut proxy_wr);
        let server_to_client = tokio::io::copy(&mut proxy_rd, &mut client_wr);

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
            info!("tunnel error: {}", e);
        }
    };
    Ok(())
}

async fn quic_conn(config: MLEClientConfig)
                   -> Result<(SendStream<TlsSession>, RecvStream<TlsSession>)> {
    // let remote = (config.server_host.as_str(), config.server_port)
    //     .to_socket_addrs()?
    //     .next()
    //     .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
    debug!("client connect to remote addr: {:?}", &remote);
    let mut endpoint = quinn::Endpoint::builder();
    endpoint.default_client_config(quic_config(config.local)?);
    debug!("quic client config finished.");
    let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;
    debug!("client bind local endpoint");
    let new_conn = endpoint
        .connect(&remote, "localhost")?
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

    pub fn client(self) -> Result<MLEClient> {
        Ok(MLEClient {
            config: self,
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