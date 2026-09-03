use anyhow::{Context, Result};
use lib::config::{Config, Kind, Protocol};
use lib::connector::LocalConnector;
use lib::kcp::connector::KcpConnector;
use lib::{connector, generate_key_and_cert_pem};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "magicalane", about = "A quic proxy.")]
struct Opt {
    #[structopt(long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: Opt = Opt::from_args();
    let content = std::fs::read(opt.config)?;
    let config: Config = toml::from_slice(&content)?;

    start_with_config(config).await?;
    Ok(())
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn start_with_config(config: Config) -> Result<()> {
    let password = config.password;
    let bandwidth = config.bandwidth;
    let kind = config.kind;
    let tuning = config.tuning.clone().unwrap_or_default();
    env_logger::init();
    install_crypto_provider();
    match kind {
        Kind::Server {
            port,
            ca,
            key,
            protocol,
            tls,
        } => {
            let protocol = Protocol::from_opt(&protocol)
                .with_context(|| "unknown protocol (expected \"quic\" or \"kcp\")")?;
            let tls = tls.unwrap_or(true);
            match protocol {
                Protocol::Quic => {
                    let connector = LocalConnector;
                    let key_cert = match (key, ca) {
                        (Some(key), Some(cert)) => (key.into(), cert.into()),
                        (_, _) => generate_key_and_cert_pem("tls", "org", "examples")?,
                    };
                    let mut server = lib::quic::server::Server::new(
                        connector,
                        key_cert,
                        port,
                        password,
                        bandwidth,
                        tuning.quic.clone(),
                    )?;
                    server.run().await?;
                }
                Protocol::Kcp => {
                    let connector = LocalConnector;
                    let key_cert = match (key, ca) {
                        (Some(key), Some(cert)) => (key.into(), cert.into()),
                        (_, _) => generate_key_and_cert_pem("tls", "org", "examples")?,
                    };
                    let mut server = lib::kcp::listener::Server::new(
                        connector,
                        key_cert,
                        port,
                        password,
                        bandwidth,
                        tls,
                        tuning.kcp.clone(),
                    )?;
                    server.run().await?;
                }
            }
        }
        Kind::Client {
            proxy,
            socks5_port,
            tproxy: _,
        } => {
            let protocol = Protocol::from_opt(&proxy.protocol)
                .with_context(|| "unknown protocol (expected \"quic\" or \"kcp\")")?;
            let tls = proxy.tls.unwrap_or(true);
            let kcp_tuning = tuning.kcp.clone();
            let quic_tuning = tuning.quic.clone();
            match protocol {
                Protocol::Quic => {
                    let ca_path = proxy.ca_path.map(std::path::PathBuf::from);
                    let quic_client = lib::quic::client::ClientActorHndler::new(
                        proxy.host,
                        proxy.port,
                        ca_path,
                        password.as_bytes().to_vec(),
                        quic_tuning,
                    )
                    .await?;
                    let connector = connector::QuicConnector::new(quic_client);
                    run_socks_server(connector, socks5_port, bandwidth).await?;
                }
                Protocol::Kcp => {
                    let ca_path = proxy.ca_path.map(std::path::PathBuf::from);
                    let connector = KcpConnector::new(
                        proxy.host,
                        proxy.port,
                        ca_path,
                        password.as_bytes().to_vec(),
                        tls,
                        kcp_tuning,
                    )?;
                    run_socks_server(connector, socks5_port, bandwidth).await?;
                }
            }
        }
    };
    Ok(())
}

async fn run_socks_server<C, IO>(connector: C, socks5_port: u16, bandwidth: usize) -> Result<()>
where
    C: lib::connector::Connector<Connection = IO> + Send + 'static + Clone,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let mut server =
        lib::socks5::server::Server::new(Some(socks5_port), connector, bandwidth).await?;
    server.run().await?;
    Ok(())
}
