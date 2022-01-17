use anyhow::Result;
use lib::config::{Config, Kind};
use lib::connector::LocalConnector;
use lib::{connector, generate_key_and_cert_pem};
use structopt::StructOpt;
use tracing::Level;

#[derive(StructOpt, Debug)]
enum Mode {
    Client {},
    Server,
}

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

fn is_verbose(verbose: bool) -> Level {
    if verbose {
        Level::TRACE
    } else {
        Level::INFO
    }
}

async fn start_with_config(config: Config) -> Result<()> {
    let password = config.password;
    let bandwidth = config.bandwidth;
    let kind = config.kind;
    setup_logger(config.verbose, &kind)?;
    match kind {
        Kind::Server { port, ca, key } => {
            let connector = LocalConnector;
            let key_cert = match (key, ca) {
                (Some(key), Some(cert)) => (key.into(), cert.into()),
                (_, _) => generate_key_and_cert_pem("tls", "org", "examples")?,
            };
            let mut server =
                lib::quic::server::Server::new(connector, key_cert, port, password, bandwidth)?;
            server.run().await?;
        }
        Kind::Client {
            proxy,
            socks5_port,
            tproxy: _,
        } => {
            let ca_path = proxy.ca_path.map(|path| path.into());
            let quic_client = lib::quic::client::ClientActorHndler::new(
                proxy.host,
                proxy.port,
                ca_path,
                password.as_bytes().to_vec(),
            )
            .await?;
            let connector = connector::QuicConnector::new(quic_client);
            let mut socks_server =
                lib::socks5::server::Server::new(Some(socks5_port), connector, bandwidth).await?;
            socks_server.run().await?;
        }
    };
    Ok(())
}

fn setup_logger(verbose: bool, kind: &Kind) -> Result<()> {
    let log_dir = match kind {
        Kind::Server {
            port: _,
            ca: _,
            key: _,
        } => "./server",
        Kind::Client {
            proxy: _,
            socks5_port: _,
            tproxy: _,
        } => "./client",
    };
    let file_appender = tracing_appender::rolling::hourly(log_dir, "magicalane.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(is_verbose(verbose))
        .with_writer(non_blocking)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("no global subscriber has been set");

    Ok(())
}
