use std::path::PathBuf;

use anyhow::Result;
use lib::{
    generate_key_and_cert_pem,
    quic::{self, server::Server},
    quic_connector,
};
use socks5lib::LocalConnector;
use structopt::StructOpt;
use tracing::Level;

#[derive(StructOpt, Debug)]
enum Mode {
    Client {},
    Server,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "magicalane", about = "A quic proxy.")]
enum Opt {
    Client {
        #[structopt(long)]
        server_host: String,
        #[structopt(long)]
        server_port: u16,
        #[structopt(long)]
        socks_port: u16,
        #[structopt(long)]
        password: String,
        #[structopt(parse(from_os_str), long)]
        ca: Option<PathBuf>,
        #[structopt(long)]
        verbose: bool,
    },
    Server {
        #[structopt(long)]
        port: u16,
        #[structopt(long)]
        password: String,
        #[structopt(parse(from_os_str), long)]
        ca: Option<PathBuf>,
        #[structopt(parse(from_os_str), long)]
        key: Option<PathBuf>,
        #[structopt(long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: Opt = Opt::from_args();
    match opt {
        Opt::Client {
            server_host,
            server_port,
            socks_port,
            password,
            ca,
            verbose,
        } => {
            let file_appender = tracing_appender::rolling::hourly("./log", "magicalane-client.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(is_verbose(verbose))
                .with_writer(non_blocking)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no global subscriber has been set");
            let quic_client = quic::client::ClientActorHndler::new(
                server_host.clone(),
                server_port,
                ca,
                password.as_bytes().to_vec(),
            )
            .await?;
            let connector = quic_connector::QuicConnector::new(quic_client);
            let mut socks_server =
                socks5lib::server::Server::new(Some(socks_port), connector).await?;
            socks_server.run().await?;
        }
        Opt::Server {
            port,
            password,
            ca,
            key,
            verbose,
        } => {
            let file_appender = tracing_appender::rolling::hourly("./log", "magicalane-server.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(is_verbose(verbose))
                .with_writer(non_blocking)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no global subscriber has been set");
            let key_cert = match (key, ca) {
                (Some(key), Some(cert)) => (key, cert),
                (_, _) => generate_key_and_cert_pem("tls", "org", "examples")?,
            };
            let connector = LocalConnector;
            let mut server = Server::new(connector, key_cert, port, password)?;
            server.run().await?;
        }
    }
    Ok(())
}

fn is_verbose(verbose: bool) -> Level {
    if verbose {
        Level::TRACE
    } else {
        Level::INFO
    }
}
