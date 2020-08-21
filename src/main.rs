// use tracing_futures::Instrument as _;
use std::path::PathBuf;

use anyhow::Result;
use structopt::StructOpt;
use tracing::Level;

use lib::{client::MLEClientConfig, server::MLEServerConfig};

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
        http_proxy_port: u16,
        #[structopt(long)]
        password: String,
        #[structopt(long)]
        local: bool,
        #[structopt(long)]
        verbose: bool
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
        verbose: bool
    },
}

#[tokio::main]
async fn main() -> Result<()> {

    let opt: Opt = Opt::from_args();
    match opt {
        Opt::Client {
            server_host,
            server_port,
            http_proxy_port,
            password,
            local,
            verbose } => {
            let file_appender = tracing_appender::rolling::hourly("./log", "magicalane-client.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(is_verbose(verbose))
                .with_writer(non_blocking)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no global subscriber has been set");
            MLEClientConfig::new(server_host, server_port, http_proxy_port, password, local)?
                .build()?.run().await?
        },
        Opt::Server {
            port,
            password,
            ca,
            key,
            verbose } => {
            let file_appender = tracing_appender::rolling::hourly("./log", "magicalane-server.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(is_verbose(verbose))
                .with_writer(non_blocking)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no global subscriber has been set");
            MLEServerConfig::new(port, password, ca, key)?
                .server()?.run().await?
        },
    }
    Ok(())
}

fn is_verbose(verbose: bool) -> Level {
    return if verbose {
        Level::TRACE
    } else {
        Level::INFO
    }
}
