use structopt::StructOpt;
use tracing::Level;
use tracing::log::info;
// use tracing_futures::Instrument as _;
use std::path::PathBuf;
use lib::{server::MLEServerConfig, client::MLEClientConfig};
use anyhow::Result;

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
        local: bool
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
    },
}

#[tokio::main]
async fn main() -> Result<()> {

    let opt: Opt = Opt::from_args();
    println!("opt: {:?}", &opt);
    match opt {
        Opt::Client { server_host, server_port, http_proxy_port, password, local } => {
            let file_appender = tracing_appender::rolling::hourly(".", "magicalane-client.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(Level::DEBUG)
                .with_writer(non_blocking)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no global subscriber has been set");
            MLEClientConfig::new(server_host, server_port, http_proxy_port, password, local)?
                .client()?.run().await?
        },
        Opt::Server { port, password, ca, key } => {
            let file_appender = tracing_appender::rolling::hourly(".", "magicalane-server.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(Level::DEBUG)
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
