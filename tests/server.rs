use std::{io::stderr, path::PathBuf};

use lib::{
    error::Result,
    protocol::{Kind, Protocol},
    server1::Server,
    socks::server::SocksServer,
};
use tracing::{error, info, info_span, Level};

#[tokio::test]
pub async fn server_test() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("no global subscriber has been set");
    let mut server = Server::new(None, 3333, String::from("pwd")).await?;
    server.run().await?;

    Ok(())
}

#[tokio::test]
pub async fn client_test() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("no global subscriber has been set");
    let path = PathBuf::from("/home/magicalne/.local/share/examples/cert.der");
    let mut socks = SocksServer::new(None, "localhost", 3333, Some(path), String::from("pwd")).await?;
    socks.start().await?;
    Ok(())
}
