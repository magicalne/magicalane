use lib::{error::Result, socks::server::SocksServer};
use tracing::{info, span, Instrument, Level};

#[tokio::test]
pub async fn test() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let port = 8088;
    let local_addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let server_span = span!(Level::TRACE, "server", %local_addr);
    SocksServer::new(None, "localhost", port, None, "pwd".to_string())
        .await?
        .start()
        .instrument(server_span.clone())
        .await?;
    Ok(())
}
