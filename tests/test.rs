use lib::connector::LocalConnector;
use lib::error::Result;
use lib::{
    connector::QuicConnector,
    generate_key_and_cert_der,
    quic::{self, server::Server},
};
use tracing::Level;

#[tokio::test]
#[ignore = "integration test"]
pub async fn server_test() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("no global subscriber has been set");
    let connector = LocalConnector;
    let key_cert = generate_key_and_cert_der("tls", "org", "examples")?;
    let mut server = Server::new(connector, key_cert, 3333, String::from("pwd"), 8024)?;
    server.run().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "integration test"]
pub async fn client_test() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("no global subscriber has been set");
    let (_, cert) = generate_key_and_cert_der("tls", "org", "examples")?;
    let quic_client = quic::client::ClientActorHndler::new(
        "localhost".to_string(),
        3333,
        Some(cert),
        "pwd".as_bytes().to_vec(),
    )
    .await?;
    let connector = QuicConnector::new(quic_client);
    let mut socks_server = lib::socks5::server::Server::new(None, connector, 8024).await?;
    socks_server.run().await?;
    Ok(())
}
