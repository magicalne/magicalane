use std::io::stderr;

use lib::{client1, error::Result, protocol::{Kind, Protocol}, server1::Server};
use tracing::{error, info, info_span, Level};

#[tokio::test]
pub async fn test() -> Result<()> {
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
pub async fn test1() -> Result<()> {
    let mut conn = client1::connect("localhost", 3333).await?;
    let p = Protocol::new(
        Kind::TCP,
        "pwd".to_string(),
        "google.com".to_string(),
        443,
        None,
    );
    let mut buf = p.encode().expect("encode failed");
    conn.write_all(&buf).await.expect("write error");
    conn.write_finish().await.expect("close send stream");
    conn.read_all(&mut buf).await.expect("read error");
    dbg!(buf);
    Ok(())
}
