use hyper::{client::service, server};
use lib::{error::Result, server1};
use server1::QuinnServer;

#[tokio::test]
pub async fn test() -> Result<()>{
    let server = QuinnServer::new(None, 3333, String::from("pwd"));
    server.run().await?;
    Ok(())
}