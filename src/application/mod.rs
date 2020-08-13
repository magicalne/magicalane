pub mod quic_client;
pub mod quic_server;

#[cfg(test)]
mod test {
    use super::*;
    #[tokio::test]
    async fn test() {
        let server = quic_server::QuicServer::new(
            4443,
            None,
            None
        ).unwrap();
        server.await;
        dbg!("test");
        // rt.spawn(server);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let client = quic_client::QuicClient::new(
            "localhost".into(),
            4443,
            true
        ).unwrap();
    }
}