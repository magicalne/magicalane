use std::{io::stderr, path::PathBuf};

use lib::{
    error::{Error, Result},
    generate_key_and_cert_der,
    protocol::{Kind, Protocol},
    quic::{quinn_client, quinn_server, stream::StreamActorHandler},
    server1::Server,
    socks::server::SocksServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tracing::{error, info, info_span, trace, Level};

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
    let path =
        PathBuf::from("/Users/magiclane/Library/Application Support/org.tls.examples/cert.der");
    // let path = PathBuf::from("/home/magicalne/.local/share/examples/cert.der");
    let mut socks =
        SocksServer::new(None, "localhost", 3333, Some(path), String::from("pwd")).await?;
    socks.start().await?;
    Ok(())
}

async fn tcp_echo_server() -> Result<()> {
    let tcp_listener = TcpListener::bind("localhost:2234").await?;
    while let Ok((mut stream, addr)) = tcp_listener.accept().await {
        trace!("accept addr: {:?}", addr);
        tokio::spawn(async move {
            let mut buf = vec![0; 128];
            let n = stream.read(&mut buf).await?;
            let m = stream.write(&buf[..n]).await?;
            trace!("Recv {:?} bytes, send {:?} bytes", n, m);
            Ok::<(), Error>(())
        });
    }
    Ok(())
}

#[tokio::test]
async fn single_client_test() -> Result<()> {
    /*
    Open an echo server. The request to echo server is proxy target.
    Setup a proxy server to serve.
    Setup a proxy client to accept multiple requests.
     */
    let echo_server = tokio::spawn(async move {
        tcp_echo_server().await?;
        Ok::<(), Error>(())
    });
    let quic_server = tokio::spawn(async move {
        let passwd = "pwd".to_string();
        let mut server = quinn_server::QuinnServer::new(None, 3334, passwd).await?;
        server.run().await?;
        Ok::<(), Error>(())
    });
    let (_, cert) = generate_key_and_cert_der()?;
    let mut client =
        quinn_client::QuinnClient::new("localhost".to_string(), 3334, Some(cert)).await?;
    let connection = client.open_conn().await?;
    let (send, recv) = connection.open_bi().await?;
    let mut stream_handler = StreamActorHandler::new(None);
    let passwd = b"pwd";
    let passwd = Vec::from(&passwd[..]);
    stream_handler.send_passwd(send, recv, passwd).await?;
    for _ in 0..10 {
        let mut stream_handler = stream_handler.clone();
        tokio::spawn(async move {
            //TODO
            // stream_handler.send_addr(send, recv)
        });
    }
    Ok(())
}

#[test]
pub fn generate_cert() -> Result<()> {
    let (key, cert) = generate_key_and_cert_der()?;
    dbg!(key, cert);
    Ok(())
}
