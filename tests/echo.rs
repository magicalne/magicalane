use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
};

use futures::StreamExt;
use lib::{
    error::{Error, Result},
    generate_key_and_cert_der, load_private_cert, load_private_key, ALPN_QUIC,
};
use quinn::{Endpoint, NewConnection, ServerConfig};
use tracing::{error, trace, Level};

#[tokio::test]
pub async fn echo_server() -> Result<()> {
    setup_log();
    let mut endpoint_builder = Endpoint::builder();
    let server_config = ServerConfig::default();
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.enable_keylog();
    let (key, cert) = generate_key_and_cert_der()?;
    let key = load_private_key(key.as_path())?;
    let cert_chain = load_private_cert(cert.as_path())?;
    server_config.certificate(cert_chain, key)?;
    server_config.protocols(ALPN_QUIC);
    endpoint_builder.listen(server_config.build());
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3334);
    let (_, mut incoming) = endpoint_builder.bind(&addr)?;

    while let Some(conn) = incoming.next().await {
        tokio::spawn(async move {
            let conn = conn.await?;
            let mut bi_stream = conn.bi_streams;
            tokio::spawn(async move {
                while let Some(Ok((mut send, mut recv))) = bi_stream.next().await {
                    let mut buf = vec![0; 128];
                    if let Some(n) = recv.read(&mut buf).await? {
                        send.write_all(&buf[..n]).await?;
                        send.finish().await?;
                    }
                }
                Ok::<(), Error>(())
            });
            Ok::<(), Error>(())
        });
    }
    Ok(())
}

#[tokio::test]
pub async fn echo_client() -> Result<()> {
    setup_log();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(ALPN_QUIC);
    client_config.enable_keylog();
    let (key, cert) = generate_key_and_cert_der()?;
    fs::read(cert)
        .map(|cert| quinn::Certificate::from_der(&cert))
        .map(|cert| match cert {
            Ok(cert) => {
                if let Err(err) = client_config.add_certificate_authority(cert) {
                    error!("Client add cert failed: {:?}.", err);
                }
            }
            Err(err) => {
                error!("Client parse cert error: {:?}.", err);
            }
        })?;
    let config = client_config.build();
    let remote = ("localhost", 3334)
        .to_socket_addrs()?
        .find(|add| add.is_ipv4())
        .ok_or(Error::UnknownRemoteHost)?;
    trace!("Connect remote: {:?}", &remote);
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(config);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    // Bind this endpoint to a UDP socket on the given client address.
    let (endpoint, incoming) = endpoint_builder.bind(&addr)?;
    trace!("Client bind endpoint: {:?}", &addr);

    let connection = endpoint.connect(&remote, "localhost")?.await?;
    let NewConnection { connection, .. } = connection;
    for i in 0..10usize {
        let (mut send, mut recv) = connection.open_bi().await?;
        tokio::spawn(async move {
            let buf = b"1111111";
            send.write_all(buf).await?;
            let mut buf = vec![0; 128];
            if let Some(n) = recv.read(&mut buf).await? {
                trace!("[{:?}] read: {:?} bytes, {:?}", i, n, &buf[..n]);
            }
            Ok::<(), Error>(())
        });
        // sleep(Duration::new(10, 0));
    }
    Ok(())
}

fn setup_log() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("no global subscriber has been set");
}
