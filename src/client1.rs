use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
};

use quinn::{crypto::rustls::TlsSession, generic::NewConnection, Endpoint};

use crate::{error::Error, stream::QuinnBidiStream, Result, ALPN_QUIC};

pub struct QuinnClient {
    password: String,
    bidi: QuinnBidiStream<TlsSession>,
}

impl QuinnClient {
    pub async fn new(password: String, host: &str, port: u16) -> Result<Self> {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(ALPN_QUIC);
        client_config.enable_keylog();
        // let dirs = directories_next::ProjectDirs::from("org", "tls", "examples").unwrap();
        let cert = fs::read("/home/magicalne/.local/share/examples/cert.der")?;
        // let cert = fs::read(dirs.data_local_dir().join("cert.der"))?;
        client_config
            .add_certificate_authority(quinn::Certificate::from_der(&cert)?)
            .map_err(|_| Error::WebPkiError)?;
        let config = client_config.build();
        let remote = (host, port)
            .to_socket_addrs()?
            .find(|add| add.is_ipv4())
            .ok_or(Error::UnknownRemoteHost)?;
        dbg!(&remote);
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.default_client_config(config);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // Bind this endpoint to a UDP socket on the given client address.
        let (endpoint, _) = endpoint_builder.bind(&addr)?;

        // Connect to the server passing in the server name which is supposed to be in the server certificate.
        let connection = endpoint.connect(&remote, host)?.await?;
        let NewConnection { connection, .. } = connection;
        dbg!(connection.stats());
        let (send, recv) = connection.open_bi().await?;
        dbg!(send.id(), recv.id());
        let bidi = QuinnBidiStream::new(send, recv);
        Ok(Self { password, bidi })
    }
}
