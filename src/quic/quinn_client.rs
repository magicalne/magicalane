use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

use quinn::{Connection, Endpoint, NewConnection};
use tracing::{error, trace};

use crate::{
    error::{Error, Result},
    ALPN_QUIC,
};

pub struct QuinnClient {
    remote_addr: SocketAddr,
    endpoint: Endpoint,
    server_name: String,
}

impl QuinnClient {
    pub async fn new(
        server_name: String,
        port: u16,
        cert_path: Option<PathBuf>,
    ) -> Result<Self> {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(ALPN_QUIC);
        client_config.enable_keylog();
        cert_path
            .map(|path| {
                fs::read(path)
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
                    })
            })
            .map(|r| {
                r.map_err(|err| {
                    error!("Client config cert with error: {:?}.", err);
                })
            });
        let config = client_config.build();
        let remote_addr = (server_name.as_str(), port)
            .to_socket_addrs()?
            .find(|add| add.is_ipv4())
            .ok_or(Error::UnknownRemoteHost)?;
        trace!("Connect remote: {:?}", &remote_addr);
        let mut endpoint_builder = Endpoint::builder();
        endpoint_builder.default_client_config(config);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // Bind this endpoint to a UDP socket on the given client address.
        let (endpoint, _) = endpoint_builder.bind(&addr)?;
        trace!("Client bind endpoint: {:?}", &addr);

        Ok(Self {
            remote_addr,
            endpoint,
            server_name,
        })
    }

    pub async fn open_conn(&mut self) -> Result<Connection> {
        let connection = self
            .endpoint
            .connect(&self.remote_addr, &self.server_name)?
            .await?;
        let NewConnection { connection, .. } = connection;
        Ok(connection)
    }
}
