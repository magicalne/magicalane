use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    rc::Rc,
    sync::Arc,
};

use futures::{Future, StreamExt, future::try_join, ready};

use tracing::{error, trace};

use crate::{
    error::{Error, Result},
    quic::quic_quinn::QuinnServer,
    ALPN_QUIC,
};

pub struct Server {
    quinn_server: QuinnServer,
}

impl Server {
    pub async fn new(
        key_cert: Option<(PathBuf, PathBuf)>,
        port: u16,
        password: String,
    ) -> Result<Self> {
        let quinn_server = QuinnServer::new(key_cert, port, password).await?;
        Ok(Self { quinn_server })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some(conn) = self.quinn_server.next().await {
            match conn {
                Ok(mut conn) => {
                    tokio::spawn(async move {
                        if let Ok(()) = conn.validate_password().await {
                            tokio::spawn(async move {
                                if let Ok(mut transfer) = conn.open_remote().await {
                                    if let Err(err) = transfer.copy().await {
                                        error!("Transfer error: {:?}", err);
                                    }
                                }
                            });
                        }
                    });
                }
                Err(err) => {
                    error!("Connection error: {:?}", err);
                }
            }
        }
        Ok(())
    }
}
