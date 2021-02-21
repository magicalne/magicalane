use std::{fs, future::Future, path::PathBuf, task::Poll};

use bytes::{Buf, Bytes, BytesMut};
use error::{Error, Result};
use futures::{future, ready, FutureExt};
use quic::RecvStream;
use quinn::{CertificateChain, PrivateKey};

use protocol::Protocol;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite}, net::{TcpStream, UdpSocket}};

pub mod error;
pub mod protocol;
pub mod quic;
pub mod server1;
pub mod transport;

pub const ALPN_QUIC: &[&[u8]] = &[b"hq-29"];

pub fn generate_key_and_cert_der() -> Result<(PathBuf, PathBuf)> {
    let dirs = directories::ProjectDirs::from("org", "tls", "examples").unwrap();
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    if !cert_path.exists() || !key_path.exists() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = cert.serialize_private_key_der();
        let cert = cert.serialize_der()?;
        fs::create_dir_all(&path)?;
        fs::write(&cert_path, &cert)?;
        fs::write(&key_path, &key)?;
    }
    Ok((key_path, cert_path))
}

pub fn generate_key_and_cert_pem() -> Result<(PathBuf, PathBuf)> {
    let dirs = directories::ProjectDirs::from("org", "tls", "examples").unwrap();
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.pem");
    let key_path = path.join("key.pem");
    if !cert_path.exists() || !key_path.exists() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = cert.serialize_private_key_pem();
        let cert = cert.serialize_pem()?;
        fs::create_dir_all(&path)?;
        fs::write(&cert_path, &cert)?;
        fs::write(&key_path, &key)?;
    }
    Ok((key_path, cert_path))
}

fn load_private_key(key_path: PathBuf) -> Result<PrivateKey> {
    let key = fs::read(&key_path)?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        quinn::PrivateKey::from_der(&key)?
    } else {
        quinn::PrivateKey::from_pem(&key)?
    };
    Ok(key)
}

fn load_private_cert(cert_path: PathBuf) -> Result<CertificateChain> {
    let cert_chain = fs::read(&cert_path)?;
    let cert_chain = if cert_path
        .extension()
        .map_or(false, |x| x == "der" || x == "crt")
    {
        quinn::CertificateChain::from_certs(quinn::Certificate::from_der(&cert_chain))
    } else {
        quinn::CertificateChain::from_pem(&cert_chain)?
    };
    Ok(cert_chain)
}

pub struct Connection<C: quic::Connection<Bytes>> {
    connection: C,
}

impl<C: quic::Connection<Bytes>> Connection<C> {
    pub fn new(connection: C) -> Self {
        Self { connection }
    }

    pub async fn connect(&mut self) -> Result<ConnectionStream<C::BidiStream>> {
        let stream = future::poll_fn(|cx| self.connection.poll_open_bidi_stream(cx)).await?;
        Ok(ConnectionStream::new(stream))
    }

    pub async fn accept(&mut self) -> Result<ConnectionStream<C::BidiStream>> {
        let stream = future::poll_fn(|cx| self.connection.poll_accept_bidi_stream(cx)).await?;
        Ok(ConnectionStream::new(stream))
    }
}

pub struct ConnectionStream<S> {
    stream: S,
}

impl<S: quic::BidiStream<Bytes>> ConnectionStream<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub async fn proxy(self) -> Result<()> {
        let (send, mut recv) = self.stream.split();
        // if let Some(n) = future::poll_fn(|cx| recv.poll_data(cx)).await? {
        //     recv

        //     let protocol = Protocol::parse(buf.chunk())?;
        //     match protocol.kind {
        //         protocol::Kind::TCP => {
        //             let addr = (protocol.host.as_str(), protocol.port);
        //             let stream = TcpStream::connect(addr).await?;
        //             let (r, s) = stream.into_split();
        //         }
        //         protocol::Kind::UDP => {
        //             let addr = (protocol.host.as_str(), protocol.port);
        //             let stream = UdpSocket::connect(addr).await?;
        //             let (r, s) = stream.into_split();
        //         }
        //         protocol::Kind::Error => return Err(Error::UnknowProtocolKindErrlr),
        //     }
        // }
        Ok(())
    }
}

pub struct Proxy<R: AsyncRead, W: AsyncWrite> {
    src_recv: R,
    src_send: W,
    dst_recv: R,
    dst_send: W,
}

#[pin_project::pin_project]
pub struct TcpRecvStream {
    #[pin]
    stream: TcpStream,
    buf: BytesMut,
}

impl<'a> TcpRecvStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buf: BytesMut::new(),
        }
    }
}
