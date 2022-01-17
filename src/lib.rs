use std::{
    fs,
    path::{Path, PathBuf},
};

use error::Result;
use quinn::{CertificateChain, PrivateKey};

pub mod config;
pub mod connector;
pub mod error;
pub(crate) mod proxy;
pub mod quic;
pub mod socks5;

pub const ALPN_QUIC: &[&[u8]] = &[b"hq-29"];

pub fn generate_key_and_cert_der(
    qualifier: &str,
    org: &str,
    application: &str,
) -> Result<(PathBuf, PathBuf)> {
    let dirs = directories::ProjectDirs::from(qualifier, org, application).unwrap();
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

pub fn generate_key_and_cert_pem(
    qualifier: &str,
    org: &str,
    application: &str,
) -> Result<(PathBuf, PathBuf)> {
    let dirs = directories::ProjectDirs::from(qualifier, org, application).unwrap();
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

pub fn load_private_key(key_path: &Path) -> Result<PrivateKey> {
    let key = fs::read(key_path)?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        quinn::PrivateKey::from_der(&key)?
    } else {
        quinn::PrivateKey::from_pem(&key)?
    };
    Ok(key)
}

pub fn load_private_cert(cert_path: &Path) -> Result<CertificateChain> {
    let cert_chain = fs::read(cert_path)?;
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
