use std::{fs, path::PathBuf};

pub mod error;
pub mod protocol;
pub mod quic;

pub const ALPN_QUIC: &[&[u8]] = &[b"hq-29"];

pub fn generate_key_and_cert_der() -> error::Result<(PathBuf, PathBuf)> {
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

pub fn generate_key_and_cert_pem() -> error::Result<(PathBuf, PathBuf)> {
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