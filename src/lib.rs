use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use error::Result;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

pub mod config;
pub mod connector;
pub mod error;
pub mod kcp;
pub(crate) mod proxy;
pub mod dns;
pub mod httpin;
pub mod tproxy;
pub mod routing;
pub mod udp;
pub mod dispatch;
pub mod quic;
pub mod socks5;

/// ALPN protocol identifier used by the QUIC transport.
pub const ALPN_QUIC: &[&[u8]] = &[b"magicalane-1"];

/// Build a quinn `TransportConfig` from optional tuning. Defaults to
/// quinn's own (cubic congestion control, default windows).
pub fn transport_config(tuning: Option<&config::QuicTuning>) -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    if let Some(t) = tuning {
        let factory: std::sync::Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> = match t.congestion_name() {
            "bbr" => Arc::new(quinn::congestion::BbrConfig::default()),
            "new-reno" | "newreno" | "reno" => Arc::new(quinn::congestion::NewRenoConfig::default()),
            "cubic" => Arc::new(quinn::congestion::CubicConfig::default()),
            other => {
                log::warn!("unknown congestion controller {other:?}, falling back to cubic");
                Arc::new(quinn::congestion::CubicConfig::default())
            }
        };
        tc.congestion_controller_factory(factory);
        if let Some(w) = t.send_window {
            tc.send_window(w);
        }
        if let Some(w) = t.receive_window {
            tc.receive_window(quinn::VarInt::from_u64(w).unwrap_or(quinn::VarInt::MAX));
        }
        if let Some(w) = t.stream_receive_window {
            tc.stream_receive_window(quinn::VarInt::from_u64(w).unwrap_or(quinn::VarInt::MAX));
        }
    }
    Arc::new(tc)
}

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
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let key = cert.key_pair.serialize_der();
        let cert = cert.cert.der();
        fs::create_dir_all(path)?;
        fs::write(&cert_path, cert)?;
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
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let key = cert.key_pair.serialize_pem();
        let cert = cert.cert.pem();
        fs::create_dir_all(path)?;
        fs::write(&cert_path, cert)?;
        fs::write(&key_path, &key)?;
    }
    Ok((key_path, cert_path))
}

pub fn load_private_key(key_path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(key_path)?;
    let key = if key_path.extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &key[..])?.ok_or(error::Error::InvalidPrivateKey(
            key_path.display().to_string(),
        ))?
    };
    Ok(key)
}

pub fn load_private_cert(cert_path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let cert_chain = fs::read(cert_path)?;
    let chain = if cert_path
        .extension()
        .is_some_and(|x| x == "der" || x == "crt")
    {
        vec![CertificateDer::from(cert_chain)]
    } else {
        rustls_pemfile::certs(&mut &cert_chain[..]).collect::<std::io::Result<Vec<_>>>()?
    };
    Ok(chain)
}
