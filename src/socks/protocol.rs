use thiserror::Error;

pub struct Request {
    version: Version,
    cmd: Command,
    addr_type: Addr,
    port: u16,
}

pub enum Version {
    V4,
    V5,
}

pub enum Command {
    Connect,
    Bind,
    UDPAsociate,
}

pub enum Addr {
    IPV4([u8; 4]),
    IPV6([u8; 16]),
    DomainName(Vec<u8>),
}

impl Addr {
    fn new(buf: &[u8]) -> Result<Self> {
        buf.get(0)
            .and_then(|tp| match *tp {
                1 => {
                    let mut arr = [0; 4];
                    arr[..4].clone_from_slice(&buf[4..(4 + 4)]);
                    Some(Addr::IPV4(arr))
                }
                4 => {
                    let mut arr = [0; 16];
                    arr[..16].clone_from_slice(&buf[4..(16 + 4)]);
                    Some(Addr::IPV6(arr))
                }
                3 => {
                    let size = buf.get(1).map(|l| -> usize {
                        *l as usize
                    });
                    if let Some(size) = size {
                        let mut domain = vec![0; 256];
                        for i in 0..size {
                            domain.push(buf[i + 1]);
                        }
                        Some(Addr::DomainName(domain))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .ok_or(Error::InvalidateAddress)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unsuported socks version.")]
    UnsupportedVersion,
    #[error("Unsuported socks command.")]
    UnsupportedCommand,
    #[error("Invalidate address")]
    InvalidateAddress,
    #[error("Invalidate domain name")]
    InvalidateDomain,
}

type Result<T> = std::result::Result<T, Error>;

impl Request {
    pub fn new(buf: &[u8]) -> Result<Self> {
        let ver = buf
            .get(0)
            .and_then(|v| {
                if *v == 5 {
                    Some(Version::V5)
                } else {
                    None
                }
            })
            .ok_or(Error::UnsupportedVersion)?;
        let cmd = buf
            .get(1)
            .and_then(|c| match *c {
                1 => Some(Command::Connect),
                2 => Some(Command::Bind),
                3 => Some(Command::UDPAsociate),
                _ => None,
            })
            .ok_or(Error::UnsupportedCommand)?;
        todo!()
    }
}
