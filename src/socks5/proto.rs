use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    usize,
};

use bytes::BufMut;
use log::trace;

use super::{error::Error, Result};

#[derive(Debug, Clone)]
pub enum Version {
    V4,
    V5,
}

impl Version {
    fn new(ver: u8) -> Result<Version> {
        match ver {
            4 => Ok(Version::V4),
            5 => Ok(Version::V5),
            _ => Err(Error::InvalidVersion(ver)),
        }
    }

    fn get_u8(&self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V5 => 5,
        }
    }
}

#[derive(Debug)]
pub enum Method {
    NoAuth,
    Gssapi,
    UsernamePassword,
    Ianna,
    Reserverd,
    NoAcceptableMethod,
}

impl Method {
    pub fn new(m: u8) -> Result<Method> {
        match m {
            0x00 => Ok(Method::NoAuth),
            0x01 => Ok(Method::Gssapi),
            0x02 => Ok(Method::UsernamePassword),
            0x03..=0x7F => Ok(Method::Ianna),
            0x80..=0xFE => Ok(Method::Reserverd),
            0xFF => Ok(Method::NoAcceptableMethod),
        }
    }

    pub fn get_u8(&self) -> u8 {
        match self {
            Self::NoAuth => 0,
            Self::Gssapi => 1,
            Self::UsernamePassword => 2,
            Self::Ianna => 3,
            Self::Reserverd => 0x80,
            Self::NoAcceptableMethod => 0xFF,
        }
    }
}

pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Command {
    pub fn new(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            _ => Err(Error::InvalidCommand(b)),
        }
    }

    pub fn get_u8(&self) -> u8 {
        match self {
            Command::Connect => 0,
            Command::Bind => 1,
            Command::UdpAssociate => 2,
        }
    }
}

#[derive(Clone)]
pub enum Addr {
    SocketAddr(SocketAddr),
    DomainName(Vec<u8>, u16),
}

impl Debug for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::SocketAddr(addr) => f.write_fmt(format_args!("SocksetAddr: {}", addr)),
            Addr::DomainName(buf, port) => {
                let domain = String::from_utf8_lossy(buf);
                f.write_fmt(format_args!("domain: {}:{}", domain, port))
            }
        }
    }
}

impl Addr {
    pub fn new(buf: &[u8]) -> Result<Self> {
        buf.get(0)
            .and_then(|tp| match *tp {
                1 => {
                    //1 flag, 4 bytes ipv4, 2 bytes port
                    if buf.len() >= 7 {
                        let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                        let port: u16 = ((buf[5] as u16) << 8) | (buf[6] as u16);
                        Some(Self::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
                            ip, port,
                        ))))
                    } else {
                        None
                    }
                }
                4 => {
                    //1 flat, 16 bytes ipv6, 2 bytes port
                    if buf.len() >= 19 {
                        let port = (buf[17] as u16) << 8 | (buf[18] as u16);
                        let ip = Ipv6Addr::new(
                            (buf[1] as u16) << 8 | (buf[2] as u16),
                            (buf[3] as u16) << 8 | (buf[4] as u16),
                            (buf[5] as u16) << 8 | (buf[6] as u16),
                            (buf[7] as u16) << 8 | (buf[8] as u16),
                            (buf[9] as u16) << 8 | (buf[10] as u16),
                            (buf[11] as u16) << 8 | (buf[12] as u16),
                            (buf[13] as u16) << 8 | (buf[14] as u16),
                            (buf[15] as u16) << 8 | (buf[16] as u16),
                        );
                        Some(Self::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                            ip, port, 0, 0,
                        ))))
                    } else {
                        None
                    }
                }
                3 => {
                    let size = buf.get(1).map(|l| -> usize { *l as usize });
                    if let Some(size) = size {
                        trace!(
                            "buf:[2+size]: {}, buf:[3+size]: {}",
                            buf[2 + size],
                            buf[3 + size]
                        );
                        let port = (buf[2 + size] as u16) << 8 | (buf[3 + size] as u16);
                        Some(Self::DomainName(Vec::from(&buf[2..(2 + size)]), port))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .ok_or(Error::InvalidAddress)
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        match self {
            Addr::SocketAddr(addr) => match addr {
                SocketAddr::V4(ipv4) => {
                    buf.put_u8(1);
                    buf.put_slice(&ipv4.ip().octets());
                    buf.put_u16(ipv4.port());
                }
                SocketAddr::V6(ipv6) => {
                    buf.put_u8(4);
                    buf.put_slice(&ipv6.ip().octets());
                    buf.put_u16(ipv6.port());
                }
            },
            Addr::DomainName(domain, port) => {
                buf.put_u8(3);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain);
                buf.put_u16(*port);
            }
        }
    }
}

pub enum Reply {
    Succeeded,
    GeneralSocksServerFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSuported,
    UnAssigned,
}

impl Reply {
    pub fn new(r: u8) -> Self {
        match r {
            0x00 => Self::Succeeded,
            0x01 => Self::GeneralSocksServerFailure,
            0x02 => Self::ConnectionNotAllowed,
            0x03 => Self::NetworkUnreachable,
            0x04 => Self::HostUnreachable,
            0x05 => Self::TtlExpired,
            0x06 => Self::CommandNotSupported,
            0x07 => Self::AddressTypeNotSuported,
            _ => Self::UnAssigned,
        }
    }

    pub fn encode(&self) -> u8 {
        match self {
            Reply::Succeeded => 0x00,
            Reply::GeneralSocksServerFailure => 0x01,
            Reply::ConnectionNotAllowed => 0x02,
            Reply::NetworkUnreachable => 0x03,
            Reply::HostUnreachable => 0x04,
            Reply::TtlExpired => 0x05,
            Reply::CommandNotSupported => 0x06,
            Reply::AddressTypeNotSuported => 0x07,
            Reply::UnAssigned => 0x08,
        }
    }
}

pub struct Decoder;

impl Decoder {
    // Version and method selection message.
    pub fn parse_connecting(buf: &[u8]) -> Result<(Version, Vec<Method>)> {
        if buf.len() < 3 {
            return Err(Error::InvalidMessage());
        }
        let ver = Version::new(buf[0])?;
        let n = buf[1];
        if n == 0 || buf[2..].len() != (n as usize) {
            return Err(Error::InvalidMessage());
        }
        let methods: Vec<Method> = buf[2..]
            .iter()
            .map(|b| Method::new(*b))
            .collect::<Result<Vec<Method>>>()?;
        Ok((ver, methods))
    }

    pub fn parse_nego_req(buf: &[u8]) -> Result<(Version, Command, Addr)> {
        let ver = match buf.get(0) {
            Some(b) => Version::new(*b)?,
            None => return Err(Error::InvalidMessage()),
        };
        let cmd = match buf.get(1) {
            Some(1) => Command::Connect,
            Some(2) => Command::Bind,
            Some(3) => Command::UdpAssociate,
            _ => return Err(Error::InvalidMessage()),
        };
        let buf = &buf[3..];
        let addr = Addr::new(buf)?;
        Ok((ver, cmd, addr))
    }
}

pub struct Encoder;

impl Encoder {
    pub fn encode_method_select_msg<B: BufMut>(ver: Version, method: &Method, buf: &mut B) {
        buf.put_u8(ver.get_u8());
        buf.put_u8(method.get_u8());
    }

    pub fn encode_server_reply<B: BufMut>(
        ver: &Version,
        rep: &Reply,
        addr: &Addr,
        mut buf: &mut B,
    ) {
        buf.put_u8(ver.get_u8());
        buf.put_u8(rep.encode());
        buf.put_u8(0x00); //reserved
        addr.encode(&mut buf);
    }
}
