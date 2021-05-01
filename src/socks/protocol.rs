use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    u16,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

//https://tools.ietf.org/html/rfc1928
const VERSION_V4: u8 = 0x04;
const VERSION_V5: u8 = 0x05;
const NO_AUTH_REQUIRED: u8 = 0x00;
const GSSAPI: u8 = 0x01;
const USERNAME_PASSWORD: u8 = 0x02;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const CONNECT: u8 = 0x01;
const BIND: u8 = 0x02;
const UDP_ASSOCIATE: u8 = 0x03;
const IP_V4: u8 = 0x01;
const IP_V6: u8 = 0x04;
const DOMAIN_NAME: u8 = 0x03;

pub const VERSION_METHOD_MESSAGE: [u8; 2] = [5, 0]; //socks5, no auth

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

pub type Result<T> = std::result::Result<T, Error>;

pub enum Method {
    NoAuthRequired,
    GSSAPI,
    UsernamePassword,
    IANAAssigned(u8),
    ReservedForPrivateMethods(u8),
    NoAcceptableMethods(u8),
}

impl Method {
    fn decode(b: u8) -> Self {
        match b {
            0 => Method::NoAuthRequired,
            1 => Method::GSSAPI,
            2 => Method::UsernamePassword,
            3..=0x7f => Method::IANAAssigned(b),
            0x8f..=0xef => Method::ReservedForPrivateMethods(b),
            _ => Method::NoAcceptableMethods(b),
        }
    }

    fn encode(self) -> u8 {
        match self {
            Method::NoAuthRequired => NO_AUTH_REQUIRED,
            Method::GSSAPI => GSSAPI,
            Method::UsernamePassword => USERNAME_PASSWORD,
            Method::IANAAssigned(b) => b,
            Method::ReservedForPrivateMethods(b) => b,
            Method::NoAcceptableMethods(b) => b,
        }
    }
}

#[derive(Debug)]
pub enum Version {
    V4,
    V5,
}

impl Version {
    fn decode(b: u8) -> Result<Self> {
        match b {
            VERSION_V4 => Ok(Version::V4),
            VERSION_V5 => Ok(Version::V5),
            _ => Err(Error::UnsupportedVersion),
        }
    }

    fn encode(self) -> u8 {
        match self {
            Version::V4 => VERSION_V4,
            Version::V5 => VERSION_V5,
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Connect,
    Bind,
    UDPAsociate,
}

impl Command {
    fn decode(b: u8) -> Result<Self> {
        match b {
            CONNECT => Ok(Command::Connect),
            BIND => Ok(Command::Bind),
            UDP_ASSOCIATE => Ok(Command::UDPAsociate),
            _ => Err(Error::UnsupportedCommand),
        }
    }

    fn encode(self) -> u8 {
        match self {
            Command::Connect => CONNECT,
            Command::Bind => BIND,
            Command::UDPAsociate => UDP_ASSOCIATE,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Addr {
    SocketAddr(SocketAddr),
    DomainName(Vec<u8>, u16),
}

impl Addr {
    pub fn decode(buf: &[u8]) -> Result<Self> {
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
                        let port = (buf[1 + size] as u16) << 8 | (buf[2 + size] as u16);
                        Some(Self::DomainName(Vec::from(&buf[2..(2 + size)]), port))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .ok_or(Error::InvalidateAddress)
    }

    pub fn encode(&self, buf: &mut BytesMut) {
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

#[derive(Debug)]
pub struct Request {
    pub ver: Version,
    pub cmd: Command,
    pub addr: Addr,
}

impl Request {
    pub fn new(buf: &[u8]) -> Result<Self> {
        let ver = buf
            .get(0)
            .and_then(|v| if *v == 5 { Some(Version::V5) } else { None })
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
        let buf = &buf[3..];
        let addr = Addr::decode(&buf)?;
        Ok(Self { ver, cmd, addr })
    }
}

/**
 REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
*/
pub enum Rep {
    Suceeded,
    GeneralSocksServerFailure,
    ConnectionNotAllowedByRuleset,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TTLExpired,
    CommandNotSupported,
    AddressTypeNotSuported,
    Unassigned,
}

impl Rep {
    fn encode(self) -> u8 {
        match self {
            Rep::Suceeded => 0,
            Rep::GeneralSocksServerFailure => 1,
            Rep::ConnectionNotAllowedByRuleset => 2,
            Rep::NetworkUnreachable => 3,
            Rep::HostUnreachable => 4,
            Rep::ConnectionRefused => 5,
            Rep::TTLExpired => 6,
            Rep::CommandNotSupported => 7,
            Rep::AddressTypeNotSuported => 8,
            Rep::Unassigned => 9,
        }
    }
}

pub struct Reply<'a> {
    ver: Version,
    rep: Rep,
    addr: &'a Addr,
}

impl<'a> Reply<'a> {
    pub fn v5(rep: Rep, addr: &'a Addr) -> Self {
        Self {
            ver: Version::V5,
            rep,
            addr,
        }
    }

    pub fn encode(self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(self.ver.encode());
        buf.put_u8(self.rep.encode());
        buf.put_u8(0); //reserved
        self.addr.encode(&mut buf);
        buf
    }
}

#[cfg(test)]
mod tests {

    use bytes::{Buf, BufMut, BytesMut};

    use crate::socks;

    use super::{Rep, Reply, Request};
    #[test]
    fn test_protocol() -> socks::protocol::Result<()> {
        let mut buf = BytesMut::new();
        buf.put_u8(5);
        buf.put_u8(1);
        buf.put_u8(0);
        buf.put_u8(1);
        buf.put_slice(&[192, 168, 1, 1]);
        buf.put_u16(1080);
        let req = Request::new(&buf)?;
        let reply = Reply::v5(Rep::Suceeded, req.addr);
        let buf = reply.encode();
        let mut expect = BytesMut::new();
        expect.put_u8(5);
        expect.put_u8(0);
        expect.put_u8(0);
        expect.put_u8(1);
        expect.put_slice(&[192, 168, 1, 1]);
        expect.put_u16(1080);
        assert_eq!(expect.chunk(), buf.chunk());

        Ok(())
    }

    #[test]
    fn test() {
        let vec = vec![0; 1];
        let mut buf = vec.into_boxed_slice();
        dbg!(buf.len());
        let arr = [1, 2, 3, 34, 1, 1];
        buf[0..arr.len()].clone_from_slice(&arr);
    }
}
