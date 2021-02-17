use bytes::{BytesMut, BufMut};
use anyhow::Result;
use nom::{
    IResult,
    sequence::terminated,
    character::is_alphanumeric,
    number::complete::be_u16,
    bytes::complete::{tag, take, take_while},
};
use tracing::error;
use crate::error::MagicalaneError;
use std::net::{ToSocketAddrs, SocketAddr};

#[derive(Debug, Eq, PartialEq)]
pub enum Kind {
    //0
    TCP,
    //1
    UDP,
    Error
}

const SPLIT: u8 = b'\0';

#[derive(Debug, Eq, PartialEq)]
pub struct Protocol {
    pub kind: Kind,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub payload: Option<Vec<u8>>,
}

impl Protocol {
    pub fn new(kind: Kind,
               password: String,
               host: String,
               port: u16,
               payload: Option<Vec<u8>>) -> Self {
        Protocol {
            kind,
            password,
            host,
            port,
            payload,
        }
    }

    pub fn encode(&self) -> Result<BytesMut> {
        let mut bytes = BytesMut::new();
        bytes.put_u8(match self.kind {
            Kind::TCP => 0u8,
            Kind::UDP => 1u8,
            _ => 2u8
        });
        bytes.put_slice(self.password.clone().as_bytes());
        bytes.put_u8(SPLIT);
        bytes.put_slice(self.host.clone().as_bytes());
        bytes.put_u8(SPLIT);
        bytes.put_u16(self.port);
        if self.payload.is_some() {
            bytes.put_slice(&self.payload.clone().unwrap()[..])
        }
        Ok(bytes)
    }

    pub fn parse(i: &[u8]) -> Result<Self, MagicalaneError> {
        match protocol_parser(&i) {
            Ok((_, protocol)) => {
                Ok(protocol)
            }
            Err(err) => {
                error!("parse error: {:?}", err);
                Err(MagicalaneError::ParseError)
            },
        }
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let uri = format!("{}:{}", self.host.clone(), self.port);
        if let Ok(mut socket) = uri.to_socket_addrs() {
            return socket.next()
        }
        None
    }
}

fn parse_kind(i: &[u8]) -> Kind {
    match i.first() {
        Some(0u8) => {
            Kind::TCP
        }
        Some(1u8) => {
            Kind::UDP
        },
        _ => Kind::Error
    }
}

fn protocol_parser(i: &[u8]) -> IResult<&[u8], Protocol> {
    let (i, o) = take(1usize)(i)?;
    let kind = parse_kind(o);
    let split = b"\0";
    let (i, o) = terminated(take_while(is_alphanumeric), tag(split))(i)?;
    let password = String::from_utf8(o.to_vec()).expect("parse password failed");
    let (i, o) = terminated(
        take_while(|c| is_alphanumeric(c) || c == b'.' || c == b'-' || c == b'_'),
        tag(split)
    )(i)?;
    let host = String::from_utf8(o.to_vec()).expect("parse host failed");

    let (i, o) = take(2usize)(i)?;
    let (_, port) = be_u16(o)?;
    let payload = if i.is_empty() {
        None
    } else {
        Some(i.to_vec())
    };
    Ok((i, Protocol {
        kind,
        password,
        host,
        port,
        payload
    }))
}

#[test]
fn test() {
    let i: Vec<u8> = vec![0, 49, 50, 51, 0, 98, 97, 105, 100, 117, 46, 99, 111, 109, 0, 1, 187, 22, 3, 1, 2, 0, 1, 0, 1, 252, 3, 3, 206, 59, 193, 161, 52, 141, 134, 226, 229, 44, 251, 231, 111, 57, 149, 105, 14, 119, 76, 134, 20, 218, 118, 196, 141, 234, 63, 111, 184, 225, 136, 116, 32, 131, 131, 17, 181, 63, 179, 160, 123, 36, 82, 224, 42, 89, 71, 44, 211, 92, 184, 138, 247, 128, 119, 223, 122, 130, 100, 191, 122, 154, 233, 215, 191, 0, 62, 19, 2, 19, 3, 19, 1, 192, 44, 192, 48, 0, 159, 204, 169, 204, 168, 204, 170, 192, 43, 192, 47, 0, 158, 192, 36, 192, 40, 0, 107, 192, 35, 192, 39, 0, 103, 192, 10, 192, 20, 0, 57, 192, 9, 192, 19, 0, 51, 0, 157, 0, 156, 0, 61, 0, 60, 0, 53, 0, 47, 0, 255, 1, 0, 1, 117, 0, 0, 0, 14, 0, 12, 0, 0, 9, 98, 97, 105, 100, 117, 46, 99, 111, 109, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 12, 0, 10, 0, 29, 0, 23, 0, 30, 0, 25, 0, 24, 51, 116, 0, 0, 0, 16, 0, 11, 0, 9, 8, 104, 116, 116, 112, 47, 49, 46, 49, 0, 22, 0, 0, 0, 23, 0, 0, 0, 49, 0, 0, 0, 13, 0, 48, 0, 46, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 2, 3, 3, 1, 2, 1, 3, 2, 2, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 9, 8, 3, 4, 3, 3, 3, 2, 3, 1, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 126, 7, 63, 94, 107, 70, 76, 125, 130, 193, 46, 230, 67, 99, 246, 204, 75, 76, 197, 156, 65, 212, 239, 98, 83, 53, 148, 49, 29, 184, 134, 2, 0, 21, 0, 183, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let result = Protocol::parse(&i[..]).unwrap();
    println!("{:?}", result);
}

#[test]
fn protocol_encode_test() {
    let protocol = Protocol::new(
        Kind::TCP,
        "pw0".into(),
        "localhost".into(),
        2345,
        Some(b"111".to_vec()),
    );
    let bytes = protocol.encode();
    let vec = bytes.unwrap().to_vec();
    println!("bytes: {:?}, len: {:?}", &vec, vec.len());

    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_slice(b"pw0\0localhost\0");
    buf.put_u16(2345);
    buf.put_slice(b"111");
    assert_eq!(vec, buf);
}

#[test]
fn protocol_parser_test() {
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_slice(b"pwd\0localhost\0");
    buf.put_u16(23456);
    buf.put_slice(b"asdfadsfadfadsf");

    let result = Protocol::parse(&buf);
    let expect = Protocol {
        kind: Kind::TCP,
        password: "pwd".to_string(),
        host: "localhost".to_string(),
        port: 23456,
        payload: Some(b"asdfadsfadfadsf".to_vec()),
    };
    assert_eq!(result.unwrap(), expect);
}