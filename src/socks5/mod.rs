use std::mem::MaybeUninit;

use bytes::BufMut;
use tokio::io::ReadBuf;

pub mod conn;
pub mod error;
pub mod proto;
pub mod server;

pub type Result<T> = std::result::Result<T, error::Error>;

pub fn to_read_buf<'a>(buf: &mut impl BufMut) -> ReadBuf<'a> {
    let dst = buf.chunk_mut();
    let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
    ReadBuf::uninit(dst)
}
