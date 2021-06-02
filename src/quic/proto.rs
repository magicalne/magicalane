use std::usize;

use crate::error::{Error, Result};

/// `buf` is read from IO and compare buf with password.
pub fn compare_passwd(buf: &[u8], passwd: &[u8]) -> Result<()> {
    if buf.is_empty() {
        return Err(Error::EmptyPassword);
    }

    let n = buf[0] as usize;
    if buf.len() <= n {
        return Err(Error::WrongPassword);
    }
    if &buf[1..n + 1] == passwd {
        Ok(())
    } else {
        Err(Error::WrongPassword)
    }
}

#[test]
fn compare_passwd_test() {
    let passwd = [0, 1, 2, 3, 4];
    let buf = [5, 0, 1, 2, 3, 4, 0, 0, 0];
    assert!(compare_passwd(&buf[..], &passwd[..]).is_ok());
    let buf = [4, 1, 2, 3, 4, 0, 0, 0];
    assert!(compare_passwd(&buf[..], &passwd[..]).is_err());
    let buf = [4, 1, 2, 3];
    assert!(compare_passwd(&buf[..], &passwd[..]).is_err());
}
