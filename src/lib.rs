//! An implementation of the GDB Remote Serial Protocol, following
//! https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html

#![cfg_attr(feature = "unstable", feature(non_exhaustive))]

use std::fmt;

pub mod io;
pub mod packet;
pub mod parser;

#[derive(Debug)]
#[cfg_attr(feature = "unstable", non_exhaustive)]
pub enum Error {
    IoError(std::io::Error),
    NonNumber(String, std::num::ParseIntError),
    NonUtf8(Vec<u8>, std::str::Utf8Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(err) => write!(f, "i/o error: {}", err),
            Error::NonNumber(string, err) => {
                write!(f, "expected number, found {:?}: {}", string, err)
            }
            Error::NonUtf8(bytes, err) => write!(
                f,
                "expected UTF-8 string in this context, found {:?}: {}",
                bytes, err
            ),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(err) => Some(err),
            Error::NonNumber(_, err) => Some(err),
            Error::NonUtf8(_, err) => Some(err),
            // TODO: _ => None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}
