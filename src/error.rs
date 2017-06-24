//! Error types and converters.
use data_encoding::DecodeError;
use hyper;
use json;
use pem;
use std::io;
use std::path::Path;

use rsa::der;

/// Error type for all TUF related errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadSignature,
    Decode(String),
    Encode(String),
    Generic(String),
    Io(String),
    Serde(String),
    Opaque(String),
    UnsupportedKeyFormat(String),
    UnsupportedKeyType(String),
    UnsupportedSignatureScheme(String),
}

impl From<json::error::Error> for Error {
    fn from(err: json::error::Error) -> Error {
        Error::Serde(format!("{:?}", err))
    }
}

impl Error {
    /// Helper to include the path that causd the error for FS I/O errors.
    pub fn from_io(err: io::Error, path: &Path) -> Error {
        Error::Io(format!("Path {:?} : {:?}", path, err))
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(format!("{:?}", err))
    }
}

impl From<hyper::error::Error> for Error {
    fn from(err: hyper::error::Error) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

impl From<hyper::error::ParseError> for Error {
    fn from(err: hyper::error::ParseError) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Error {
        Error::Decode(format!("{:?}", err))
    }
}

impl From<pem::Error> for Error {
    fn from(err: pem::Error) -> Error {
        Error::Decode(format!("{:?}", err))
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Io("Error reading/writing DER".into())
    }
}
