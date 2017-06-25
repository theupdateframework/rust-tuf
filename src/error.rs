//! Error types and converters.

use data_encoding::DecodeError;
use hyper;
use json;
use pem;
use std::io;
use std::path::Path;

use metadata::Role;
use rsa::der;

/// Error type for all TUF related errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The metadata had a bad signature.
    BadSignature,
    /// There was a problem decoding the metadata.
    Decode(String),
    /// There was a problem encoding the metadata.
    Encode(String),
    /// Metadata was expired.
    ExpiredMetadata(Role),
    /// Generic catcher for all errors.
    Generic(String),
    /// An illegal argument was passed into a function.
    IllegalArgument(String),
    /// There was an IO error.
    Io(String),
    /// The metadata or target was not found.
    NotFound,
    /// There was an internal `serde` error.
    Serde(String),
    /// The key format is not supported.
    UnsupportedKeyFormat(String),
    /// The key type is not supported.
    UnsupportedKeyType(String),
    /// The signature scheme is not supported.
    UnsupportedSignatureScheme(String),
    /// The metadata or target failed to verify.
    VerificationFailure(String),
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
    fn from(_: der::Error) -> Error {
        Error::Io("Error reading/writing DER".into())
    }
}
