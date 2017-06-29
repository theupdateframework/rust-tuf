//! Error types and converters.

use data_encoding::DecodeError;
use hyper;
use json;
use pem;
use std::io;
use std::path::Path;
use tempfile;

use metadata::Role;
use rsa::der;

/// Error type for all TUF related errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The metadata had a bad signature.
    BadSignature,
    /// There was a problem encoding or decoding.
    Encoding(String),
    /// Metadata was expired.
    ExpiredMetadata(Role),
    /// An illegal argument was passed into a function.
    IllegalArgument(String),
    /// The metadata was missing, so an operation could not be completed.
    MissingMetadata(Role),
    /// There were no available hash algorithms.
    NoSupportedHashAlgorithm,
    /// The metadata or target was not found.
    NotFound,
    /// Opaque error type, to be interpreted similar to HTTP 500. Something went wrong, and you may
    /// or may not be able to do anything about it.
    Opaque(String),
    /// There was a library internal error. These errors are *ALWAYS* bugs and should be reported.
    Programming(String),
    /// The target is unavailable. This may mean it is either not in the metadata or the metadata
    /// chain to the target cannot be fully verified.
    TargetUnavailable,
    /// The metadata or target failed to verify.
    VerificationFailure(String),
}

impl From<json::error::Error> for Error {
    fn from(err: json::error::Error) -> Error {
        Error::Encoding(format!("JSON: {:?}", err))
    }
}

impl Error {
    /// Helper to include the path that causd the error for FS I/O errors.
    pub fn from_io(err: io::Error, path: &Path) -> Error {
        Error::Opaque(format!("Path {:?} : {:?}", path, err))
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Opaque(format!("IO: {:?}", err))
    }
}

impl From<hyper::error::Error> for Error {
    fn from(err: hyper::error::Error) -> Error {
        Error::Opaque(format!("Hyper: {:?}", err))
    }
}

impl From<hyper::error::ParseError> for Error {
    fn from(err: hyper::error::ParseError) -> Error {
        Error::Opaque(format!("Hyper: {:?}", err))
    }
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Error {
        Error::Encoding(format!("{:?}", err))
    }
}

impl From<pem::Error> for Error {
    fn from(err: pem::Error) -> Error {
        Error::Encoding(format!("{:?}", err))
    }
}

impl From<der::Error> for Error {
    fn from(_: der::Error) -> Error {
        Error::Opaque("Error reading/writing DER".into())
    }
}

impl From <tempfile::PersistError> for Error {
    fn from(err: tempfile::PersistError) -> Error {
        Error::Opaque(format!("Error persisting temp file: {:?}", err))
    }
}
