//! Error types and converters.

use data_encoding::DecodeError;
use derp;
use hyper;
use serde_json;
use std::fmt;
use std::io;
use std::path::Path;
use tempfile;

use crate::metadata::Role;

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
    /// There is no known or available hash algorithm.
    UnkonwnHashAlgorithm(String),
    /// There is no known or available key type.
    UnknownKeyType(String),
    /// The metadata or target failed to verify.
    VerificationFailure(String),
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::BadSignature => "bad signature",
            Error::Encoding(_) => "encoding",
            Error::ExpiredMetadata(_) => "expired metadata",
            Error::IllegalArgument(_) => "illegal argument",
            Error::MissingMetadata(_) => "missing metadata",
            Error::NoSupportedHashAlgorithm => "no supported hash algorithm",
            Error::NotFound => "not found",
            Error::Opaque(_) => "opaque",
            Error::Programming(_) => "programming",
            Error::TargetUnavailable => "target unavailable",
            Error::UnkonwnHashAlgorithm(_) => "unknown hash algorithm",
            Error::UnknownKeyType(_) => "unknown key type",
            Error::VerificationFailure(_) => "verification failure",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Error {
        Error::Encoding(format!("JSON: {:?}", err))
    }
}

impl Error {
    /// Helper to include the path that causd the error for FS I/O errors.
    pub fn from_io(err: &io::Error, path: &Path) -> Error {
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

impl From<derp::Error> for Error {
    fn from(err: derp::Error) -> Error {
        Error::Encoding(format!("DER: {:?}", err))
    }
}

impl From<tempfile::PersistError> for Error {
    fn from(err: tempfile::PersistError) -> Error {
        Error::Opaque(format!("Error persisting temp file: {:?}", err))
    }
}
