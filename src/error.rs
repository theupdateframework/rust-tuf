//! Error types and converters.
use json;
use std::io;
use std::path::Path;
use hyper;

/// Error type for all TUF related errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Generic(String),
    Io(String),
    Serde(String),
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
