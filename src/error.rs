use hyper;
use json;
use std::io;

use metadata::{KeyId, Role};

/// Error type for all TUF related errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    CanonicalJsonError(String),
    ExpiredMetadata(Role),
    Generic(String),
    Http(String),
    InvalidConfig(String),
    Io(String),
    Json(String),
    MetadataHashMismatch(Role),
    MissingMetadata(Role),
    NonUniqueSignatures,
    NoSupportedHashAlgorithms,
    OversizedMetadata(Role),
    OversizedTarget,
    SignatureSchemeMismatch,
    TargetHashMismatch,
    UnknownKey(KeyId),
    UnknownRole(String),
    UnknownTarget,
    UnmetThreshold(Role),
    UnsupportedKeyType(String),
    UnsupportedSignatureScheme(String),
    VerificationFailure(String),
    VersionDecrease(Role),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(format!("{:?}", err))
    }
}

impl From<json::Error> for Error {
    fn from(err: json::Error) -> Error {
        Error::Json(format!("{:?}", err))
    }
}

impl From<hyper::error::Error> for Error {
    fn from(err: hyper::error::Error) -> Error {
        Error::Http(format!("{:?}", err))
    }
}

impl From<hyper::error::ParseError> for Error {
    fn from(err: hyper::error::ParseError) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}
