use json;
use std::io;

use metadata::{KeyId, Role};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    CanonicalJsonError(String),
    ExpiredMetadata,
    InvalidConfig(String),
    Io(String),
    Json(String),
    MissingMetadata(Role),
    NonUniqueSignatures,
    NoSupportedHashAlgorithms,
    SignatureSchemeMismatch,
    TargetHashMismatch,
    UnknownKey(KeyId),
    UnknownRole(String),
    UnknownTarget,
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
