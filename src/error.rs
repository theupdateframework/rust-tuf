use json;
use std::io;

use metadata::{KeyId};

#[derive(Debug)]
pub enum Error {
    CanonicalJsonError(String),
    InvalidConfig(String),
    Io(io::Error),
    Json(json::Error),
    NonUniqueSignatures,
    SignatureSchemeMismatch,
    UnknownKey(KeyId),
    UnknownRole(String),
    UnsupportedKeyType(String),
    UnsupportedSignatureScheme(String),
    VerificationFailure,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<json::Error> for Error {
    fn from(err: json::Error) -> Error {
        Error::Json(err)
    }
}

