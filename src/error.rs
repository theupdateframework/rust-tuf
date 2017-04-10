use json;
use std::io;

use metadata::{KeyId};

#[derive(Debug)]
pub enum TufError {
    InvalidConfig(String),
    Io(io::Error),
    Json(json::Error),
    NonUniqueSignatures,
    SignatureSchemeMismatch,
    UnknownKey(KeyId),
    UnknownRole(String),
    VerificationFailure(VerificationFailure),
}

impl From<io::Error> for TufError {
    fn from(err: io::Error) -> TufError {
        TufError::Io(err)
    }
}

impl From<json::Error> for TufError {
    fn from(err: json::Error) -> TufError {
        TufError::Json(err)
    }
}


#[derive(Debug)]
pub enum VerificationFailure {
    Undefined, // TODO remove this later
}
