use core::{Role, KeyId};

#[derive(Debug)]
pub enum TufError {
    InvalidConfig(String),
    InvalidRole(String),
    MissingRole(Role),
    NonUniqueSignatures,
    SignatureSchemeMismatch,
    ThresholdNotMet(Role),
    UnknownKey(KeyId),
    VerificationFailure(VerificationFailure),
}

#[derive(Debug)]
pub enum VerificationFailure {
    Undefined, // TODO remove this later
}
