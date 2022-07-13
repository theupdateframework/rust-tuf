//! Error types and converters.

use data_encoding::DecodeError;
use std::io;
use thiserror::Error;

use crate::metadata::{MetadataPath, MetadataVersion, TargetPath};

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for all TUF related errors.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    /// The metadata had a bad signature.
    #[error("bad signature")]
    BadSignature(MetadataPath),

    /// There was a problem encoding or decoding.
    #[error("encoding: {0}")]
    Encoding(String),

    /// Metadata was expired.
    #[error("expired {0} metadata")]
    ExpiredMetadata(MetadataPath),

    /// An illegal argument was passed into a function.
    #[error("illegal argument: {0}")]
    IllegalArgument(String),

    /// Generic error for HTTP connections.
    #[error("http: {0}")]
    Http(#[from] http::Error),

    /// Unexpected HTTP response status.
    #[error("error getting {uri}: request failed with status code {code}")]
    BadHttpStatus {
        /// HTTP status code.
        code: http::StatusCode,

        /// URI Resource that resulted in the error.
        uri: String,
    },

    /// An IO error occurred.
    #[error("IO: {0}")]
    Io(#[from] io::Error),

    /// A json serialization error occurred.
    #[error("json: {0}")]
    Json(#[from] serde_json::error::Error),

    /// Errors that can occur parsing HTTP streams.
    #[cfg(feature = "hyper")]
    #[error("hyper: {0}")]
    Hyper(#[from] hyper::Error),

    /// A tempfile persist error occurred.
    #[error("tempfile: {0}")]
    TempfilePersist(#[from] tempfile::PersistError),

    /// A tempfile path persist error occurred.
    #[error("tempfile: {0}")]
    TempfilePathPersist(#[from] tempfile::PathPersistError),

    /// A derp error occurred.
    #[error("derp: {0}")]
    Derp(#[from] derp::Error),

    /// A data encoding error occurred.
    #[error("data encoding: {0}")]
    DataEncoding(#[from] DecodeError),

    /// The metadata was missing, so an operation could not be completed.
    #[error("missing {0} metadata")]
    MissingMetadata(MetadataPath),

    /// There were no available hash algorithms.
    #[error("no supported hash algorithm")]
    NoSupportedHashAlgorithm,

    /// The metadata was not found.
    #[error("metadata {path} at version {version} not found")]
    MetadataNotFound {
        /// The metadata path.
        path: MetadataPath,

        /// The metadata version.
        version: MetadataVersion,
    },

    /// The target was not found.
    #[error("target {0} not found")]
    TargetNotFound(TargetPath),

    /// Opaque error type, to be interpreted similar to HTTP 500. Something went wrong, and you may
    /// or may not be able to do anything about it.
    #[error("opaque: {0}")]
    Opaque(String),

    /// There is no known or available key type.
    #[error("unknown key type: {0}")]
    UnknownKeyType(String),

    /// The metadata threshold cannot equal 0.
    #[error("metadata {0} threshold must be greater than zero")]
    MetadataThresholdMustBeGreaterThanZero(MetadataPath),

    /// The metadata's version must be less than `u32::MAX`.
    #[error("metadata {0} version should be less than max u32")]
    MetadataVersionMustBeSmallerThanMaxU32(MetadataPath),

    /// The metadata was not signed with enough valid signatures.
    #[error("metadata {0} signature threshold not met: {number_of_valid_signatures}/{threshold}")]
    MetadataMissingSignatures {
        /// The signed metadata.
        role: MetadataPath,
        /// The number of signatures which are valid.
        number_of_valid_signatures: u32,
        /// The minimum number of valid signatures.
        threshold: u32,
    },

    /// Attempted to update metadata with an older version.
    #[error("attempted to roll back metadata {0} from version {trusted_version} to {new_version}")]
    MetadataAttemptedRollBack {
        /// The metadata.
        role: MetadataPath,
        /// The trusted metadata's version.
        trusted_version: u32,
        /// The new metadata's version.
        new_version: u32,
    },

    /// The parent metadata expected the child metadata to be at one version, but was found to be at
    /// another version.
    #[error("metadata {parent_role} expected metadata {child_role} version {expected_version}, but found {new_version}")]
    MetadataUnexpectedVersion {
        /// The parent metadata that contains the child metadata's version.
        parent_role: MetadataPath,
        /// The child metadata that has an unexpected version.
        child_role: MetadataPath,
        /// The expected version of the child metadata.
        expected_version: u32,
        /// The actual version of the child metadata.
        new_version: u32,
    },

    /// The parent metadata does not contain a description of the child metadata.
    #[error("metadata {parent_role} missing description of {child_role}")]
    MissingMetadataDescription {
        /// The parent metadata that contains the child metadata's description.
        parent_role: MetadataPath,
        /// The child metadata that should have been contained in the parent.
        child_role: MetadataPath,
    },

    /// The parent metadata did not delegate to the child role.
    #[error("{parent_role} delegation to {child_role} is not authorized")]
    UnauthorizedDelegation {
        /// The parent metadata that did not delegate to the child.
        parent_role: MetadataPath,
        /// That child metadata that was not delegated to by the parent.
        child_role: MetadataPath,
    },
}
