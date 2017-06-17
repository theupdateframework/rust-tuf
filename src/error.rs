//! Error types and converters.

use hyper;
use json;
use std::path::Path;
use std::io;

use metadata::Role;

/// Error type for all TUF related errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// ASN.1 parse errors.
    Asn1,
    /// Errors for converting JSON to canonical JSON.
    CanonicalJsonError(String),
    /// The metadata for the given role has expired.
    ExpiredMetadata(Role),
    /// Generic error type for more opaque error reporting.
    Generic(String),
    /// An HTTP or network error.
    Http(String),
    /// The TUF configuration was invalid.
    InvalidConfig(String),
    /// Wrapper for IO errors.
    Io(String),
    /// There was an error parsing JSON.
    Json(String),
    /// The calculated and provided hashes for the matadata did not match.
    MetadataHashMismatch(Role),
    /// A necessary piece of metadata was missing.
    MissingMetadata(Role),
    /// The signed metadata had duplicate signatures from a particular key.
    NonUniqueSignatures(Role),
    /// The metadata did not provide any hash algorithms that this library can calculate.
    NoSupportedHashAlgorithms,
    /// A piece of metadata exceeded the provided or maximum allowed size.
    OversizedMetadata(Role),
    /// The calculated and provided hashes for the target did not match.
    UnknownRole(String),
    /// The target does not exist in valid metadata or could not be verified.
    UnavailableTarget,
    /// The role did not have enough signatures to meet the required threshold.
    UnmetThreshold(Role),
    /// The key type was not supported by this library.
    UnsupportedKeyType(String),
    /// The signature scheme was not supported by this library.
    UnsupportedSignatureScheme(String),
    /// There was an error in the verification process.
    VerificationFailure(String),
    /// A piece of metadata decreased its version when not allowed.
    VersionDecrease(Role),
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
