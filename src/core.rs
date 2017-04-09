use chrono::{DateTime, UTC};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use error::TufError;

/// A TUF role.
#[derive(Clone, Eq, PartialEq, Debug, Hash)]
// TODO this might make more sense to turn into a trait so we can type check it elsewhere
pub enum Role {
    Root,
    Snapshot,
    Targets,
    Timestamp,
}


impl FromStr for Role {
    type Err = TufError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root" | "Root" => Ok(Role::Root),
            "snapshot" | "Snapshot" => Ok(Role::Snapshot),
            "targets" | "Targets" => Ok(Role::Targets),
            "timestamp" | "Timestamp" => Ok(Role::Timestamp),
            r => Err(TufError::InvalidRole(r.to_string()))
        }
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Role::Root => write!(f, "{}", "root"),
            Role::Targets => write!(f, "{}", "targets"),
            Role::Snapshot => write!(f, "{}", "snapshot"),
            Role::Timestamp => write!(f, "{}", "timestamp"),
        }
    }
}


pub trait SignedMetadata {
    fn signed(&self) -> Vec<u8>;
    fn signatures(&self) -> &[Signature];
}


/// Generic type for various types of role metadata
pub trait Metadata {
    /// Returns whether or not the metadata is expired.
    fn is_expired(&self) -> bool;
}

/// Metadata for the `root` role.
#[derive(Clone, Debug)]
pub struct RootMetadata {
    typ: Role,
    consistent_snapshot: Option<bool>,
    expires: DateTime<UTC>,
    pub keys: HashMap<KeyId, Key>,
    version: i32,
    pub roles: HashMap<Role, RoleDefinition>, // TODO ensure all are present
}

impl Metadata for RootMetadata {
    fn is_expired(&self) -> bool {
        UTC::now() > self.expires
    }
}

// TODO this doesn't check the _type = root
#[derive(Clone, Debug)]
pub struct SignedRootMetadata {
    pub signed: RootMetadata,
    signatures: Vec<Signature>,
}

impl SignedMetadata for SignedRootMetadata {
    fn signed(&self) -> Vec<u8> {
        unimplemented!() // TODO
    }

    fn signatures(&self) -> &[Signature] {
        self.signatures.as_ref()
    }
}

/// Metadata for the `snapshot` role.
#[derive(Clone, Debug)]
pub struct SnapshotMetadata {
    expires: DateTime<UTC>,
    version: i32,
    meta: HashMap<String, MetadataMetadata>,
}

// TODO this doesn't check the _type = root
#[derive(Clone, Debug)]
pub struct SignedSnapshotMetadata {
    signed: SnapshotMetadata,
    signatures: Vec<Signature>,
}

impl SignedMetadata for SignedSnapshotMetadata {
    fn signed(&self) -> Vec<u8> {
        unimplemented!() // TODO
    }

    fn signatures(&self) -> &[Signature] {
        self.signatures.as_ref()
    }
}


/// Metadata for the `targets` role.
#[derive(Clone, Debug)]
pub struct TargetsMetadata {
    expires: DateTime<UTC>,
    version: i32,
    targets: HashMap<String, Target>,
    delegations: Delegations,
}

// TODO this doesn't check the _type = root
#[derive(Clone, Debug)]
pub struct SignedTargetsMetadata {
    signed: TargetsMetadata,
    signatures: Vec<Signature>,
}

impl SignedMetadata for SignedTargetsMetadata {
    fn signed(&self) -> Vec<u8> {
        unimplemented!() // TODO
    }

    fn signatures(&self) -> &[Signature] {
        self.signatures.as_ref()
    }
}


/// Metadata for the `timestamp` role.
#[derive(Clone, Debug)]
pub struct TimestampMetadata {
    expires: DateTime<UTC>,
    version: i32,
    meta: HashMap<String, MetadataMetadata>,
}

// TODO this doesn't check the _type = root
#[derive(Clone, Debug)]
pub struct SignedTimestampMetadata {
    signed: TimestampMetadata,
    signatures: Vec<Signature>,
}

impl SignedMetadata for SignedTimestampMetadata {
    fn signed(&self) -> Vec<u8> {
        unimplemented!() // TODO
    }

    fn signatures(&self) -> &[Signature] {
        self.signatures.as_ref()
    }
}

// TODO mirror metadata


#[derive(Clone, PartialEq, Debug)]
pub struct RoleDefinition {
    pub key_ids: Vec<KeyId>,
    pub threshold: i32,
}

/// A cryptographic signature.
#[derive(Clone, PartialEq, Debug)]
pub struct Signature {
    pub key_id: KeyId,
    pub method: SignatureScheme,
    pub sig: SignatureValue,
}


#[derive(Clone, PartialEq, Debug)]
pub struct Key {
    typ: KeyType,
    value: KeyValue,
}

impl Key {
    pub fn verify(&self, signed: &[u8], scheme: &SignatureScheme) -> Result<(), TufError> {
        unimplemented!() // TODO
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum KeyType {
    Ed25519,
    Rsa,
    Unsupported(String),
}


#[derive(Clone, PartialEq, Debug)]
pub struct KeyValue {
    public: Vec<u8>,
}


#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct KeyId(String);


#[derive(Clone, PartialEq, Debug)]
pub struct SignatureValue(Vec<u8>);


#[derive(Clone, PartialEq, Debug)]
pub enum SignatureScheme {
    Ed25519,
    RsaSsaPss,
    Unsupported(String),
}



#[derive(Clone, PartialEq, Debug)]
pub struct MetadataMetadata {
    length: i64,
    hashes: HashMap<HashType, HashValue>,
    version: i32,
}


#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub enum HashType {
    Sha512,
    Sha256,
    Unsupported(String),
}


#[derive(Clone, PartialEq, Debug)]
pub struct HashValue(Vec<u8>);


#[derive(Clone, Debug)]
pub struct Target {
    length: i64,
    hashes: HashMap<HashType, HashValue>,
    custom: Option<HashMap<String, String>>, // TODO json value
}


#[derive(Clone, PartialEq, Debug)]
pub struct Delegations {
    keys: Vec<KeyId>,
    roles: Vec<DelegatedRole>,
}


#[derive(Clone, PartialEq, Debug)]
pub struct DelegatedRole {
    name: String,
    key_ids: Vec<KeyId>,
    threshold: i32,
    // TODO path_hash_prefixes
    paths: Vec<String>,
}
