use chrono::{DateTime, UTC};
use json;
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use error::TufError;

pub enum Role {
    Root,
    Targets,
    Timestamp,
    Snapshot,
}

impl FromStr for Role {
    type Err = TufError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Root" => Ok(Role::Root),
            "Snapshot" => Ok(Role::Snapshot),
            "Targets" => Ok(Role::Targets),
            "Timestamp" => Ok(Role::Timestamp),
            role => Err(TufError::UnknownRole(String::from(role))),
        }
    }   
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Role::Root      => write!(f, "{}", "root"),
            Role::Targets   => write!(f, "{}", "targets"),
            Role::Snapshot  => write!(f, "{}", "snapshot"),
            Role::Timestamp => write!(f, "{}", "timestamp"),
        }
    }   
}

pub trait RoleType {
    fn role() -> Role;
}

pub struct Root {}
impl RoleType for Root {
    fn role() -> Role {
        Role::Root
    }
}

pub struct Targets {}
impl RoleType for Targets {
    fn role() -> Role {
        Role::Targets
    }
}

pub struct Timestamp {}
impl RoleType for Timestamp {
    fn role() -> Role {
        Role::Timestamp
    }
}

pub struct Snapshot {}
impl RoleType for Snapshot {
    fn role() -> Role {
        Role::Snapshot
    }
}

pub trait SignedMetadata<R: RoleType, M: Metadata<R>>: Deserialize {
    fn signatures(&self) -> Vec<Signature>;
    fn signed(&self) -> json::Value;
}

pub trait Metadata<R: RoleType>: Deserialize {}

pub struct RootMetadata {
    // TODO
}

impl Metadata<Root> for RootMetadata {}

impl Deserialize for RootMetadata {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(ref object) = Deserialize::deserialize(de)? {
            unimplemented!() // TODO
        } else {
            unimplemented!() // TODO
        }
    }   
}

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
        if self.typ.supports(scheme) {
            unimplemented!() // TODO
        } else {
            Err(TufError::SignatureSchemeMismatch)
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum KeyType {
    Ed25519,
    Rsa,
    Unsupported(String),
}

impl KeyType {
    fn supports(&self, scheme: &SignatureScheme) -> bool {
        false // TODO
    }
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
// TODO this is a dumb name
pub struct TargetInfo {
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
