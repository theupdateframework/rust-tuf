use chrono::{DateTime, UTC};
use crypto::ed25519;
use json;
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::ops::Deref;
use std::str::FromStr;

use error::Error;

#[derive(Deserialize)]
pub enum Role {
    Root,
    Targets,
    Timestamp,
    Snapshot,
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Root" => Ok(Role::Root),
            "Snapshot" => Ok(Role::Snapshot),
            "Targets" => Ok(Role::Targets),
            "Timestamp" => Ok(Role::Timestamp),
            role => Err(Error::UnknownRole(String::from(role))),
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

pub struct SignedMetadata<R: RoleType> {
    pub signatures: Vec<Signature>,
    pub signed: json::Value,
    _role: PhantomData<R>,
}

impl<R: RoleType> Deserialize for SignedMetadata<R> {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(ref object) = Deserialize::deserialize(de)? {
            match (object.get("signatures"), object.get("signed")) {
                (Some(&json::Value::Array(ref arr)), Some(v @ &json::Value::Object(_))) => {
                    Ok(SignedMetadata::<R> {
                        signatures: Vec::new(), // TODO
                        signed: v.clone(),
                        _role: PhantomData,
                    })
                },
                _ => unimplemented!(), // TODO
            }
        } else {
            unimplemented!() // TODO
        }
    }
}

pub trait Metadata<R: RoleType>: Deserialize {}

pub struct RootMetadata {
    typ: Role,
    //consistent_snapshot: bool,
    //expires: DateTime<UTC>,
    //version: i32,
    pub keys: HashMap<KeyId, Key>,
    root: RoleDefinition,
    // TODO targets: RoleDefinition,
    // TODO timestamp: RoleDefinition,
    // TODO snapshot: RoleDefinition,
}

impl RootMetadata {
    pub fn role_definition<R: RoleType>(&self) -> &RoleDefinition {
        match R::role() {
            Role::Root => &self.root,
            _ => unimplemented!() // TODO
        }
    }
}

impl Metadata<Root> for RootMetadata {}

impl Deserialize for RootMetadata {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(object) = Deserialize::deserialize(de)? {
            unimplemented!() // TODO
        } else {
            Err(DeserializeError::custom(format!("Role was not an object")))
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
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
    pub fn verify(&self, scheme: &SignatureScheme, msg: &[u8], sig: &SignatureValue) -> Result<(), Error> {
        if self.typ.supports(scheme) {
            match self.typ {
                KeyType::Unsupported(ref s) => Err(Error::UnsupportedKeyType(s.clone())),
                _ => scheme.verify(&self.value, msg, sig),
            }
        } else {
            Err(Error::SignatureSchemeMismatch)
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum KeyType {
    Ed25519,
    Unsupported(String),
}

impl KeyType {
    fn supports(&self, scheme: &SignatureScheme) -> bool {
        match (self, scheme) {
            (&KeyType::Ed25519, &SignatureScheme::Ed25519) => true,
            _ => false
        }
    }
}


#[derive(Clone, PartialEq, Debug)]
pub struct KeyValue(Vec<u8>);


#[derive(Clone, Hash, Eq, PartialEq, Debug, Deserialize)]
pub struct KeyId(String);


#[derive(Clone, PartialEq, Debug)]
pub struct SignatureValue(Vec<u8>);


#[derive(Clone, PartialEq, Debug)]
pub enum SignatureScheme {
    Ed25519,
    Unsupported(String),
}

impl SignatureScheme {
    fn verify(&self, pub_key: &KeyValue, msg: &[u8], sig: &SignatureValue) -> Result<(), Error> {
        match self {
            &SignatureScheme::Ed25519 => {
                if ed25519::verify(msg, &pub_key.0, &sig.0) {
                    Ok(())
                } else {
                    // TODO better error
                    Err(Error::VerificationFailure)
                }
            },
            &SignatureScheme::Unsupported(ref s) => Err(Error::UnsupportedSignatureScheme(s.clone())),
        }
    }
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
