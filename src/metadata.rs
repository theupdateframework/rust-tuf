use chrono::{DateTime, UTC};
use json;
use ring;
use ring::digest::{digest, SHA256};
use ring::signature::{verify, ED25519};
use rustc_serialize::hex::{FromHex, ToHex};
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter, Debug};
use std::marker::PhantomData;
use std::str::FromStr;
use untrusted::Input;

use error::Error;

#[derive(Eq, PartialEq, Deserialize, Debug)]
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
            Role::Root => write!(f, "{}", "root"),
            Role::Targets => write!(f, "{}", "targets"),
            Role::Snapshot => write!(f, "{}", "snapshot"),
            Role::Timestamp => write!(f, "{}", "timestamp"),
        }
    }
}

pub trait RoleType: Debug {
    fn role() -> Role;
}

#[derive(Debug)]
pub struct Root {}
impl RoleType for Root {
    fn role() -> Role {
        Role::Root
    }
}

#[derive(Debug)]
pub struct Targets {}
impl RoleType for Targets {
    fn role() -> Role {
        Role::Targets
    }
}

#[derive(Debug)]
pub struct Timestamp {}
impl RoleType for Timestamp {
    fn role() -> Role {
        Role::Timestamp
    }
}

#[derive(Debug)]
pub struct Snapshot {}
impl RoleType for Snapshot {
    fn role() -> Role {
        Role::Snapshot
    }
}

#[derive(Debug)]
pub struct SignedMetadata<R: RoleType> {
    pub signatures: Vec<Signature>,
    pub signed: json::Value,
    _role: PhantomData<R>,
}

impl<R: RoleType> Deserialize for SignedMetadata<R> {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {
            match (object.remove("signatures"), object.remove("signed")) {
                (Some(a @ json::Value::Array(_)), Some(v @ json::Value::Object(_))) => {
                    Ok(SignedMetadata::<R> {
                        signatures: json::from_value(a).map_err(|e| {
                                DeserializeError::custom(format!("Bad signature data: {}", e))
                            })?,
                        signed: v.clone(),
                        _role: PhantomData,
                    })
                }
                _ => unimplemented!(), // TODO
            }
        } else {
            unimplemented!() // TODO
        }
    }
}

pub trait Metadata<R: RoleType>: Deserialize {
    fn expires(&self) -> &DateTime<UTC>;
}

pub struct RootMetadata {
    // TODO consistent_snapshot: bool,
    expires: DateTime<UTC>,
    pub version: i32,
    pub keys: HashMap<KeyId, Key>,
    root: RoleDefinition,
    targets: RoleDefinition,
    timestamp: RoleDefinition,
    snapshot: RoleDefinition,
}

impl RootMetadata {
    pub fn role_definition<R: RoleType>(&self) -> &RoleDefinition {
        match R::role() {
            Role::Root => &self.root,
            Role::Targets => &self.targets,
            Role::Timestamp => &self.timestamp,
            Role::Snapshot => &self.snapshot,
        }
    }
}

impl Metadata<Root> for RootMetadata {
    fn expires(&self) -> &DateTime<UTC> {
        &self.expires
    }
}

impl Deserialize for RootMetadata {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {
            let typ = json::from_value::<Role>(object.remove("_type")
                    .ok_or_else(|| DeserializeError::custom("Field '_type' missing"))?)
                .map_err(|e| {
                    DeserializeError::custom(format!("Field '_type' not a valid role: {}", e))
                })?;

            if typ != Role::Root {
                return Err(DeserializeError::custom("Field '_type' was not 'Root'"));
            }

            let keys = json::from_value(object.remove("keys")
                    .ok_or_else(|| DeserializeError::custom("Field 'keys' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'keys' not a valid key map: {}", e))
                })?;

            let expires = json::from_value(object.remove("expires")
                    .ok_or_else(|| DeserializeError::custom("Field 'expires' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'expires' did not have a valid format: {}", e))
                })?;

            let version = json::from_value(object.remove("version")
                    .ok_or_else(|| DeserializeError::custom("Field 'version' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'version' did not have a valid format: {}", e))
                })?;

            let mut roles = object.remove("roles")
                .and_then(|v| match v {
                    json::Value::Object(o) => Some(o),
                    _ => None,
                })
                .ok_or_else(|| DeserializeError::custom("Field 'roles' missing"))?;

            let root = json::from_value(roles.remove("root")
                    .ok_or_else(|| DeserializeError::custom("Role 'root' missing"))?)
                .map_err(|e| {
                    DeserializeError::custom(format!("Root role definition error: {}", e))
                })?;

            let targets = json::from_value(roles.remove("targets")
                    .ok_or_else(|| DeserializeError::custom("Role 'targets' missing"))?)
                .map_err(|e| {
                    DeserializeError::custom(format!("Targets role definition error: {}", e))
                })?;

            let timestamp = json::from_value(roles.remove("timestamp")
                    .ok_or_else(|| DeserializeError::custom("Role 'timestamp' missing"))?)
                .map_err(|e| {
                    DeserializeError::custom(format!("Timetamp role definition error: {}", e))
                })?;

            let snapshot = json::from_value(roles.remove("snapshot")
                    .ok_or_else(|| DeserializeError::custom("Role 'shapshot' missing"))?)
                .map_err(|e| {
                    DeserializeError::custom(format!("Snapshot role definition error: {}", e))
                })?;

            Ok(RootMetadata {
                expires: expires,
                version: version,
                keys: keys,
                root: root,
                targets: targets,
                timestamp: timestamp,
                snapshot: snapshot,
            })
        } else {
            Err(DeserializeError::custom("Role was not an object"))
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct RoleDefinition {
    pub key_ids: Vec<KeyId>,
    pub threshold: i32,
}

impl Deserialize for RoleDefinition {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {
            let key_ids = json::from_value(object.remove("keyids")
                    .ok_or_else(|| DeserializeError::custom("Field 'keyids' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'keyids' not a valid array: {}", e))
                })?;

            let threshold = json::from_value(object.remove("threshold")
                    .ok_or_else(|| DeserializeError::custom("Field 'threshold' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'threshold' not a an int: {}", e))
                })?;

            if threshold <= 0 {
                return Err(DeserializeError::custom("'threshold' must be >= 1"));
            }


            Ok(RoleDefinition {
                key_ids: key_ids,
                threshold: threshold,
            })
        } else {
            Err(DeserializeError::custom("Role definition was not an object"))
        }
    }
}

#[derive(Debug)]
pub struct TargetsMetadata {
    expires: DateTime<UTC>,
    pub version: i32,
    pub delegations: Option<Delegations>,
    pub targets: HashMap<String, TargetInfo>,
}

impl Metadata<Targets> for TargetsMetadata {
    fn expires(&self) -> &DateTime<UTC> {
        &self.expires
    }
}

impl Deserialize for TargetsMetadata {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {
            let delegations = match object.remove("delegations") {
                // TODO this should accept null / empty object too
                // currently the options are "not present at all" or "completely correct"
                // and everything else errors out
                Some(value) => {
                    Some(json::from_value(value).map_err(|e| {
                            DeserializeError::custom(format!("Bad delegations format: {}", e))
                        })?)
                }
                None => None,
            };

            let expires = json::from_value(object.remove("expires")
                    .ok_or_else(|| DeserializeError::custom("Field 'expires' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'expires did not have a valid format: {}", e))
                })?;

            let version = json::from_value(object.remove("version")
                    .ok_or_else(|| DeserializeError::custom("Field 'version' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'version' did not have a valid format: {}", e))
                })?;

            match object.remove("targets") {
                Some(t) => {
                    let targets =
                        json::from_value(t).map_err(|e| {
                                DeserializeError::custom(format!("Bad targets format: {}", e))
                            })?;

                    Ok(TargetsMetadata {
                        version: version,
                        expires: expires,
                        delegations: delegations,
                        targets: targets,
                    })
                }
                _ => Err(DeserializeError::custom("Signature missing fields".to_string())),
            }
        } else {
            Err(DeserializeError::custom("Role was not an object"))
        }
    }
}

pub struct TimestampMetadata {
    expires: DateTime<UTC>,
    pub version: i32,
    pub meta: HashMap<String, MetadataMetadata>,
}

impl Metadata<Timestamp> for TimestampMetadata {
    fn expires(&self) -> &DateTime<UTC> {
        &self.expires
    }
}

impl Deserialize for TimestampMetadata {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {

            let expires = json::from_value(object.remove("expires")
                    .ok_or_else(|| DeserializeError::custom("Field 'expires' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'expires' did not have a valid format: {}", e))
                })?;

            let version = json::from_value(object.remove("version")
                    .ok_or_else(|| DeserializeError::custom("Field 'version' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'version' did not have a valid format: {}", e))
                })?;

            match object.remove("meta") {
                Some(m) => {
                    let meta = json::from_value(m).map_err(|e| {
                            DeserializeError::custom(format!("Bad meta-meta format: {}", e))
                        })?;

                    Ok(TimestampMetadata {
                        expires: expires,
                        version: version,
                        meta: meta,
                    })
                }
                _ => Err(DeserializeError::custom("Signature missing fields".to_string())),
            }
        } else {
            Err(DeserializeError::custom("Role was not an object"))
        }
    }
}

pub struct SnapshotMetadata {
    expires: DateTime<UTC>,
    pub version: i32,

    // TODO this needs to use something other than MetaMeta
    // because the spec says that hash/len are only mandatory for Root role
    // but I'm lazy for now just to get this up and running
    pub meta: HashMap<String, MetadataMetadata>,
}

impl Metadata<Snapshot> for SnapshotMetadata {
    fn expires(&self) -> &DateTime<UTC> {
        &self.expires
    }
}

impl Deserialize for SnapshotMetadata {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {
            let expires = json::from_value(object.remove("expires")
                    .ok_or_else(|| DeserializeError::custom("Field 'expires' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'expires' did not have a valid format: {}", e))
                })?;

            let version = json::from_value(object.remove("version")
                    .ok_or_else(|| DeserializeError::custom("Field 'version' missing"))?).map_err(|e| {
                    DeserializeError::custom(format!("Field 'version' did not have a valid format: {}", e))
                })?;

            match object.remove("meta") {
                Some(m) => {
                    let meta = json::from_value(m).map_err(|e| {
                            DeserializeError::custom(format!("Bad meta-meta format: {}", e))
                        })?;

                    Ok(SnapshotMetadata {
                        expires: expires,
                        version: version,
                        meta: meta,
                    })
                }
                _ => Err(DeserializeError::custom("Signature missing fields".to_string())),
            }
        } else {
            Err(DeserializeError::custom("Role was not an object"))
        }
    }
}

/// A cryptographic signature.
#[derive(Clone, PartialEq, Debug)]
pub struct Signature {
    pub key_id: KeyId,
    pub method: SignatureScheme,
    pub sig: SignatureValue,
}

impl Deserialize for Signature {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {
            match (object.remove("keyid"), object.remove("method"), object.remove("sig")) {
                (Some(k), Some(m), Some(s)) => {
                    let key_id =
                        json::from_value(k).map_err(|e| {
                                DeserializeError::custom(format!("Failed at keyid: {}", e))
                            })?;
                    let method =
                        json::from_value(m).map_err(|e| {
                                DeserializeError::custom(format!("Failed at method: {}", e))
                            })?;
                    let sig = json::from_value(s)
                        .map_err(|e| DeserializeError::custom(format!("Failed at sig: {}", e)))?;

                    Ok(Signature {
                        key_id: key_id,
                        method: method,
                        sig: sig,
                    })
                }
                _ => Err(DeserializeError::custom("Signature missing fields".to_string())),
            }
        } else {
            Err(DeserializeError::custom("Signature was not an object".to_string()))
        }
    }
}


/// A public key
#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct Key {
    #[serde(rename = "keytype")]
    pub typ: KeyType,
    #[serde(rename = "keyval")]
    pub value: KeyValue,
}

impl Key {
    pub fn verify(&self,
                  scheme: &SignatureScheme,
                  msg: &[u8],
                  sig: &SignatureValue)
                  -> Result<(), Error> {
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

/// Types of public keys.
#[derive(Clone, PartialEq, Debug)]
pub enum KeyType {
    Ed25519,
    Unsupported(String),
}

impl KeyType {
    fn supports(&self, scheme: &SignatureScheme) -> bool {
        match (self, scheme) {
            (&KeyType::Ed25519, &SignatureScheme::Ed25519) => true,
            _ => false,
        }
    }
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(KeyType::Ed25519),
            typ => Ok(KeyType::Unsupported(typ.into())),
        }
    }
}

impl Deserialize for KeyType {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|_| unreachable!())
        } else {
            Err(DeserializeError::custom("Key type was not a string"))
        }
    }
}


/// The raw bytes of a public key.
#[derive(Clone, PartialEq, Debug)]
pub struct KeyValue(pub Vec<u8>);

impl KeyValue {
    /// Calculates the `KeyId` of the public key.
    pub fn key_id(&self) -> KeyId {
        KeyId(digest(&SHA256, &self.0).as_ref().to_hex())
    }
}

impl Deserialize for KeyValue {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        match Deserialize::deserialize(de)? {
            json::Value::String(ref s) => {
                // TODO this is shit because we can't tell what type of key it is
                // e.g., ed25519 => hex, rsa => PEM
                // need to add this into the type/struct so it can be accessed here
                s.from_hex()
                    .map(KeyValue)
                    .map_err(|e| DeserializeError::custom(format!("Key value was not hex: {}", e)))
            }
            json::Value::Object(mut object) => {
                json::from_value::<KeyValue>(object.remove("public")
                        .ok_or_else(|| DeserializeError::custom("Field 'public' missing"))?)
                    .map_err(|e| {
                        DeserializeError::custom(format!("Field 'public' not encoded correctly: \
                                                          {}",
                                                         e))
                    })
            }
            _ => Err(DeserializeError::custom("Key value was not a string or object")),
        }
    }
}


/// The hex encoded ID of a public key.
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct KeyId(pub String);

impl Deserialize for KeyId {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        match Deserialize::deserialize(de)? {
            json::Value::String(s) => Ok(KeyId(s)),
            _ => Err(DeserializeError::custom("Key ID was not a string")),
        }
    }
}


#[derive(Clone, PartialEq, Debug)]
pub struct SignatureValue(Vec<u8>);

impl Deserialize for SignatureValue {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        match Deserialize::deserialize(de)? {
            json::Value::String(ref s) => {
                s.from_hex()
                    .map(SignatureValue)
                    .map_err(|e| {
                        DeserializeError::custom(format!("Signature value was not hex: {}", e))
                    })
            }
            _ => Err(DeserializeError::custom("Signature value was not a string")),
        }
    }
}


#[derive(Clone, PartialEq, Debug)]
pub enum SignatureScheme {
    Ed25519,
    Unsupported(String),
}

impl SignatureScheme {
    fn verify(&self, pub_key: &KeyValue, msg: &[u8], sig: &SignatureValue) -> Result<(), Error> {
        match self {
            &SignatureScheme::Ed25519 => {
                ring::signature::verify(
                    &ED25519,
                    Input::from(&pub_key.0), Input::from(msg), Input::from(&sig.0)
                ).map_err(|_| Error::VerificationFailure("Bad signature".into()))
            }
            &SignatureScheme::Unsupported(ref s) => {
                Err(Error::UnsupportedSignatureScheme(s.clone()))
            }
        }
    }
}

impl FromStr for SignatureScheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(SignatureScheme::Ed25519),
            typ => Ok(SignatureScheme::Unsupported(typ.into())),
        }
    }
}

impl Deserialize for SignatureScheme {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|_| unreachable!())
        } else {
            Err(DeserializeError::custom("Key type was not a string"))
        }
    }
}


#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct MetadataMetadata {
    pub length: i64,
    pub hashes: HashMap<HashType, HashValue>,
    pub version: i32,
}


#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub enum HashType {
    Sha256,
    Sha512,
    Unsupported(String),
}

impl HashType {
    pub fn preferences() -> Vec<HashType> {
        // TODO avoid heap
        vec![HashType::Sha512, HashType::Sha256]
    }
}

impl FromStr for HashType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha256" => Ok(HashType::Sha256),
            "sha512" => Ok(HashType::Sha512),
            typ => Ok(HashType::Unsupported(typ.into())),
        }
    }
}

impl Deserialize for HashType {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|_| unreachable!())
        } else {
            Err(DeserializeError::custom("Hash type was not a string"))
        }
    }
}


#[derive(Clone, PartialEq, Debug)]
pub struct HashValue(pub Vec<u8>);

impl Deserialize for HashValue {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        match Deserialize::deserialize(de)? {
            json::Value::String(ref s) => {
                s.from_hex()
                    .map(HashValue)
                    .map_err(|e| DeserializeError::custom(format!("Hash value was not hex: {}", e)))
            }
            _ => Err(DeserializeError::custom("Hash value was not a string")),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
// TODO this is a dumb name
pub struct TargetInfo {
    pub length: i64,
    pub hashes: HashMap<HashType, HashValue>,
    pub custom: Option<HashMap<String, String>>, // TODO json value
}


#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct Delegations {
    keys: Vec<KeyId>,
    roles: Vec<DelegatedRole>,
}


#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct DelegatedRole {
    name: String,
    key_ids: Vec<KeyId>,
    threshold: i32,
    // TODO path_hash_prefixes
    paths: Vec<String>,
}
