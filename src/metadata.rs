use chrono::{DateTime, UTC};
use crypto::ed25519;
use json;
use rustc_serialize::hex::FromHex;
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter, Debug};
use std::marker::PhantomData;
use std::ops::Deref;
use std::str::FromStr;

use error::Error;

#[derive(Eq, PartialEq, Deserialize)]
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
                        signatures: json::from_value(a)
                            .map_err(|e| DeserializeError::custom(format!("Bad signature data: {}", e)))?,
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
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {
            // TODO unwrap
            let typ = json::from_value::<Role>(object.remove("_type")
                    .ok_or(DeserializeError::custom("Field '_type' missing"))?
                )
                .map_err(|e| DeserializeError::custom(format!("Field '_type' not a valid role: {}", e)))?;

            if typ != Role::Root {
                return Err(DeserializeError::custom("Field '_type' was not 'Root'"));
            }

            let keys = json::from_value(object.remove("keys")
                    .ok_or(DeserializeError::custom("Field 'keys' missing"))?
                )
                .map_err(|e| DeserializeError::custom(format!("Field 'keys' not a valid key map: {}", e)))?;

            let mut roles = object.remove("roles")
                .and_then(|v| {
                    match v {
                        json::Value::Object(o) => Some(o),
                        _ => None,
                    }
                })
                .ok_or(DeserializeError::custom("Field 'roles' missing"))?;

            let root = json::from_value(roles.remove("root")
                    .ok_or(DeserializeError::custom("Role 'root' missing"))?
                )
                .map_err(|e| DeserializeError::custom(format!("Root role definition error: {}", e)))?;

            Ok(RootMetadata {
                keys: keys,
                root: root,
            })
        } else {
            Err(DeserializeError::custom("Role was not an object"))
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct RoleDefinition {
    #[serde(rename = "keyids")]
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

impl Deserialize for Signature {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::Object(mut object) = Deserialize::deserialize(de)? {
            match (object.remove("keyid"), object.remove("method"), object.remove("sig")) {
                (Some(k), Some(m), Some(s)) => {
                    let key_id = json::from_value(k)
                        .map_err(|e| DeserializeError::custom(format!("Failed at keyid: {}", e)))?;
                    let method = json::from_value(m)
                        .map_err(|e| DeserializeError::custom(format!("Failed at method: {}", e)))?;
                    let sig = json::from_value(s)
                        .map_err(|e| DeserializeError::custom(format!("Failed at sig: {}", e)))?;

                    Ok(Signature {
                        key_id: key_id,
                        method: method,
                        sig: sig,
                    })
                },
                _ => Err(DeserializeError::custom("Signature missing fields".to_string())),
            }
        } else {
            Err(DeserializeError::custom("Signature was not an object".to_string()))
        }
    }
}


#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct Key {
    #[serde(rename = "keytype")]
    typ: KeyType,
    #[serde(rename = "keyval")]
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


#[derive(Clone, PartialEq, Debug)]
pub struct KeyValue(Vec<u8>);

impl Deserialize for KeyValue {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        match Deserialize::deserialize(de)? {
            json::Value::String(ref s) => {
                s.from_hex()
                    .map(KeyValue)
                    .map_err(|e| DeserializeError::custom(format!("Key value was not hex: {}", e)))
            },
            json::Value::Object(mut object) => {
                json::from_value::<KeyValue>(object.remove("public")
                        .ok_or(DeserializeError::custom("Field 'public' missing"))?
                    )
                    .map_err(|e| DeserializeError::custom(format!("Field 'public' not encoded correctly: {}", e)))
            },
            _ => Err(DeserializeError::custom("Key value was not a string or object"))
        }
    }
}


#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct KeyId(String);

impl Deserialize for KeyId {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        match Deserialize::deserialize(de)? {
            json::Value::String(s) => {
                Ok(KeyId(s))
            },
            _ => Err(DeserializeError::custom("Key ID was not a string"))
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
                    .map_err(|e| DeserializeError::custom(format!("Signature value was not hex: {}", e)))
            },
            _ => Err(DeserializeError::custom("Signature value was not a string"))
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
                if ed25519::verify(msg, &pub_key.0, &sig.0) {
                    Ok(())
                } else {
                    Err(Error::VerificationFailure("Bad signature".into()))
                }
            },
            &SignatureScheme::Unsupported(ref s) => Err(Error::UnsupportedSignatureScheme(s.clone())),
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
