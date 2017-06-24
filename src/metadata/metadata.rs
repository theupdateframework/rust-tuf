use chrono::DateTime;
use chrono::offset::Utc;
use data_encoding::HEXLOWER;
use ring;
use ring::digest::{self, SHA256};
use ring::signature::{ED25519, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA512};
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, SerializeTupleStruct, Error as SerializeError};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug};
use std::marker::PhantomData;
use std::str::FromStr;
use untrusted::Input;

use Result;
use error::Error;
use metadata::interchange::{RawData, DataInterchange};
use metadata::shims;

pub fn calculate_key_id(public_key: &PublicKeyValue) -> KeyId {
    let mut context = digest::Context::new(&SHA256);
    context.update(&public_key.0);
    KeyId(context.finish().as_ref().to_vec())
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    #[serde(rename = "root")]
    Root,
    #[serde(rename = "snapshot")]
    Snapshot,
    #[serde(rename = "targets")]
    Targets,
    #[serde(rename = "timestamp")]
    Timestamp,
}


#[derive(Debug)]
pub enum MetadataVersion {
    None,
    Number(u32),
    Hash(String),
}

impl MetadataVersion {
    pub fn prefix(&self) -> String {
        match self {
            &MetadataVersion::None => String::new(),
            &MetadataVersion::Number(ref x) => format!("{}.", x),
            &MetadataVersion::Hash(ref s) => format!("{}.", s),
        }
    }
}

pub trait Metadata: Debug + PartialEq + Serialize + DeserializeOwned {}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMetadata<D, R, M>
where
    D: DataInterchange,
    R: RawData<D>,
    M: Metadata,
{
    signatures: Vec<Signature>,
    signed: R,
    _interchage: PhantomData<D>,
    _metadata: PhantomData<M>,
}

impl<D, R, M> SignedMetadata<D, R, M>
where
    D: DataInterchange,
    R: RawData<D>,
    M: Metadata,
{
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    pub fn signatures_mut(&mut self) -> &mut Vec<Signature> {
        &mut self.signatures
    }

    pub fn signed(&self) -> &R {
        &self.signed
    }
}

#[derive(Debug, PartialEq)]
pub struct RootMetadata {
    version: u32,
    expires: DateTime<Utc>,
    consistent_snapshot: bool,
    keys: HashMap<KeyId, PublicKey>,
    root: RoleDefinition,
    snapshot: RoleDefinition,
    targets: RoleDefinition,
    timestamp: RoleDefinition,
}

impl RootMetadata {
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        consistent_snapshot: bool,
        keys: HashMap<KeyId, PublicKey>,
        root: RoleDefinition,
        snapshot: RoleDefinition,
        targets: RoleDefinition,
        timestamp: RoleDefinition,
    ) -> Self {
        RootMetadata {
            version: version,
            expires: expires,
            consistent_snapshot: consistent_snapshot,
            keys: keys,
            root: root,
            snapshot: snapshot,
            targets: targets,
            timestamp: timestamp,
        }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }

    pub fn consistent_snapshot(&self) -> bool {
        self.consistent_snapshot
    }

    pub fn keys(&self) -> &HashMap<KeyId, PublicKey> {
        &self.keys
    }

    pub fn root(&self) -> &RoleDefinition {
        &self.root
    }

    pub fn snapshot(&self) -> &RoleDefinition {
        &self.snapshot
    }

    pub fn targets(&self) -> &RoleDefinition {
        &self.targets
    }

    pub fn timestamp(&self) -> &RoleDefinition {
        &self.timestamp
    }
}

impl Metadata for RootMetadata {}

impl Serialize for RootMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::RootMetadata::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for RootMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::RootMetadata = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    key_id: KeyId,
    scheme: SignatureScheme,
    signature: SignatureValue,
}

impl Signature {
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn scheme(&self) -> &SignatureScheme {
         &self.scheme    
    }

    pub fn signature(&self) -> &SignatureValue {
        &self.signature
    }
}

/// A `KeyId` is calculated as `sha256(public_key_bytes)`. The TUF spec says that it should be
/// `sha256(cjson(encoded(public_key_bytes)))`, but this is meaningless once the spec moves away
/// from using only JSON as the data interchange format.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    pub fn new(bytes: Vec<u8>) -> Self {
        KeyId(bytes)
    }

    pub fn from_string(string: &str) -> Result<Self> {
        Ok(KeyId(HEXLOWER.decode(string.as_bytes())?))
    }
}

impl Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        write!(f, "KeyId {{ \"{}\" }}", HEXLOWER.encode(&self.0))
    }
}

impl Serialize for KeyId {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = ser.serialize_tuple_struct("KeyId", 1)?;
        s.serialize_field(&HEXLOWER.encode(&self.0))?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let mut string: String = Deserialize::deserialize(de)?;
        KeyId::from_string(&string).map_err(|e| DeserializeError::custom("shit!".to_string()))
    }
}

#[derive(Debug, PartialEq)]
pub enum SignatureScheme {
    Ed25519,
    RsaSsaPssSha256,
    RsaSsaPssSha512,
}

impl SignatureScheme {}

impl ToString for SignatureScheme {
    fn to_string(&self) -> String {
        match self {
            &SignatureScheme::Ed25519 => "ed25519",
            &SignatureScheme::RsaSsaPssSha256 => "rsassa-pss-sha256",
            &SignatureScheme::RsaSsaPssSha512 => "rsassa-pss-sha512",
        }.to_string()
    }
}

impl FromStr for SignatureScheme {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(SignatureScheme::Ed25519),
            "rsassa-pss-sha256" => Ok(SignatureScheme::RsaSsaPssSha256),
            "rsassa-pss-sha512" => Ok(SignatureScheme::RsaSsaPssSha512),
            typ => Err(Error::UnsupportedSignatureScheme(typ.into())),
        }
    }
}

impl Serialize for SignatureScheme {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SignatureScheme {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let mut string: String = Deserialize::deserialize(de)?;
        Ok(string.parse().unwrap())
    }
}

#[derive(PartialEq)]
pub struct SignatureValue(Vec<u8>);

impl SignatureValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        SignatureValue(bytes)
    }

    pub fn from_string(string: &str) -> Result<Self> {
        Ok(SignatureValue(HEXLOWER.decode(string.as_bytes())?))
    }
}

impl Debug for SignatureValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        write!(f, "SignatureValue {{ \"{}\" }}", HEXLOWER.encode(&self.0))
    }
}

impl Serialize for SignatureValue {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = ser.serialize_tuple_struct("SignatureValue", 1)?;
        s.serialize_field(&HEXLOWER.encode(&self.0))?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for SignatureValue {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let mut string: String = Deserialize::deserialize(de)?;
        SignatureValue::from_string(&string).map_err(|e| {
            DeserializeError::custom("Signature value was not valid hex lower".to_string())
        })
    }
}

/// Types of public keys.
#[derive(Clone, PartialEq, Debug)]
pub enum KeyType {
    /// [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519)
    Ed25519,
    /// [RSA](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29)
    Rsa,
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(KeyType::Ed25519),
            "rsa" => Ok(KeyType::Rsa),
            typ => Err(Error::UnsupportedKeyType(typ.into())),
        }
    }
}

impl ToString for KeyType {
    fn to_string(&self) -> String {
        match self {
            &KeyType::Ed25519 => "ed25519",
            &KeyType::Rsa => "rsa",
        }.to_string()
    }
}

impl Serialize for KeyType {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let mut string: String = Deserialize::deserialize(de)?;
        Ok(string.parse().unwrap())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    typ: KeyType,
    format: KeyFormat,
    key_id: KeyId,
    value: PublicKeyValue,
}

impl PublicKey {
    pub fn new(typ: KeyType, format: KeyFormat, value: PublicKeyValue) -> Self {
        PublicKey {
            typ: typ,
            format: format,
            key_id: calculate_key_id(&value),
            value: value,
        }
    }

    pub fn typ(&self) -> &KeyType {
        &self.typ
    }

    pub fn format(&self) -> &KeyFormat {
        &self.format
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn value(&self) -> &PublicKeyValue {
        &self.value
    }

    pub fn verify(&self, scheme: &SignatureScheme, msg: &[u8], sig: &SignatureValue) -> Result<()> {
        let alg: &ring::signature::VerificationAlgorithm = match scheme {
            &SignatureScheme::Ed25519 => &ED25519,
            &SignatureScheme::RsaSsaPssSha256 => &RSA_PSS_2048_8192_SHA256,
            &SignatureScheme::RsaSsaPssSha512 => &RSA_PSS_2048_8192_SHA512,
        };

        ring::signature::verify(
            alg,
            Input::from(&self.value.0),
            Input::from(msg),
            Input::from(&sig.0),
        ).map_err(|_: ring::error::Unspecified| Error::BadSignature)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::PublicKey::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::PublicKey = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKeyValue(Vec<u8>);

impl PublicKeyValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        PublicKeyValue(bytes)
    }

    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyFormat {
    HexLower,
    Pkcs1,
    Spki,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RoleDefinition {
    threshold: u32,
    key_ids: HashSet<KeyId>,
}

impl RoleDefinition {
    pub fn new(threshold: u32, key_ids: HashSet<KeyId>) -> Result<Self> {
        if threshold < 1 {
            return Err(Error::Encode(format!("Illegal threshold: {}", threshold)));
        }

        Ok(RoleDefinition {
            threshold: threshold,
            key_ids: key_ids,
        })
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn key_ids(&self) -> &HashSet<KeyId> {
        &self.key_ids
    }
}

impl Serialize for RoleDefinition {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::RoleDefinition::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for RoleDefinition {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::RoleDefinition = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use json;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn parse_spki_json() {
        let mut jsn = json!({"type": "rsa", "value": {}});

        let mut file = File::open(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("rsa")
                .join("spki-1.pub"),
        ).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();

        let _ = jsn.as_object_mut()
            .unwrap()
            .get_mut("value")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("public".into(), json::Value::String(buf.trim().into()));

        let key: PublicKey = json::from_value(jsn.clone()).unwrap();
        assert_eq!(key.typ(), &KeyType::Rsa);
        assert_eq!(key.format(), &KeyFormat::Spki);

        let deserialized: json::Value = json::to_value(key).unwrap();
        assert_eq!(deserialized, jsn);
    }

    #[test]
    fn parse_pkcs1_json() {
        let mut jsn = json!({"type": "rsa", "value": {}});

        let mut file = File::open(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("rsa")
                .join("pkcs1-1.pub"),
        ).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();

        let _ = jsn.as_object_mut()
            .unwrap()
            .get_mut("value")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("public".into(), json::Value::String(buf.trim().into()));

        let key: PublicKey = json::from_value(jsn.clone()).unwrap();
        assert_eq!(key.typ(), &KeyType::Rsa);
        assert_eq!(key.format(), &KeyFormat::Pkcs1);

        let deserialized: json::Value = json::to_value(key).unwrap();
        assert_eq!(deserialized, jsn);
    }

    #[test]
    fn parse_hex_json() {
        let mut jsn = json!({"type": "ed25519", "value": {}});
        let buf = "2bedead4feed".to_string();

        let _ = jsn.as_object_mut()
            .unwrap()
            .get_mut("value")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("public".into(), json::Value::String(buf.clone()));

        let key: PublicKey = json::from_value(jsn.clone()).unwrap();
        assert_eq!(key.typ(), &KeyType::Ed25519);
        assert_eq!(key.format(), &KeyFormat::HexLower);

        let deserialized: json::Value = json::to_value(key).unwrap();
        assert_eq!(deserialized, jsn);
    }
}
