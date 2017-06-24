use data_encoding::HEXLOWER;
use ring::digest::{self, SHA256};
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, SerializeTupleStruct, Error as SerializeError};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::marker::PhantomData;
use std::str::FromStr;

use Result;
use error::Error;
use metadata::interchange::{RawData, DataInterchange};
use metadata::shims;

pub fn calculate_key_id(public_key: &PublicKeyValue) -> KeyId {
    let mut context = digest::Context::new(&SHA256);
    context.update(&public_key.0);
    KeyId(context.finish().as_ref().to_vec())
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RootMetadata {
    keys: HashMap<KeyId, PublicKey>,
    roles: HashMap<String, RoleDefinition>,
}

impl Metadata for RootMetadata {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    key_id: KeyId,
    method: SignatureScheme,
    sig: SignatureValue,
}

impl Signature {
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

/// A `KeyId` is calculated as `sha256(public_key_bytes)`. The TUF spec says that it should be
/// `sha256(cjson(encoded(public_key_bytes)))`, but this is meaningless once the spec moves away
/// from using only JSON as the data interchange format.
#[derive(PartialEq, Eq, Hash)]
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

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub struct PublicKeyValue(Vec<u8>);

impl PublicKeyValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        PublicKeyValue(bytes)
    }

    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum KeyFormat {
    HexLower,
    Pkcs1,
    Spki,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RoleDefinition {}

#[cfg(test)]
mod test {
    use super::*;
    use json;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn parse_spki_json() {
        let mut jsn = json!({"keytype": "rsa", "keyval": {}});

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
            .get_mut("keyval")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("public".into(), json::Value::String(buf.clone()));

        let key: PublicKey = json::from_value(jsn.clone()).unwrap();
        assert_eq!(key.typ(), &KeyType::Rsa);
        assert_eq!(key.format(), &KeyFormat::Spki);

        let deserialized: json::Value = json::to_value(key).unwrap();
        assert_eq!(deserialized, jsn);
    }

    #[test]
    fn parse_pkcs1_json() {
        let mut jsn = json!({"keytype": "rsa", "keyval": {}});

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
            .get_mut("keyval")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("public".into(), json::Value::String(buf.clone()));

        let key: PublicKey = json::from_value(jsn.clone()).unwrap();
        assert_eq!(key.typ(), &KeyType::Rsa);
        assert_eq!(key.format(), &KeyFormat::Pkcs1);

        let deserialized: json::Value = json::to_value(key).unwrap();
        assert_eq!(deserialized, jsn);
    }

    #[test]
    fn parse_hex_json() {
        let mut jsn = json!({"keytype": "ed25519", "keyval": {}});
        let buf = "2bedead4feed".to_string();

        let _ = jsn.as_object_mut()
            .unwrap()
            .get_mut("keyval")
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
