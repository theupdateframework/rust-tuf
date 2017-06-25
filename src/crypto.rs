use data_encoding::HEXLOWER;
use ring;
use ring::digest::{self, SHA256};
use ring::signature::{ED25519, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA512};
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, SerializeTupleStruct, Error as SerializeError};
use std::fmt::{self, Debug};
use std::str::FromStr;
use untrusted::Input;

use Result;
use error::Error;
use rsa;
use shims;

pub fn calculate_key_id(public_key: &PublicKeyValue) -> KeyId {
    let mut context = digest::Context::new(&SHA256);
    context.update(&public_key.0);
    KeyId(context.finish().as_ref().to_vec())
}

/// A `KeyId` is calculated as `sha256(public_key_bytes)`. The TUF spec says that it should be
/// `sha256(cjson(encoded(public_key_bytes)))`, but this is meaningless once the spec moves away
/// from using only JSON as the data interchange format.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    fn from_string(string: &str) -> Result<Self> {
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
        let string: String = Deserialize::deserialize(de)?;
        KeyId::from_string(&string).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
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
        let string: String = Deserialize::deserialize(de)?;
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
        let string: String = Deserialize::deserialize(de)?;
        SignatureValue::from_string(&string).map_err(|e| {
            DeserializeError::custom(format!("Signature value was not valid hex lower: {:?}", e))
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
        let string: String = Deserialize::deserialize(de)?;
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
    pub fn from_ed25519(value: PublicKeyValue) -> Result<Self> {
        if value.value().len() != 32 {
            return Err(Error::Decode(
                "Ed25519 public key was not 32 bytes long".into(),
            ));
        }

        Ok(PublicKey {
            typ: KeyType::Ed25519,
            format: KeyFormat::HexLower,
            key_id: calculate_key_id(&value),
            value: value,
        })
    }

    pub fn from_rsa(value: PublicKeyValue, format: KeyFormat) -> Result<Self> {
        // TODO check n > 2048 bits

        let key_id = calculate_key_id(&value);

        let pkcs1_value = match format {
            KeyFormat::Pkcs1 => {
                let bytes = rsa::from_pkcs1(value.value()).ok_or(
                    Error::IllegalArgument(
                        "Key claimed to be PKCS1 but could not be parsed."
                            .into(),
                    ),
                )?;
                PublicKeyValue(bytes)
            }
            KeyFormat::Spki => {
                let bytes = rsa::from_spki(value.value()).ok_or(Error::IllegalArgument(
                    "Key claimed to be SPKI but could not be parsed."
                        .into(),
                ))?;
                PublicKeyValue(bytes)
            }
            x => {
                return Err(Error::IllegalArgument(
                    format!("RSA keys in format {:?} not supported.", x),
                ))
            }
        };

        Ok(PublicKey {
            typ: KeyType::Rsa,
            format: format,
            key_id: key_id,
            value: pkcs1_value,
        })
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
