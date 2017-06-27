//! Cryptographic structures and functions.

use data_encoding::HEXLOWER;
use ring;
use ring::digest::{self, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{RSAKeyPair, RSASigningState, Ed25519KeyPair, ED25519,
                      RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256,
                      RSA_PSS_SHA512};
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, SerializeTupleStruct, Error as SerializeError};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::str::FromStr;
use std::sync::Arc;
use untrusted::Input;

use Result;
use error::Error;
use rsa;
use shims;

static HASH_ALG_PREFS: &'static [HashAlgorithm] = &[HashAlgorithm::Sha512, HashAlgorithm::Sha256];

/// Given a map of hash algorithms and their values, get the prefered algorithm and the hash
/// calculated by it. Returns an `Err` if there is no match.
pub fn hash_preference<'a>(
    hashes: &'a HashMap<HashAlgorithm, HashValue>,
) -> Result<(&'static HashAlgorithm, &'a HashValue)> {
    for alg in HASH_ALG_PREFS {
        match hashes.get(alg) {
            Some(v) => return Ok((alg, v)),
            None => continue,
        }
    }
    Err(Error::NoSupportedHashAlgorithm)
}

/// Calculate the given key's ID.
///
/// A `KeyId` is calculated as `sha256(public_key_bytes)`. The TUF spec says that it should be
/// `sha256(cjson(encoded(public_key_bytes)))`, but this is meaningless once the spec moves away
/// from using only JSON as the data interchange format.
pub fn calculate_key_id(public_key: &PublicKeyValue) -> KeyId {
    let mut context = digest::Context::new(&SHA256);
    context.update(&public_key.0);
    KeyId(context.finish().as_ref().to_vec())
}

/// Wrapper type for public key's ID.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    fn from_string(string: &str) -> Result<Self> {
        Ok(KeyId(HEXLOWER.decode(string.as_bytes())?))
    }
}

impl Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

/// Cryptographic signature schemes.
#[derive(Debug, PartialEq)]
pub enum SignatureScheme {
    /// [Ed25519](https://ed25519.cr.yp.to/)
    Ed25519,
    /// [RSASSA-PSS](https://tools.ietf.org/html/rfc5756) calculated over SHA256
    RsaSsaPssSha256,
    /// [RSASSA-PSS](https://tools.ietf.org/html/rfc5756) calculated over SHA512
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
            typ => Err(Error::Encoding(typ.into())),
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

/// Wrapper type for the value of a cryptographic signature.
#[derive(PartialEq)]
pub struct SignatureValue(Vec<u8>);

impl SignatureValue {
    /// Create a new `SignatureValue` from the given bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        SignatureValue(bytes)
    }

    /// Create a new `SignatureValue` from the given hex-lower string.
    pub fn from_string(string: &str) -> Result<Self> {
        Ok(SignatureValue(HEXLOWER.decode(string.as_bytes())?))
    }
}

impl Debug for SignatureValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
    /// [Ed25519](https://ed25519.cr.yp.to/)
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
            typ => Err(Error::Encoding(typ.into())),
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

enum PrivateKeyType {
    Ed25519(Ed25519KeyPair),
    Rsa(Arc<RSAKeyPair>),
}

impl Debug for PrivateKeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            &PrivateKeyType::Ed25519(_) => "ed25519",
            &PrivateKeyType::Rsa(_) => "rsa",
        };
        write!(f, "PrivateKeyType {{ \"{}\" }}", s)
    }
}

/// A structure containing information about a public key.
pub struct PrivateKey {
    private: PrivateKeyType,
}

impl PrivateKey {
    /// Create an Ed25519 private key from PKCS#8v2 DER bytes.
    pub fn ed25519_from_pkcs8(der_key: &[u8]) -> Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8(Input::from(der_key)).map_err(
            |_| {
                Error::Encoding("Could not parse key as PKCS#8v2".into())
            },
        )?;
        Ok(PrivateKey { private: PrivateKeyType::Ed25519(key) })
    }

    /// Create an RSA private key from PKCS#8v2 DER bytes.
    pub fn rsa_from_pkcs8(der_key: &[u8]) -> Result<Self> {
        let key = RSAKeyPair::from_pkcs8(Input::from(der_key)).map_err(|_| {
            Error::Encoding("Could not parse key as PKCS#8v2".into())
        })?;
        Ok(PrivateKey { private: PrivateKeyType::Rsa(Arc::new(key)) })
    }

    /// Sign a message with the given scheme.
    pub fn sign(&self, msg: &[u8], scheme: &SignatureScheme) -> Result<SignatureValue> {
        match (&self.private, scheme) {
            (&PrivateKeyType::Rsa(ref rsa), &SignatureScheme::RsaSsaPssSha256) => {
                let mut signing_state = RSASigningState::new(rsa.clone()).map_err(|_| {
                    Error::Opaque("Could not initialize RSA signing state.".into())
                })?;
                let rng = SystemRandom::new();
                let mut buf = vec![0; signing_state.key_pair().public_modulus_len()];
                signing_state
                    .sign(&RSA_PSS_SHA256, &rng, msg, &mut buf)
                    .map_err(|_| Error::Opaque("Failed to sign message.".into()))?;
                Ok(SignatureValue(buf))
            }
            (&PrivateKeyType::Rsa(ref rsa), &SignatureScheme::RsaSsaPssSha512) => {
                let mut signing_state = RSASigningState::new(rsa.clone()).map_err(|_| {
                    Error::Opaque("Could not initialize RSA signing state.".into())
                })?;
                let rng = SystemRandom::new();
                let mut buf = vec![0; signing_state.key_pair().public_modulus_len()];
                signing_state
                    .sign(&RSA_PSS_SHA512, &rng, msg, &mut buf)
                    .map_err(|_| Error::Opaque("Failed to sign message.".into()))?;
                Ok(SignatureValue(buf))
            }
            (&PrivateKeyType::Ed25519(ref ed), &SignatureScheme::Ed25519) => {
                Ok(SignatureValue(ed.sign(msg).as_ref().into()))
            }
            (k, s) => Err(Error::IllegalArgument(
                format!("Key {:?} can't be used with scheme {:?}", k, s),
            )),
        }
    }
}


/// A structure containing information about a public key.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    typ: KeyType,
    format: KeyFormat,
    key_id: KeyId,
    value: PublicKeyValue,
}

impl PublicKey {
    /// Create a `PublicKey` from an Ed25519 `PublicKeyValue`.
    pub fn from_ed25519(value: PublicKeyValue) -> Result<Self> {
        if value.value().len() != 32 {
            return Err(Error::Encoding(
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

    /// Create a `PublicKey` from an RSA `PublicKeyValue`, either SPKI or PKCS#1.
    pub fn from_rsa(value: PublicKeyValue, format: KeyFormat) -> Result<Self> {
        // TODO check n > 2048 bits (but this is ok because `ring` doesn't support less)

        let key_id = calculate_key_id(&value);

        let pkcs1_value = match format {
            KeyFormat::Pkcs1 => {
                let bytes = rsa::from_pkcs1(value.value()).ok_or_else(|| {
                    Error::IllegalArgument(
                        "Key claimed to be PKCS1 but could not be parsed.".into(),
                    )
                })?;
                PublicKeyValue(bytes)
            }
            KeyFormat::Spki => {
                let bytes = rsa::from_spki(value.value()).ok_or_else(|| {
                    Error::IllegalArgument("Key claimed to be SPKI but could not be parsed.".into())
                })?;
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

    /// An immutable reference to the key's type.
    pub fn typ(&self) -> &KeyType {
        &self.typ
    }

    /// An immutable reference to the key's format.
    pub fn format(&self) -> &KeyFormat {
        &self.format
    }

    /// An immutable reference to the key's ID.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// An immutable reference to the key's public value.
    pub fn value(&self) -> &PublicKeyValue {
        &self.value
    }

    /// Use this key and the given signature scheme to verify the message again a signature.
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

/// Wrapper type for a decoded public key.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKeyValue(Vec<u8>);

impl PublicKeyValue {
    /// Create a new `PublicKeyValue` from the given bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        PublicKeyValue(bytes)
    }

    /// An immutable reference to the public key's bytes.
    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

/// Possible encoding/decoding formats for a public key.
#[derive(Clone, Debug, PartialEq)]
pub enum KeyFormat {
    /// The key should be read/written as hex-lower bytes.
    HexLower,
    /// The key should be read/written as PKCS#1 PEM.
    Pkcs1,
    /// The key should be read/written as SPKI PEM.
    Spki,
}

/// A structure that contains a `Signature` and associated data for verifying it.
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    key_id: KeyId,
    scheme: SignatureScheme,
    signature: SignatureValue,
}

impl Signature {
    /// An immutable reference to the `KeyId` that produced the signature.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// An immutable reference to the `SignatureScheme` used to create this signature.
    pub fn scheme(&self) -> &SignatureScheme {
        &self.scheme
    }

    /// An immutable reference to the `SignatureValue`.
    pub fn signature(&self) -> &SignatureValue {
        &self.signature
    }
}

/// The available hash algorithms.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA256 as describe in [RFC-6234](https://tools.ietf.org/html/rfc6234)
    #[serde(rename = "sha256")]
    Sha256,
    /// SHA512 as describe in [RFC-6234](https://tools.ietf.org/html/rfc6234)
    #[serde(rename = "sha512")]
    Sha512,
}

/// Wrapper for the value of a hash digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashValue(Vec<u8>);

impl HashValue {
    /// An immutable reference to the bytes of the hash value.
    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rsa_2048_ead_pkcs8_and_sign() {
        let der = include_bytes!("../tests/rsa/rsa-2048-private-key.pk8");
        let key = PrivateKey::rsa_from_pkcs8(der.as_ref()).unwrap();
        let msg = b"test";
        let _ = key.sign(msg, &SignatureScheme::RsaSsaPssSha256).unwrap();
        let _ = key.sign(msg, &SignatureScheme::RsaSsaPssSha512).unwrap();
        assert!(key.sign(msg, &SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn rsa_4096_read_pkcs8_and_sign() {
        let der = include_bytes!("../tests/rsa/rsa-4096-private-key.pk8");
        let key = PrivateKey::rsa_from_pkcs8(der.as_ref()).unwrap();
        let msg = b"test";
        let _ = key.sign(msg, &SignatureScheme::RsaSsaPssSha256).unwrap();
        let _ = key.sign(msg, &SignatureScheme::RsaSsaPssSha512).unwrap();
        assert!(key.sign(msg, &SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn ed25519_read_pkcs8_and_sign() {
        let der = include_bytes!("../tests/ed25519/ed25519-1.pk8");
        let key = PrivateKey::ed25519_from_pkcs8(der.as_ref()).unwrap();
        let msg = b"test";
        let _ = key.sign(msg, &SignatureScheme::Ed25519).unwrap();
        assert!(key.sign(msg, &SignatureScheme::RsaSsaPssSha256).is_err());
        assert!(key.sign(msg, &SignatureScheme::RsaSsaPssSha512).is_err());
    }
}
