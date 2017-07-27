//! Cryptographic structures and functions.

use data_encoding::BASE64URL;
use derp::{self, Der, Tag};
use ring;
use ring::digest::{self, SHA256, SHA512};
use ring::rand::SystemRandom;
use ring::signature::{RSAKeyPair, RSASigningState, Ed25519KeyPair, ED25519,
                      RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256,
                      RSA_PSS_SHA512};
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, Error as SerializeError};
use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;
use untrusted::Input;

use Result;
use error::Error;
use shims;

const HASH_ALG_PREFS: &'static [HashAlgorithm] = &[HashAlgorithm::Sha512, HashAlgorithm::Sha256];

/// 1.2.840.113549.1.1.1 rsaEncryption(PKCS #1)
const RSA_SPKI_OID: &'static [u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// 1.3.101.112 curveEd25519(EdDSA 25519 signature algorithm)
const ED25519_SPKI_OID: &'static [u8] = &[0x2b, 0x65, 0x70];

/// Given a map of hash algorithms and their values, get the prefered algorithm and the hash
/// calculated by it. Returns an `Err` if there is no match.
///
/// ```
/// use std::collections::HashMap;
/// use tuf::crypto::{hash_preference, HashValue, HashAlgorithm};
///
/// let mut map = HashMap::new();
/// assert!(hash_preference(&map).is_err());
///
/// let _ = map.insert(HashAlgorithm::Sha512, HashValue::new(vec![0x00, 0x01]));
/// assert_eq!(hash_preference(&map).unwrap().0, &HashAlgorithm::Sha512);
///
/// let _ = map.insert(HashAlgorithm::Sha256, HashValue::new(vec![0x02, 0x03]));
/// assert_eq!(hash_preference(&map).unwrap().0, &HashAlgorithm::Sha512);
/// ```
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

/// Calculate the size and hash digest from a given `Read`.
pub fn calculate_hashes<R: Read>(
    mut read: R,
    hash_algs: &[HashAlgorithm],
) -> Result<(u64, HashMap<HashAlgorithm, HashValue>)> {
    if hash_algs.len() == 0 {
        return Err(Error::IllegalArgument(
            "Cannot provide empty set of hash algorithms".into(),
        ));
    }

    let mut size = 0;
    let mut hashes = HashMap::new();
    for alg in hash_algs {
        let context = match alg {
            &HashAlgorithm::Sha256 => digest::Context::new(&SHA256),
            &HashAlgorithm::Sha512 => digest::Context::new(&SHA512),
        };

        let _ = hashes.insert(alg, context);
    }

    let mut buf = vec![0; 1024];
    loop {
        match read.read(&mut buf) {
            Ok(read_bytes) => {
                if read_bytes == 0 {
                    break;
                }

                size += read_bytes as u64;

                for (_, mut context) in hashes.iter_mut() {
                    context.update(&buf[0..read_bytes]);
                }
            }
            e @ Err(_) => e.map(|_| ())?,
        }
    }

    let hashes = hashes
        .drain()
        .map(|(k, v)| {
            (k.clone(), HashValue::new(v.finish().as_ref().to_vec()))
        })
        .collect();
    Ok((size, hashes))
}

fn calculate_key_id(public_key: &[u8]) -> KeyId {
    let mut context = digest::Context::new(&SHA256);
    context.update(&public_key);
    KeyId(context.finish().as_ref().to_vec())
}

/// Wrapper type for public key's ID.
///
/// # Calculating
/// A `KeyId` is calculated as `sha256(spki(pub_key_bytes))` where `spki` is a function that takes
/// any encoding for a public key an converts it into the `SubjectPublicKeyInfo` (SPKI) DER
/// encoding.
///
/// Note: Historically the TUF spec says that a key's ID should be calculated with
/// `sha256(cjson(encoded(pub_key_bytes)))`, but since there could be multiple supported data
/// interchange formats, relying on an encoding that uses JSON does not make sense.
///
/// # ASN.1
/// ```bash
/// PublicKey ::= CHOICE {
///     -- This field is checked for consistency against `subjectPublicKey`.
///     -- The OID determines how we attempt to parse the `BIT STRING`.
///     algorithm        AlgorithmIdentifier,
///     -- Either:
///     --   1. Encapsulates an `RsaPublicKey`
///     --   2. Equals an `Ed25519PublicKey`
///     subjectPublicKey BIT STRING
/// }
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     -- Either:
///     --   1. 1.2.840.113549.1.1.1 rsaEncryption(PKCS #1)
///     --   2. 1.3.101.112 curveEd25519(EdDSA 25519 signature algorithm)
///     algorithm  OBJECT IDENTIFIER,
///     -- In our cases, this is always `NULL`.
///     parameters ANY DEFINED BY algorithm OPTIONAL
/// }
///
/// RsaPublicKey ::= SEQUENCE {
///     modulus  INTEGER (1..MAX),
///     exponent INTEGER (1..MAX)
/// }
///
/// Ed25519PublicKey ::= BIT STRING
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    /// Parse a key ID from a base64url string.
    pub fn from_string(string: &str) -> Result<Self> {
        if string.len() != 44 {
            return Err(Error::IllegalArgument(
                "Base64 key ID must be 44 characters long".into(),
            ));
        }
        Ok(KeyId(BASE64URL.decode(string.as_bytes())?))
    }
}

impl Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyId {{ \"{}\" }}", BASE64URL.encode(&self.0))
    }
}

impl Serialize for KeyId {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BASE64URL.encode(&self.0).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        KeyId::from_string(&string).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Cryptographic signature schemes.
#[derive(Debug, Clone, PartialEq)]
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
        string.parse().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

/// Wrapper type for the value of a cryptographic signature.
#[derive(Clone, PartialEq)]
pub struct SignatureValue(Vec<u8>);

impl SignatureValue {
    /// Create a new `SignatureValue` from the given bytes.
    ///
    /// Note: It is unlikely that you ever want to do this manually.
    pub fn new(bytes: Vec<u8>) -> Self {
        SignatureValue(bytes)
    }

    /// Create a new `SignatureValue` from the given base64url string.
    ///
    /// Note: It is unlikely that you ever want to do this manually.
    pub fn from_string(string: &str) -> Result<Self> {
        Ok(SignatureValue(BASE64URL.decode(string.as_bytes())?))
    }
}

impl Debug for SignatureValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignatureValue {{ \"{}\" }}", BASE64URL.encode(&self.0))
    }
}

impl Serialize for SignatureValue {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BASE64URL.encode(&self.0).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for SignatureValue {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        SignatureValue::from_string(&string).map_err(|e| {
            DeserializeError::custom(format!("Signature value was not valid base64url: {:?}", e))
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

impl KeyType {
    fn from_oid(oid: &[u8]) -> Result<Self> {
        match oid {
            x if x == RSA_SPKI_OID => Ok(KeyType::Rsa),
            x if x == ED25519_SPKI_OID => Ok(KeyType::Ed25519),
            x => Err(Error::Encoding(format!(
                "Unknown OID: {}",
                x.iter().map(|b| format!("{:x}", b)).collect::<String>()
            ))),
        }
    }

    fn as_oid(&self) -> &'static [u8] {
        match self {
            &KeyType::Rsa => RSA_SPKI_OID,
            &KeyType::Ed25519 => ED25519_SPKI_OID,
        }
    }
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
        string.parse().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
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

/// A structure containing information about a private key.
pub struct PrivateKey {
    private: PrivateKeyType,
    public: PublicKey,
}

impl PrivateKey {
    /// Create a private key from PKCS#8v2 DER bytes.
    ///
    /// # Generating Keys
    ///
    /// If you use `cargo install tuf`, you will have access to the TUF CLI tool that will allow
    /// you to generate keys. If you do not want to do this, the following can be used instead.
    ///
    /// ## Ed25519
    ///
    /// ```bash
    /// $ touch ed25519-private-key.pk8
    /// $ chmod 0600 ed25519-private-key.pk8
    /// ```
    ///
    /// ```no_run
    /// extern crate ring;
    /// use ring::rand::SystemRandom;
    /// use ring::signature::Ed25519KeyPair;
    /// use std::fs::File;
    /// use std::io::Write;
    ///
    /// fn main() {
    ///     let mut file = File::open("ed25519-private-key.pk8").unwrap();
    ///     let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    ///     file.write_all(&key).unwrap()
    /// }
    /// ```
    ///
    /// ## RSA
    ///
    /// ```bash
    /// $ umask 077
    /// $ openssl genpkey -algorithm RSA \
    ///     -pkeyopt rsa_keygen_bits:4096 \
    ///     -pkeyopt rsa_keygen_pubexp:65537 | \
    ///     openssl pkcs8 -topk8 -nocrypt -outform der > rsa-4096-private-key.pk8
    /// ```
    pub fn from_pkcs8(der_key: &[u8]) -> Result<Self> {
        match Self::ed25519_from_pkcs8(der_key) {
            Ok(k) => Ok(k),
            Err(e1) => {
                match Self::rsa_from_pkcs8(der_key) {
                    Ok(k) => Ok(k),
                    Err(e2) => Err(Error::Opaque(format!(
                        "Key was neither Ed25519 nor RSA: {:?} {:?}",
                        e1,
                        e2
                    ))),
                }
            }
        }
    }

    fn ed25519_from_pkcs8(der_key: &[u8]) -> Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8(Input::from(der_key)).map_err(
            |_| {
                Error::Encoding("Could not parse key as PKCS#8v2".into())
            },
        )?;

        let public = PublicKey {
            typ: KeyType::Ed25519,
            key_id: calculate_key_id(&write_spki(key.public_key_bytes(), &KeyType::Ed25519)?),
            value: PublicKeyValue(key.public_key_bytes().to_vec()),
        };
        let private = PrivateKeyType::Ed25519(key);

        Ok(PrivateKey {
            private: private,
            public: public,
        })
    }

    fn rsa_from_pkcs8(der_key: &[u8]) -> Result<Self> {
        let key = RSAKeyPair::from_pkcs8(Input::from(der_key)).map_err(|_| {
            Error::Encoding("Could not parse key as PKCS#8v2".into())
        })?;

        if key.public_modulus_len() < 256 {
            return Err(Error::IllegalArgument(format!(
                "RSA public modulus must be 2048 or greater. Found {}",
                key.public_modulus_len() * 8
            )));
        }

        let pub_key = extract_rsa_pub_from_pkcs8(der_key)?;

        let public = PublicKey {
            typ: KeyType::Rsa,
            key_id: calculate_key_id(&write_spki(&pub_key, &KeyType::Rsa)?),
            value: PublicKeyValue(pub_key),
        };
        let private = PrivateKeyType::Rsa(Arc::new(key));

        Ok(PrivateKey {
            private: private,
            public: public,
        })
    }

    /// Return whether or not this key supports the given signature scheme.
    pub fn supports(&self, scheme: &SignatureScheme) -> bool {
        match (&self.private, scheme) {
            (&PrivateKeyType::Rsa(_), &SignatureScheme::RsaSsaPssSha256) => true,
            (&PrivateKeyType::Rsa(_), &SignatureScheme::RsaSsaPssSha512) => true,
            (&PrivateKeyType::Ed25519(_), &SignatureScheme::Ed25519) => true,
            _ => false,
        }
    }

    /// Sign a message with the given scheme.
    pub fn sign(&self, msg: &[u8], scheme: SignatureScheme) -> Result<Signature> {
        let value = match (&self.private, &scheme) {
            (&PrivateKeyType::Rsa(ref rsa), &SignatureScheme::RsaSsaPssSha256) => {
                let mut signing_state = RSASigningState::new(rsa.clone()).map_err(|_| {
                    Error::Opaque("Could not initialize RSA signing state.".into())
                })?;
                let rng = SystemRandom::new();
                let mut buf = vec![0; signing_state.key_pair().public_modulus_len()];
                signing_state
                    .sign(&RSA_PSS_SHA256, &rng, msg, &mut buf)
                    .map_err(|_| Error::Opaque("Failed to sign message.".into()))?;
                SignatureValue(buf)
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
                SignatureValue(buf)
            }
            (&PrivateKeyType::Ed25519(ref ed), &SignatureScheme::Ed25519) => {
                SignatureValue(ed.sign(msg).as_ref().into())
            }
            (k, s) => {
                return Err(Error::IllegalArgument(
                    format!("Key {:?} can't be used with scheme {:?}", k, s),
                ))
            }
        };

        Ok(Signature {
            key_id: self.key_id().clone(),
            scheme: scheme,
            value: value,
        })
    }

    /// Return the public component of the key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Return the key ID of the public key.
    pub fn key_id(&self) -> &KeyId {
        &self.public.key_id
    }
}


/// A structure containing information about a public key.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    typ: KeyType,
    key_id: KeyId,
    value: PublicKeyValue,
}

impl PublicKey {
    /// Parse DER bytes as an SPKI key.
    ///
    /// See the documentation on `KeyValue` for more information on SPKI.
    pub fn from_spki(der_bytes: &[u8]) -> Result<Self> {
        let input = Input::from(der_bytes);
        let (typ, value) = input.read_all(derp::Error::Read, |input| {
            derp::nested(input, Tag::Sequence, |input| {
                let typ = derp::nested(input, Tag::Sequence, |input| {
                    let typ = derp::expect_tag_and_get_value(input, Tag::Oid)?;
                    let typ = KeyType::from_oid(typ.as_slice_less_safe()).map_err(|_| {
                        derp::Error::WrongValue
                    })?;
                    // for RSA / ed25519 this is null, so don't both parsing it
                    let _ = derp::read_null(input)?;
                    Ok(typ)
                })?;
                let value = derp::bit_string_with_no_unused_bits(input)?;
                Ok((typ, value.as_slice_less_safe().to_vec()))
            })
        })?;
        let key_id = calculate_key_id(der_bytes);
        Ok(PublicKey {
            typ: typ,
            key_id: key_id,
            value: PublicKeyValue(value),
        })
    }

    /// Write the public key as SPKI DER bytes.
    ///
    /// See the documentation on `KeyValue` for more information on SPKI.
    pub fn as_spki(&self) -> Result<Vec<u8>> {
        Ok(write_spki(&self.value.0, &self.typ)?)
    }

    /// An immutable reference to the key's type.
    pub fn typ(&self) -> &KeyType {
        &self.typ
    }

    /// An immutable reference to the key's ID.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Use this key to verify a message with a signature.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let alg: &ring::signature::VerificationAlgorithm = match sig.scheme() {
            &SignatureScheme::Ed25519 => &ED25519,
            &SignatureScheme::RsaSsaPssSha256 => &RSA_PSS_2048_8192_SHA256,
            &SignatureScheme::RsaSsaPssSha512 => &RSA_PSS_2048_8192_SHA512,
        };

        ring::signature::verify(
            alg,
            Input::from(&self.value.0),
            Input::from(msg),
            Input::from(&sig.value.0),
        ).map_err(|_| Error::BadSignature)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_spki().map_err(|e| {
            SerializeError::custom(format!("Couldn't write key as SPKI: {:?}", e))
        })?;
        shims::PublicKey::new(self.typ.clone(), &bytes).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::PublicKey = Deserialize::deserialize(de)?;
        let bytes = BASE64URL
            .decode(intermediate.public_key().as_bytes())
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))?;

        let key = PublicKey::from_spki(&bytes).map_err(|e| {
            DeserializeError::custom(format!("Couldn't parse key as SPKI: {:?}", e))
        })?;

        if intermediate.typ() != &key.typ {
            return Err(DeserializeError::custom(
                format!("Key type listed in the metadata did not match the type extrated \
                            from the key. {:?} vs. {:?}",
                            intermediate.typ(),
                            key.typ,
                            ),
            ));
        }

        Ok(key)
    }
}

#[derive(Clone, PartialEq)]
struct PublicKeyValue(Vec<u8>);

impl Debug for PublicKeyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicKeyValue {{ \"{}\" }}", BASE64URL.encode(&self.0))
    }
}

/// A structure that contains a `Signature` and associated data for verifying it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    key_id: KeyId,
    scheme: SignatureScheme,
    value: SignatureValue,
}

impl Signature {
    /// An immutable reference to the `KeyId` of the key that produced the signature.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// An immutable reference to the `SignatureScheme` used to create this signature.
    pub fn scheme(&self) -> &SignatureScheme {
        &self.scheme
    }

    /// An immutable reference to the `SignatureValue`.
    pub fn value(&self) -> &SignatureValue {
        &self.value
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
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct HashValue(Vec<u8>);

impl HashValue {
    /// Create a new `HashValue` from the given digest bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        HashValue(bytes)
    }

    /// An immutable reference to the bytes of the hash value.
    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for HashValue {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BASE64URL.encode(&self.0).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for HashValue {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        let bytes = BASE64URL.decode(s.as_bytes()).map_err(|e| {
            DeserializeError::custom(format!("Base64: {:?}", e))
        })?;
        Ok(HashValue(bytes))
    }
}

impl Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HashValue {{ \"{}\" }}", BASE64URL.encode(&self.0))
    }
}

impl Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64URL.encode(&self.0))
    }
}

fn write_spki(public: &[u8], key_type: &KeyType) -> ::std::result::Result<Vec<u8>, derp::Error> {
    let mut output = Vec::new();
    {
        let mut der = Der::new(&mut output);
        der.write_sequence(|der| {
            der.write_sequence(|der| {
                der.write_element(Tag::Oid, key_type.as_oid())?;
                der.write_null()
            })?;
            der.write_bit_string(0, |der| der.write_raw(public))
        })?;
    }

    Ok(output)
}

fn extract_rsa_pub_from_pkcs8(der_key: &[u8]) -> ::std::result::Result<Vec<u8>, derp::Error> {
    let input = Input::from(der_key);
    input.read_all(derp::Error::Read, |input| {
        derp::nested(input, Tag::Sequence, |input| {
            if derp::small_nonnegative_integer(input)? != 0 {
                return Err(derp::Error::WrongValue);
            }

            derp::nested(input, Tag::Sequence, |input| {
                let actual_alg_id = derp::expect_tag_and_get_value(input, Tag::Oid)?;
                if actual_alg_id.as_slice_less_safe() != RSA_SPKI_OID {
                    return Err(derp::Error::WrongValue);
                }
                let _ = derp::expect_tag_and_get_value(input, Tag::Null)?;
                Ok(())
            })?;

            derp::nested(input, Tag::OctetString, |input| {
                derp::nested(input, Tag::Sequence, |input| {
                    if derp::small_nonnegative_integer(input)? != 0 {
                        return Err(derp::Error::WrongValue);
                    }

                    let n = derp::positive_integer(input)?;
                    let e = derp::positive_integer(input)?;
                    let _ = input.skip_to_end();
                    write_pkcs1(n.as_slice_less_safe(), e.as_slice_less_safe())
                })
            })
        })
    })
}

fn write_pkcs1(n: &[u8], e: &[u8]) -> ::std::result::Result<Vec<u8>, derp::Error> {
    let mut output = Vec::new();
    {
        let mut der = Der::new(&mut output);
        der.write_sequence(|der| {
            der.write_positive_integer(n)?;
            der.write_positive_integer(e)
        })?;
    }

    Ok(output)
}

#[cfg(test)]
mod test {
    use super::*;
    use json;

    const RSA_2048_PK8: &'static [u8] = include_bytes!("../tests/rsa/rsa-2048.pk8.der");
    const RSA_2048_SPKI: &'static [u8] = include_bytes!("../tests/rsa/rsa-2048.spki.der");
    const RSA_2048_PKCS1: &'static [u8] = include_bytes!("../tests/rsa/rsa-2048.pkcs1.der");

    const RSA_4096_PK8: &'static [u8] = include_bytes!("../tests/rsa/rsa-4096.pk8.der");
    const RSA_4096_SPKI: &'static [u8] = include_bytes!("../tests/rsa/rsa-4096.spki.der");
    const RSA_4096_PKCS1: &'static [u8] = include_bytes!("../tests/rsa/rsa-4096.pkcs1.der");

    const ED25519_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");

    #[test]
    fn parse_rsa_2048_spki() {
        let key = PublicKey::from_spki(RSA_2048_SPKI).unwrap();
        assert_eq!(key.typ, KeyType::Rsa);
    }

    #[test]
    fn parse_rsa_4096_spki() {
        let key = PublicKey::from_spki(RSA_4096_SPKI).unwrap();
        assert_eq!(key.typ, KeyType::Rsa);
    }

    #[test]
    fn rsa_2048_read_pkcs8_and_sign() {
        let key = PrivateKey::from_pkcs8(RSA_2048_PK8).unwrap();
        let msg = b"test";

        let sig = key.sign(msg, SignatureScheme::RsaSsaPssSha256).unwrap();
        key.public.verify(msg, &sig).unwrap();

        let sig = key.sign(msg, SignatureScheme::RsaSsaPssSha512).unwrap();
        key.public.verify(msg, &sig).unwrap();

        assert!(key.sign(msg, SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn rsa_4096_read_pkcs8_and_sign() {
        let key = PrivateKey::from_pkcs8(RSA_4096_PK8).unwrap();
        let msg = b"test";

        let sig = key.sign(msg, SignatureScheme::RsaSsaPssSha256).unwrap();
        key.public.verify(msg, &sig).unwrap();

        let sig = key.sign(msg, SignatureScheme::RsaSsaPssSha512).unwrap();
        key.public.verify(msg, &sig).unwrap();

        assert!(key.sign(msg, SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn extract_pkcs1_from_rsa_2048_pkcs8() {
        let res = extract_rsa_pub_from_pkcs8(RSA_2048_PK8).unwrap();
        assert_eq!(res.as_slice(), RSA_2048_PKCS1);
    }

    #[test]
    fn extract_pkcs1_from_rsa_4096_pkcs8() {
        let res = extract_rsa_pub_from_pkcs8(RSA_4096_PK8).unwrap();
        assert_eq!(res.as_slice(), RSA_4096_PKCS1);
    }

    #[test]
    fn ed25519_read_pkcs8_and_sign() {
        let key = PrivateKey::from_pkcs8(ED25519_PK8).unwrap();
        let msg = b"test";

        let sig = key.sign(msg, SignatureScheme::Ed25519).unwrap();

        let public = PublicKey::from_spki(&key.public.as_spki().unwrap()).unwrap();
        public.verify(msg, &sig).unwrap();

        assert!(key.sign(msg, SignatureScheme::RsaSsaPssSha256).is_err());
        assert!(key.sign(msg, SignatureScheme::RsaSsaPssSha512).is_err());
    }

    #[test]
    fn serde_key_id() {
        let s = "T5vfRrM1iHpgzGwAHe7MbJH_7r4chkOAphV3OPCCv0I=";
        let jsn = json!(s);
        let parsed: KeyId = json::from_str(&format!("\"{}\"", s)).unwrap();
        assert_eq!(parsed, KeyId::from_string(s).unwrap());
        let encoded = json::to_value(&parsed).unwrap();
        assert_eq!(encoded, jsn);
    }

    #[test]
    fn serde_signature_value() {
        let s = "T5vfRrM1iHpgzGwAHe7MbJH_7r4chkOAphV3OPCCv0I=";
        let jsn = json!(s);
        let parsed: SignatureValue = json::from_str(&format!("\"{}\"", s)).unwrap();
        assert_eq!(parsed, SignatureValue::from_string(s).unwrap());
        let encoded = json::to_value(&parsed).unwrap();
        assert_eq!(encoded, jsn);
    }

    #[test]
    fn serde_rsa_public_key() {
        let der = RSA_2048_SPKI;
        let pub_key = PublicKey::from_spki(der).unwrap();
        let encoded = json::to_value(&pub_key).unwrap();
        let jsn = json!({
            "type": "rsa",
            "public_key": BASE64URL.encode(der),
        });
        assert_eq!(encoded, jsn);
        let decoded: PublicKey = json::from_value(encoded).unwrap();
        assert_eq!(decoded, pub_key);
    }

    #[test]
    fn serde_signature() {
        let key = PrivateKey::from_pkcs8(ED25519_PK8).unwrap();
        let msg = b"test";
        let sig = key.sign(msg, SignatureScheme::Ed25519).unwrap();
        let encoded = json::to_value(&sig).unwrap();
        let jsn = json!({
            "key_id": "qfrfBrkB4lBBSDEBlZgaTGS_SrE6UfmON9kP4i3dJFY=",
            "scheme": "ed25519",
            "value": "_k0Tsqc8Azod5_UQeyBfx7oOFWbLlbkjScrmqkU4lWATv-D3v5d8sHK7Z\
                eh4K18zoFc_54gWKZoBfKW6VZ45DA==",
        });
        assert_eq!(encoded, jsn);

        let decoded: Signature = json::from_value(encoded).unwrap();
        assert_eq!(decoded, sig);
    }
}
