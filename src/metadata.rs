use chrono::DateTime;
use chrono::offset::Utc;
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, Error as SerializeError};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::marker::PhantomData;

use Result;
use crypto::{KeyId, PublicKey, SignatureScheme, SignatureValue};
use error::Error;
use interchange::DataInterchange;
use shims;

pub trait VerificationStatus {}
pub struct Verified {}
impl VerificationStatus for Verified {}
pub struct Unverified {}
impl VerificationStatus for Unverified {}

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
pub struct SignedMetadata<D, M, V>
where
    D: DataInterchange,
    M: Metadata,
    V: VerificationStatus,
{
    signatures: Vec<Signature>,
    signed: D::RawData,
    _interchage: PhantomData<D>,
    _metadata: PhantomData<M>,
    _verification: PhantomData<V>,
}

impl<D, M, V> SignedMetadata<D, M, V>
where
    D: DataInterchange,
    M: Metadata,
    V: VerificationStatus,
{
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    pub fn signatures_mut(&mut self) -> &mut Vec<Signature> {
        &mut self.signatures
    }

    pub fn unverified_signed(&self) -> &D::RawData {
        &self.signed
    }

    pub fn verify(
        self,
        threshold: u32,
        authorized_key_ids: &HashSet<KeyId>,
        available_keys: &HashMap<KeyId, PublicKey>,
    ) -> Result<SignedMetadata<D, M, Verified>> {
        if self.signatures.len() < 1 {
            return Err(Error::VerificationFailure(
                "The metadata was not signed with any authorized keys."
                    .into(),
            ));
        }

        if threshold < 1 {
            return Err(Error::VerificationFailure(
                "Threshold must be strictly greater than zero".into(),
            ));
        }

        let canonical_bytes = D::canonicalize(&self.signed)?;

        let mut signatures_needed = threshold;
        for sig in self.signatures.iter() {
            if !authorized_key_ids.contains(sig.key_id()) {
                warn!(
                    "Key ID {:?} is not authorized to sign root metadata.",
                    sig.key_id()
                );
                continue;
            }

            match available_keys.get(sig.key_id()) {
                Some(ref pub_key) => {
                    match pub_key.verify(sig.scheme(), &canonical_bytes, sig.signature()) {
                        Ok(()) => {
                            debug!("Good signature from key ID {:?}", pub_key.key_id());
                            signatures_needed -= 1;
                        }
                        Err(e) => {
                            warn!("Bad signature from key ID {:?}: {:?}", pub_key.key_id(), e);
                        }
                    }
                }
                None => {
                    warn!(
                        "Key ID {:?} was not found in the set of available keys.",
                        sig.key_id()
                    );
                }
            }
            if signatures_needed == 0 {
                break;
            }
        }

        if signatures_needed == 0 {
            Ok(SignedMetadata {
                signatures: self.signatures,
                signed: self.signed,
                _interchage: PhantomData,
                _metadata: PhantomData,
                _verification: PhantomData,
            })
        } else {
            Err(Error::VerificationFailure(format!(
                "Signature threshold not met: {}/{}",
                threshold - signatures_needed,
                threshold
            )))
        }
    }
}

impl<D, M> SignedMetadata<D, M, Verified>
where
    D: DataInterchange,
    M: Metadata,
{
    pub fn signed(&self) -> &D::RawData {
        self.unverified_signed()
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
        mut keys: Vec<PublicKey>,
        root: RoleDefinition,
        snapshot: RoleDefinition,
        targets: RoleDefinition,
        timestamp: RoleDefinition,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        let keys = keys.drain(0..)
            .map(|k| (k.key_id().clone(), k))
            .collect::<HashMap<KeyId, PublicKey>>();

        Ok(RootMetadata {
            version: version,
            expires: expires,
            consistent_snapshot: consistent_snapshot,
            keys: keys,
            root: root,
            snapshot: snapshot,
            targets: targets,
            timestamp: timestamp,
        })
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
#[derive(Clone, Debug, PartialEq)]
pub struct RoleDefinition {
    threshold: u32,
    key_ids: HashSet<KeyId>,
}

impl RoleDefinition {
    pub fn new(threshold: u32, key_ids: HashSet<KeyId>) -> Result<Self> {
        if threshold < 1 {
            return Err(Error::IllegalArgument(format!("Threshold: {}", threshold)));
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
