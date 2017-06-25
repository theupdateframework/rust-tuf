//! Structures used to represent TUF metadata

use chrono::DateTime;
use chrono::offset::Utc;
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, Error as SerializeError};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::marker::PhantomData;

use Result;
use crypto::{KeyId, PublicKey, Signature};
use error::Error;
use interchange::DataInterchange;
use shims;

/// Trait used to represent whether a piece of data is verified or not.
pub trait VerificationStatus {}

/// Type used to represent verified data.
pub struct Verified {}
impl VerificationStatus for Verified {}

/// Type used to represent unverified data.
pub struct Unverified {}
impl VerificationStatus for Unverified {}

/// The TUF role.
#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// The root role.
    #[serde(rename = "root")]
    Root,
    /// The snapshot role.
    #[serde(rename = "snapshot")]
    Snapshot,
    /// The targets role.
    #[serde(rename = "targets")]
    Targets,
    /// The timestamp role.
    #[serde(rename = "timestamp")]
    Timestamp,
}

/// Enum used for addressing versioned TUF metadata.
#[derive(Debug)]
pub enum MetadataVersion {
    /// The metadata is unversioned.
    None,
    /// The metadata is addressed by a specific version number.
    Number(u32),
    /// The metadata is addressed by a hash prefix. Used with TUF's consistent snapshot feature.
    Hash(String),
}

impl MetadataVersion {
    /// Converts this struct into the string used for addressing metadata.
    pub fn prefix(&self) -> String {
        match self {
            &MetadataVersion::None => String::new(),
            &MetadataVersion::Number(ref x) => format!("{}.", x),
            &MetadataVersion::Hash(ref s) => format!("{}.", s),
        }
    }
}

/// Top level trait used for role metadata.
pub trait Metadata: Debug + PartialEq + Serialize + DeserializeOwned {}

/// A piece of raw metadata with attached signatures.
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
    /// An immutable reference to the signatures.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// A mutable reference to the signatures.
    pub fn signatures_mut(&mut self) -> &mut Vec<Signature> {
        &mut self.signatures
    }

    /// An immutable reference to the unverified raw data.
    /// 
    /// *WARNING*: This data is untrusted.
    pub fn unverified_signed(&self) -> &D::RawData {
        &self.signed
    }

    /// Verify this metadata and convert its type to `Verified`.
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
    /// An immutable reference to the verified raw data.
    pub fn signed(&self) -> &D::RawData {
        self.unverified_signed()
    }
}

/// Metdata for the root role.
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
    /// Create new `RootMetadata`.
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

    /// The version number.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// An immutable reference to the metadata's expiration `DateTime`.
    pub fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }

    /// Whether or not this repository is currently implementing that TUF consistent snapshot
    /// feature.
    pub fn consistent_snapshot(&self) -> bool {
        self.consistent_snapshot
    }

    /// An immutable reference to the map of trusted keys.
    pub fn keys(&self) -> &HashMap<KeyId, PublicKey> {
        &self.keys
    }

    /// An immutable reference to the root role's definition.
    pub fn root(&self) -> &RoleDefinition {
        &self.root
    }

    /// An immutable reference to the snapshot role's definition.
    pub fn snapshot(&self) -> &RoleDefinition {
        &self.snapshot
    }

    /// An immutable reference to the targets role's definition.
    pub fn targets(&self) -> &RoleDefinition {
        &self.targets
    }

    /// An immutable reference to the timestamp role's definition.
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

/// The definition of what allows a role to be trusted.
#[derive(Clone, Debug, PartialEq)]
pub struct RoleDefinition {
    threshold: u32,
    key_ids: HashSet<KeyId>,
}

impl RoleDefinition {
    /// Create a new `RoleDefinition` with a given threshold and set of authorized `KeyID`s.
    pub fn new(threshold: u32, key_ids: HashSet<KeyId>) -> Result<Self> {
        if threshold < 1 {
            return Err(Error::IllegalArgument(format!("Threshold: {}", threshold)));
        }

        Ok(RoleDefinition {
            threshold: threshold,
            key_ids: key_ids,
        })
    }

    /// The threshold number of signatures required for the role to be trusted.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// An immutable reference to the set of `KeyID`s that are authorized to sign the role.
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
    use json;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    use crypto::{KeyType, PublicKey, KeyFormat};

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
        let buf = "cf07711807f5176a4814613f3f348091dfc2b91f36b46a6abf6385f4ad14435b".to_string();

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
