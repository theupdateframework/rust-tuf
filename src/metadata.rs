//! Structures used to represent TUF metadata

use chrono::DateTime;
use chrono::offset::Utc;
use ring::digest::{self, SHA256, SHA512};
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, Error as SerializeError};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Display};
use std::io::Read;
use std::iter::FromIterator;
use std::marker::PhantomData;

use Result;
use crypto::{KeyId, PublicKey, Signature, HashAlgorithm, HashValue, SignatureScheme, PrivateKey};
use error::Error;
use interchange::DataInterchange;
use shims;

static PATH_ILLEGAL_COMPONENTS: &'static [&str] = &[
    "", // empty
    ".", // current dir
    "..", // parent dir
    // TODO ? "0", // may translate to nul in windows
];

static PATH_ILLEGAL_COMPONENTS_CASE_INSENSITIVE: &'static [&str] = &[
    // DOS device files
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "KEYBD$",
    "CLOCK$",
    "SCREEN$",
    "$IDLE$",
    "CONFIG$",
];

static PATH_ILLEGAL_STRINGS: &'static [&str] = &[
    "\\", // for windows compatibility
    "<",
    ">",
    "\"",
    "|",
    "?",
    "*",
    // control characters, all illegal in FAT
    "\u{000}",
    "\u{001}",
    "\u{002}",
    "\u{003}",
    "\u{004}",
    "\u{005}",
    "\u{006}",
    "\u{007}",
    "\u{008}",
    "\u{009}",
    "\u{00a}",
    "\u{00b}",
    "\u{00c}",
    "\u{00d}",
    "\u{00e}",
    "\u{00f}",
    "\u{010}",
    "\u{011}",
    "\u{012}",
    "\u{013}",
    "\u{014}",
    "\u{015}",
    "\u{016}",
    "\u{017}",
    "\u{018}",
    "\u{019}",
    "\u{01a}",
    "\u{01b}",
    "\u{01c}",
    "\u{01d}",
    "\u{01e}",
    "\u{01f}",
    "\u{07f}",
];

fn safe_path(path: &str) -> Result<()> {
    if path.starts_with("/") {
        return Err(Error::IllegalArgument("Cannot start with '/'".into()));
    }

    for bad_str in PATH_ILLEGAL_STRINGS {
        if path.contains(bad_str) {
            return Err(Error::IllegalArgument(
                format!("Path cannot contain {:?}", bad_str),
            ));
        }
    }

    for component in path.split('/') {
        for bad_str in PATH_ILLEGAL_COMPONENTS {
            if component == *bad_str {
                return Err(Error::IllegalArgument(
                    format!("Path cannot have component {:?}", component),
                ));
            }
        }

        let component_lower = component.to_lowercase();
        for bad_str in PATH_ILLEGAL_COMPONENTS_CASE_INSENSITIVE {
            if component_lower.as_str() == *bad_str {
                return Err(Error::IllegalArgument(
                    format!("Path cannot have component {:?}", component),
                ));
            }
        }
    }

    Ok(())
}

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

impl Role {
    /// Check if this role could be associated with a given path.
    ///
    /// ```
    /// use tuf::metadata::{MetadataPath, Role};
    ///
    /// assert!(Role::Root.fuzzy_matches_path(&MetadataPath::from_role(&Role::Root)));
    /// assert!(Role::Snapshot.fuzzy_matches_path(&MetadataPath::from_role(&Role::Snapshot)));
    /// assert!(Role::Targets.fuzzy_matches_path(&MetadataPath::from_role(&Role::Targets)));
    /// assert!(Role::Timestamp.fuzzy_matches_path(&MetadataPath::from_role(&Role::Timestamp)));
    ///
    /// assert!(!Role::Root.fuzzy_matches_path(&MetadataPath::from_role(&Role::Snapshot)));
    /// assert!(!Role::Root.fuzzy_matches_path(&MetadataPath::new("wat".into()).unwrap()));
    /// ```
    pub fn fuzzy_matches_path(&self, path: &MetadataPath) -> bool {
        match self {
            &Role::Root if &path.0 == "root" => true,
            &Role::Snapshot if &path.0 == "snapshot" => true,
            &Role::Timestamp if &path.0 == "timestamp" => true,
            &Role::Targets if &path.0 == "targets" => true,
            // TODO delegation support
            _ => false,
        }
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Role::Root => write!(f, "root"),
            &Role::Snapshot => write!(f, "snapshot"),
            &Role::Targets => write!(f, "targets"),
            &Role::Timestamp => write!(f, "timestamp"),
        }
    }
}

/// Enum used for addressing versioned TUF metadata.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum MetadataVersion {
    /// The metadata is unversioned.
    None,
    /// The metadata is addressed by a specific version number.
    Number(u32),
    /// The metadata is addressed by a hash prefix. Used with TUF's consistent snapshot feature.
    Hash(HashValue),
}

impl MetadataVersion {
    /// Converts this struct into the string used for addressing metadata.
    pub fn prefix(&self) -> String {
        match self {
            &MetadataVersion::None => String::new(),
            &MetadataVersion::Number(ref x) => format!("{}.", x),
            &MetadataVersion::Hash(ref v) => format!("{}.", v),
        }
    }
}

/// Top level trait used for role metadata.
pub trait Metadata: Debug + PartialEq + Serialize + DeserializeOwned {
    /// The role associated with the metadata.
    fn role() -> Role;
}

/// A piece of raw metadata with attached signatures.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedMetadata<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    signatures: Vec<Signature>,
    signed: D::RawData,
    #[serde(skip_serializing, skip_deserializing)]
    _interchage: PhantomData<D>,
    #[serde(skip_serializing, skip_deserializing)]
    _metadata: PhantomData<M>,
}

impl<D, M> SignedMetadata<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    /// Create a new `SignedMetadata`.
    pub fn new(
        metadata: &M,
        private_key: &PrivateKey,
        scheme: SignatureScheme,
    ) -> Result<SignedMetadata<D, M>> {
        let raw = D::serialize(metadata)?;
        let bytes = D::canonicalize(&raw)?;
        let sig = private_key.sign(&bytes, scheme)?;
        Ok(SignedMetadata {
            signatures: vec![sig],
            signed: raw,
            _interchage: PhantomData,
            _metadata: PhantomData,
        })
    }

    /// Append a signature to this signed metadata. Will overwrite signature by keys with the same
    /// ID.
    pub fn add_signature(
        &mut self,
        private_key: &PrivateKey,
        scheme: SignatureScheme,
    ) -> Result<()> {
        let raw = D::serialize(&self.signed)?;
        let bytes = D::canonicalize(&raw)?;
        let sig = private_key.sign(&bytes, scheme)?;
        self.signatures.retain(
            |s| s.key_id() != private_key.key_id(),
        );
        self.signatures.push(sig);
        Ok(())
    }

    /// An immutable reference to the signatures.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// A mutable reference to the signatures.
    pub fn signatures_mut(&mut self) -> &mut Vec<Signature> {
        &mut self.signatures
    }

    /// An immutable reference to the raw data.
    pub fn signed(&self) -> &D::RawData {
        &self.signed
    }

    /// Verify this metadata.
    pub fn verify(
        &self,
        threshold: u32,
        authorized_key_ids: &HashSet<KeyId>,
        available_keys: &HashMap<KeyId, PublicKey>,
    ) -> Result<()> {
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
                    match pub_key.verify(&canonical_bytes, &sig) {
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
            Ok(())
        } else {
            Err(Error::VerificationFailure(format!(
                "Signature threshold not met: {}/{}",
                threshold - signatures_needed,
                threshold
            )))
        }
    }
}

/// Metadata for the root role.
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

        let keys = HashMap::from_iter(keys.drain(..).map(|k| (k.key_id().clone(), k)));

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

impl Metadata for RootMetadata {
    fn role() -> Role {
        Role::Root
    }
}

impl Serialize for RootMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let m = shims::RootMetadata::from(self).map_err(|e| {
            SerializeError::custom(format!("{:?}", e))
        })?;
        m.serialize(ser)
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

        if key_ids.is_empty() {
            return Err(Error::IllegalArgument(
                "Cannot define a role with no associated key IDs".into(),
            ));
        }

        if (key_ids.len() as u64) < (threshold as u64) {
            return Err(Error::IllegalArgument(format!(
                "Cannot have a threshold greater than the number of associated key IDs. {} vs. {}",
                threshold,
                key_ids.len()
            )));
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

/// Wrapper for a path to metadata
#[derive(Debug, Clone, PartialEq, Hash, Eq, Serialize)]
pub struct MetadataPath(String);

impl MetadataPath {
    /// Create a new `MetadataPath` from a `String`.
    ///
    /// ```
    /// use tuf::metadata::MetadataPath;
    ///
    /// assert!(MetadataPath::new("foo".into()).is_ok());
    /// assert!(MetadataPath::new("/foo".into()).is_err());
    /// assert!(MetadataPath::new("../foo".into()).is_err());
    /// assert!(MetadataPath::new("foo/".into()).is_err());
    /// assert!(MetadataPath::new("foo/..".into()).is_err());
    /// assert!(MetadataPath::new("foo/../bar".into()).is_err());
    /// assert!(MetadataPath::new("..foo".into()).is_ok());
    /// assert!(MetadataPath::new("foo//bar".into()).is_err());
    /// assert!(MetadataPath::new("foo/..bar".into()).is_ok());
    /// assert!(MetadataPath::new("foo/bar..".into()).is_ok());
    /// ```
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(MetadataPath(path))
    }

    /// Create a metadata path from the given role.
    /// ```
    /// use tuf::metadata::{Role, MetadataPath};
    ///
    /// assert_eq!(MetadataPath::from_role(&Role::Root),
    ///            MetadataPath::new("root".into()))
    /// assert_eq!(MetadataPath::from_role(&Role::Snapshot),
    ///            MetadataPath::new("snapshot".into()))
    /// assert_eq!(MetadataPath::from_role(&Role::Targets),
    ///            MetadataPath::new("targets".into()))
    /// assert_eq!(MetadataPath::from_role(&Role::Timestamp),
    ///            MetadataPath::new("timestamp".into()))
    /// ```
    pub fn from_role(role: &Role) -> Self {
        Self::new(format!("{}", role)).unwrap()
    }

    /// Split `MetadataPath` into components that can be joined to create URL paths, Unix paths, or
    /// Windows paths.
    ///
    /// ```
    /// use tuf::crypto::HashValue;
    /// use tuf::interchange::JsonDataInterchange;
    /// use tuf::metadata::{MetadataPath, MetadataVersion};
    ///
    /// let path = MetadataPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components::<JsonDataInterchange>(&MetadataVersion::None),
    ///            ["foo".to_string(), "bar.json".to_string()]);
    /// assert_eq!(path.components::<JsonDataInterchange>(&MetadataVersion::Number(1)),
    ///            ["foo".to_string(), "1.bar.json".to_string()]);
    /// assert_eq!(path.components::<JsonDataInterchange>(
    ///                 &MetadataVersion::Hash(HashValue::new(vec![0x69, 0xb7, 0x1d]))),
    ///            ["foo".to_string(), "abcd.bar.json".to_string()]);
    /// ```
    pub fn components<D>(&self, version: &MetadataVersion) -> Vec<String>
    where
        D: DataInterchange,
    {
        let mut buf: Vec<String> = self.0.split('/').map(|s| s.to_string()).collect();
        let len = buf.len();
        buf[len - 1] = format!("{}{}.{}", version.prefix(), buf[len - 1], D::extension());
        buf
    }
}

impl ToString for MetadataPath {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for MetadataPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        MetadataPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Metadata for the timestamp role.
#[derive(Debug, PartialEq)]
pub struct TimestampMetadata {
    version: u32,
    expires: DateTime<Utc>,
    meta: HashMap<MetadataPath, MetadataDescription>,
}

impl TimestampMetadata {
    /// Create new `TimestampMetadata`.
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        meta: HashMap<MetadataPath, MetadataDescription>,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        Ok(TimestampMetadata {
            version: version,
            expires: expires,
            meta: meta,
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

    /// An immutable reference to the metadata paths and descriptions.
    pub fn meta(&self) -> &HashMap<MetadataPath, MetadataDescription> {
        &self.meta
    }
}

impl Metadata for TimestampMetadata {
    fn role() -> Role {
        Role::Timestamp
    }
}

impl Serialize for TimestampMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::TimestampMetadata::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for TimestampMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::TimestampMetadata = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

/// Description of a piece of metadata, used in verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetadataDescription {
    version: u32,
}

impl MetadataDescription {
    /// Create a new `MetadataDescription`.
    pub fn new(version: u32) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        Ok(MetadataDescription { version: version })
    }

    /// The version of the described metadata.
    pub fn version(&self) -> u32 {
        self.version
    }
}

/// Metadata for the snapshot role.
#[derive(Debug, PartialEq)]
pub struct SnapshotMetadata {
    version: u32,
    expires: DateTime<Utc>,
    meta: HashMap<MetadataPath, MetadataDescription>,
}

impl SnapshotMetadata {
    /// Create new `SnapshotMetadata`.
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        meta: HashMap<MetadataPath, MetadataDescription>,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        Ok(SnapshotMetadata {
            version: version,
            expires: expires,
            meta: meta,
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

    /// An immutable reference to the metadata paths and descriptions.
    pub fn meta(&self) -> &HashMap<MetadataPath, MetadataDescription> {
        &self.meta
    }
}

impl Metadata for SnapshotMetadata {
    fn role() -> Role {
        Role::Snapshot
    }
}

impl Serialize for SnapshotMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::SnapshotMetadata::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for SnapshotMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::SnapshotMetadata = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}


/// Wrapper for a path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct TargetPath(String);

impl TargetPath {
    /// Create a new `TargetPath` from a `String`.
    ///
    /// ```
    /// use tuf::metadata::TargetPath;
    ///
    /// assert!(TargetPath::new("foo".into()).is_ok());
    /// assert!(TargetPath::new("/foo".into()).is_err());
    /// assert!(TargetPath::new("../foo".into()).is_err());
    /// assert!(TargetPath::new("foo/".into()).is_err());
    /// assert!(TargetPath::new("foo/..".into()).is_err());
    /// assert!(TargetPath::new("foo/../bar".into()).is_err());
    /// assert!(TargetPath::new("..foo".into()).is_ok());
    /// assert!(TargetPath::new("foo//bar".into()).is_err());
    /// assert!(TargetPath::new("foo/..bar".into()).is_ok());
    /// assert!(TargetPath::new("foo/bar..".into()).is_ok());
    /// ```
    // TODO this needs to allow trailing slashes for delegations
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(TargetPath(path))
    }

    /// Split `TargetPath` into components that can be joined to create URL paths, Unix paths, or
    /// Windows paths.
    ///
    /// ```
    /// use tuf::metadata::TargetPath;
    ///
    /// let path = TargetPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components(), ["foo".to_string(), "bar".to_string()]);
    /// ```
    pub fn components(&self) -> Vec<String> {
        self.0.split('/').map(|s| s.to_string()).collect()
    }
}

impl ToString for TargetPath {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for TargetPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        TargetPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Description of a target, used in verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetDescription {
    length: u64,
    hashes: HashMap<HashAlgorithm, HashValue>,
}

impl TargetDescription {
    /// Read the from the given reader and calculate the length and hash values.
    ///
    /// ```
    /// extern crate data_encoding;
    /// extern crate tuf;
    /// use data_encoding::BASE64URL;
    /// use tuf::crypto::{HashAlgorithm,HashValue};
    /// use tuf::metadata::TargetDescription;
    ///
    /// fn main() {
    ///     let bytes: &[u8] = b"it was a pleasure to burn";
    ///     let target_description = TargetDescription::from_reader(bytes).unwrap();
    ///
    ///     // $ printf 'it was a pleasure to burn' | sha256sum
    ///     let s = "Rd9zlbzrdWfeL7gnIEi05X-Yv2TCpy4qqZM1N72ZWQs=";
    ///     let sha256 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     // $ printf 'it was a pleasure to burn' | sha512sum
    ///     let s ="tuIxwKybYdvJpWuUj6dubvpwhkAozWB6hMJIRzqn2jOUdtDTBg381brV4K\
    ///         BU1zKP8GShoJuXEtCf5NkDTCEJgQ==";
    ///     let sha512 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     assert_eq!(target_description.length(), bytes.len() as u64);
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha256), Some(&sha256));
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha512), Some(&sha512));
    /// }
    /// ```
    pub fn from_reader<R>(mut read: R) -> Result<Self>
    where
        R: Read,
    {
        let mut length = 0;
        let mut sha256 = digest::Context::new(&SHA256);
        let mut sha512 = digest::Context::new(&SHA512);

        let mut buf = vec![0; 1024];
        loop {
            match read.read(&mut buf) {
                Ok(read_bytes) => {
                    if read_bytes == 0 {
                        break;
                    }

                    length += read_bytes as u64;
                    sha256.update(&buf[0..read_bytes]);
                    sha512.update(&buf[0..read_bytes]);
                }
                e @ Err(_) => e.map(|_| ())?,
            }
        }

        let mut hashes = HashMap::new();
        let _ = hashes.insert(
            HashAlgorithm::Sha256,
            HashValue::new(sha256.finish().as_ref().to_vec()),
        );
        let _ = hashes.insert(
            HashAlgorithm::Sha512,
            HashValue::new(sha512.finish().as_ref().to_vec()),
        );
        Ok(TargetDescription {
            length: length,
            hashes: hashes,
        })
    }

    /// The maximum length of the target.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// An immutable reference to the list of calculated hashes.
    pub fn hashes(&self) -> &HashMap<HashAlgorithm, HashValue> {
        &self.hashes
    }
}

/// Metadata for the targets role.
#[derive(Debug, PartialEq)]
pub struct TargetsMetadata {
    version: u32,
    expires: DateTime<Utc>,
    targets: HashMap<TargetPath, TargetDescription>,
    delegations: Option<Delegations>,
}

impl TargetsMetadata {
    /// Create new `TargetsMetadata`.
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        targets: HashMap<TargetPath, TargetDescription>,
        delegations: Option<Delegations>,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        Ok(TargetsMetadata {
            version: version,
            expires: expires,
            targets: targets,
            delegations: delegations,
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

    /// An immutable reference to the descriptions of targets.
    pub fn targets(&self) -> &HashMap<TargetPath, TargetDescription> {
        &self.targets
    }

    /// An immutable reference to the optional delegations.
    pub fn delegations(&self) -> Option<&Delegations> {
        self.delegations.as_ref()
    }
}

impl Metadata for TargetsMetadata {
    fn role() -> Role {
        Role::Targets
    }
}

impl Serialize for TargetsMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::TargetsMetadata::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for TargetsMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::TargetsMetadata = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

/// Wrapper to described a collections of delegations.
// TODO custom deserialize to ensure no duplicates
#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct Delegations {
    keys: HashMap<KeyId, PublicKey>,
    roles: Vec<Delegation>,
}

impl Delegations {
    // TODO check all keys are used
    // TODO check all roles have their ID in the set of keys
    /// Create a new `Delegations` wrapper from the given set of trusted keys and roles.
    pub fn new(mut keys: Vec<PublicKey>, roles: Vec<Delegation>) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::IllegalArgument("Keys cannot be empty.".into()));
        }

        if roles.is_empty() {
            return Err(Error::IllegalArgument("Roles cannot be empty.".into()));
        }

        if roles.len() !=
            roles
                .iter()
                .map(|r| &r.role)
                .collect::<HashSet<&MetadataPath>>()
                .len()
        {
            return Err(Error::IllegalArgument(
                "Cannot have duplicated roles in delegations.".into(),
            ));
        }

        Ok(Delegations {
            keys: HashMap::from_iter(keys.drain(..).map(|k| (k.key_id().clone(), k))),
            roles: roles,
        })
    }

    /// An immutable reference to the keys used for this set of delegations.
    pub fn keys(&self) -> &HashMap<KeyId, PublicKey> {
        &self.keys
    }

    /// An immutable reference to the delegated roles.
    pub fn roles(&self) -> &Vec<Delegation> {
        &self.roles
    }
}

impl<'de> Deserialize<'de> for Delegations {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::Delegations = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

/// A delegated targets role.
// TODO custom deserialize to ensure good ordering
#[derive(Debug, PartialEq, Clone)]
pub struct Delegation {
    role: MetadataPath,
    key_ids: HashSet<KeyId>,
    threshold: u32,
    paths: HashSet<TargetPath>,
}

impl Delegation {
    /// Create a new delegation.
    pub fn new(
        role: MetadataPath,
        key_ids: HashSet<KeyId>,
        threshold: u32,
        paths: HashSet<TargetPath>,
    ) -> Result<Self> {
        if key_ids.is_empty() {
            return Err(Error::IllegalArgument("Cannot have empty key IDs".into()));
        }

        if paths.is_empty() {
            return Err(Error::IllegalArgument("Cannot have empty paths".into()));
        }

        if threshold < 1 {
            return Err(Error::IllegalArgument("Cannot have threshold < 1".into()));
        }

        Ok(Delegation {
            role: role,
            key_ids: key_ids,
            threshold: threshold,
            paths: paths,
        })
    }

    /// An immutable reference to the delegations's metadata path (role).
    pub fn role(&self) -> &MetadataPath {
        &self.role
    }

    /// An immutable reference to the delegations's trusted key IDs.
    pub fn key_ids(&self) -> &HashSet<KeyId> {
        &self.key_ids
    }

    /// The delegation's threshold.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// An immutable reference to the delegation's authorized paths.
    pub fn paths(&self) -> &HashSet<TargetPath> {
        &self.paths
    }
}

impl Serialize for Delegation {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::Delegation::from(self).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for Delegation {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::Delegation = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use json;
    use interchange::JsonDataInterchange;

    const ED25519_1_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    const ED25519_2_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
    const ED25519_3_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-3.pk8.der");
    const ED25519_4_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-4.pk8.der");

    #[test]
    fn serde_target_path() {
        let s = "foo/bar";
        let t = json::from_str::<TargetPath>(&format!("\"{}\"", s)).unwrap();
        assert_eq!(t.to_string().as_str(), s);
        assert_eq!(json::to_value(t).unwrap(), json!("foo/bar"));
    }

    #[test]
    fn serde_metadata_path() {
        let s = "foo/bar";
        let m = json::from_str::<MetadataPath>(&format!("\"{}\"", s)).unwrap();
        assert_eq!(m.to_string().as_str(), s);
        assert_eq!(json::to_value(m).unwrap(), json!("foo/bar"));
    }

    #[test]
    fn serde_target_description() {
        let s: &[u8] = b"from water does all life begin";
        let description = TargetDescription::from_reader(s).unwrap();
        let jsn_str = json::to_string(&description).unwrap();
        let jsn = json!({
            "length": 30,
            "hashes": {
                "sha256": "_F10XHEryG6poxJk2sDJVu61OFf2d-7QWCm7cQE8rhg=",
                "sha512": "593J2T34bimKdKT5MmaSZ0tXvmj13EVdpTGK5p2E2R3ife-xxZ8Ql\
                    EHsezz8HeN1_Y0SJqvLfK2WKUZQc98R_A==",
            },
        });
        let parsed_str: TargetDescription = json::from_str(&jsn_str).unwrap();
        let parsed_jsn: TargetDescription = json::from_value(jsn).unwrap();
        assert_eq!(parsed_str, parsed_jsn);
    }

    #[test]
    fn serde_role_definition() {
        let hashes = hashset!(
            "diNfThTFm0PI8R-Bq7NztUIvZbZiaC_weJBgcqaHlWw=",
            "ar9AgoRsmeEcf6Ponta_1TZu1ds5uXbDemBig30O7ck=",
        ).iter()
            .map(|k| KeyId::from_string(*k).unwrap())
            .collect();
        let role_def = RoleDefinition::new(2, hashes).unwrap();
        let jsn = json!({
            "threshold": 2,
            "key_ids": [
                // these need to be sorted for determinism
                "ar9AgoRsmeEcf6Ponta_1TZu1ds5uXbDemBig30O7ck=",
                "diNfThTFm0PI8R-Bq7NztUIvZbZiaC_weJBgcqaHlWw=",
            ],
        });
        let encoded = json::to_value(&role_def).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: RoleDefinition = json::from_value(encoded).unwrap();
        assert_eq!(decoded, role_def);

        let jsn = json!({
            "threshold": 0,
            "key_ids": [
                "diNfThTFm0PI8R-Bq7NztUIvZbZiaC_weJBgcqaHlWw=",
            ],
        });
        assert!(json::from_value::<RoleDefinition>(jsn).is_err());

        let jsn = json!({
            "threshold": -1,
            "key_ids": [
                "diNfThTFm0PI8R-Bq7NztUIvZbZiaC_weJBgcqaHlWw=",
            ],
        });
        assert!(json::from_value::<RoleDefinition>(jsn).is_err());
    }

    #[test]
    fn serde_root_metadata() {
        let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
        let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8).unwrap();
        let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8).unwrap();
        let timestamp_key = PrivateKey::from_pkcs8(ED25519_4_PK8).unwrap();

        let keys = vec![
            root_key.public().clone(),
            snapshot_key.public().clone(),
            targets_key.public().clone(),
            timestamp_key.public().clone(),
        ];

        let root_def = RoleDefinition::new(1, hashset!(root_key.key_id().clone())).unwrap();
        let snapshot_def = RoleDefinition::new(1, hashset!(snapshot_key.key_id().clone())).unwrap();
        let targets_def = RoleDefinition::new(1, hashset!(targets_key.key_id().clone())).unwrap();
        let timestamp_def = RoleDefinition::new(1, hashset!(timestamp_key.key_id().clone()))
            .unwrap();

        let root = RootMetadata::new(
            1,
            Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
            false,
            keys,
            root_def,
            snapshot_def,
            targets_def,
            timestamp_def,
        ).unwrap();

        let jsn = json!({
            "type": "root",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "consistent_snapshot": false,
            "keys": {
                "qfrfBrkB4lBBSDEBlZgaTGS_SrE6UfmON9kP4i3dJFY=": {
                    "type": "ed25519",
                    "public_key": "MCwwBwYDK2VwBQADIQDrisJrXJ7wJ5474-giYqk7zhb\
                        -WO5CJQDTjK9GHGWjtg==",
                },
                "4hsyITLMQoWBg0ldCLKPlRZPIEf258cMg-xdAROsO6o=": {
                    "type": "ed25519",
                    "public_key": "MCwwBwYDK2VwBQADIQAWY3bJCn9xfQJwVicvNhwlL7BQ\
                        vtGgZ_8giaAwL7q3PQ==",
                },
                "5WvZhiiSSUung_OhJVbPshKwD_ZNkgeg80i4oy2KAVs=": {
                    "type": "ed25519",
                    "public_key": "MCwwBwYDK2VwBQADIQBo2eyzhzcQBajrjmAQUwXDQ1ao_\
                        NhZ1_7zzCKL8rKzsg==",
                },
                "C2hNB7qN99EAbHVGHPIJc5Hqa9RfEilnMqsCNJ5dGdw=": {
                    "type": "ed25519",
                    "public_key": "MCwwBwYDK2VwBQADIQAUEK4wU6pwu_qYQoqHnWTTACo1\
                        ePffquscsHZOhg9-Cw==",
                },
            },
            "roles": {
                "root": {
                    "threshold": 1,
                    "key_ids": ["qfrfBrkB4lBBSDEBlZgaTGS_SrE6UfmON9kP4i3dJFY="],
                },
                "snapshot": {
                    "threshold": 1,
                    "key_ids": ["5WvZhiiSSUung_OhJVbPshKwD_ZNkgeg80i4oy2KAVs="],
                },
                "targets": {
                    "threshold": 1,
                    "key_ids": ["4hsyITLMQoWBg0ldCLKPlRZPIEf258cMg-xdAROsO6o="],
                },
                "timestamp": {
                    "threshold": 1,
                    "key_ids": ["C2hNB7qN99EAbHVGHPIJc5Hqa9RfEilnMqsCNJ5dGdw="],
                },
            },
        });

        let encoded = json::to_value(&root).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: RootMetadata = json::from_value(encoded).unwrap();
        assert_eq!(decoded, root);
    }

    #[test]
    fn serde_timestamp_metadata() {
        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
            hashmap!{
                MetadataPath::new("foo".into()).unwrap() => MetadataDescription::new(1).unwrap(),
            },
        ).unwrap();

        let jsn = json!({
            "type": "timestamp",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "meta": {
                "foo": {
                    "version": 1,
                },
            },
        });

        let encoded = json::to_value(&timestamp).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: TimestampMetadata = json::from_value(encoded).unwrap();
        assert_eq!(decoded, timestamp);
    }

    #[test]
    fn serde_snapshot_metadata() {
        let snapshot = SnapshotMetadata::new(
            1,
            Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
            hashmap! {
                MetadataPath::new("foo".into()).unwrap() => MetadataDescription::new(1).unwrap(),
            },
        ).unwrap();

        let jsn = json!({
            "type": "snapshot",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "meta": {
                "foo": {
                    "version": 1,
                },
            },
        });

        let encoded = json::to_value(&snapshot).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: SnapshotMetadata = json::from_value(encoded).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn serde_targets_metadata() {
        let targets = TargetsMetadata::new(
            1,
            Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
            hashmap! {
                TargetPath::new("foo".into()).unwrap() =>
                    TargetDescription::from_reader(b"foo" as &[u8]).unwrap(),
            },
            None,
        ).unwrap();

        let jsn = json!({
            "type": "targets",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "targets": {
                "foo": {
                    "length": 3,
                    "hashes": {
                        "sha256": "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564=",
                        "sha512": "9_u6bgY2-JDlb7vzKD5STG-jIErimDgtYkdB0NxmODJuKCx\
                            Bvl5CVNiCB3LFUYosWowMf37aGVlKfrU5RT4e1w==",
                    },
                },
            },
        });

        let encoded = json::to_value(&targets).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: TargetsMetadata = json::from_value(encoded).unwrap();
        assert_eq!(decoded, targets);
    }

    #[test]
    fn serde_targets_with_delegations_metadata() {
        let key = PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
        let delegations = Delegations::new(
            vec![key.public().clone()],
            vec![Delegation::new(
                MetadataPath::new("foo/bar".into()).unwrap(),
                hashset!(key.key_id().clone()),
                1,
                hashset!(TargetPath::new("baz/quux".into()).unwrap()),
            ).unwrap()],
        ).unwrap();

        let targets = TargetsMetadata::new(
            1,
            Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
            HashMap::new(),
            Some(delegations),
        ).unwrap();

        let jsn = json!({
            "type": "targets",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "targets": {},
            "delegations": {
                "keys": {
                    "qfrfBrkB4lBBSDEBlZgaTGS_SrE6UfmON9kP4i3dJFY=": {
                        "type": "ed25519",
                        "public_key": "MCwwBwYDK2VwBQADIQDrisJrXJ7wJ5474-giYqk7zhb\
                            -WO5CJQDTjK9GHGWjtg==",
                    },
                },
                "roles": [
                    {
                        "role": "foo/bar",
                        "threshold": 1,
                        "key_ids": ["qfrfBrkB4lBBSDEBlZgaTGS_SrE6UfmON9kP4i3dJFY="],
                        "paths": ["baz/quux"],
                    },
                ],
            }
        });

        let encoded = json::to_value(&targets).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: TargetsMetadata = json::from_value(encoded).unwrap();
        assert_eq!(decoded, targets);
    }

    #[test]
    fn serde_signed_metadata() {
        let snapshot = SnapshotMetadata::new(
            1,
            Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
            hashmap! {
                MetadataPath::new("foo".into()).unwrap() =>
                    MetadataDescription::new(1).unwrap(),
            },
        ).unwrap();

        let key = PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();

        let signed = SignedMetadata::<JsonDataInterchange, SnapshotMetadata>::new(
            &snapshot,
            &key,
            SignatureScheme::Ed25519,
        ).unwrap();

        let jsn = json!({
            "signatures": [
                {
                    "key_id": "qfrfBrkB4lBBSDEBlZgaTGS_SrE6UfmON9kP4i3dJFY=",
                    "scheme": "ed25519",
                    "value": "T2cUdVcGn08q9Cl4sKXqQni4J63TxZ48wR3jt583QuWXJ2AmxRHwEnW\
                        IHtkCOmzohF4D0v9JspeH6samO-H6CA==",
                }
            ],
            "signed": {
                "type": "snapshot",
                "version": 1,
                "expires": "2017-01-01T00:00:00Z",
                "meta": {
                    "foo": {
                        "version": 1,
                    },
                },
            },
        });

        let encoded = json::to_value(&signed).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: SignedMetadata<JsonDataInterchange, SnapshotMetadata> =
            json::from_value(encoded).unwrap();
        assert_eq!(decoded, signed);
    }
}
