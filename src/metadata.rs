//! Structures used to represent TUF metadata

use chrono::DateTime;
use chrono::offset::Utc;
use ring::digest::{self, SHA256, SHA512};
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, Error as SerializeError};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Display};
use std::io::Read;
use std::marker::PhantomData;

use Result;
use crypto::{KeyId, PublicKey, Signature, HashAlgorithm, HashValue};
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
        return Err(Error::IllegalArgument("Cannot start with '/'".into()))
    }

    for bad_str in PATH_ILLEGAL_STRINGS {
        if path.contains(bad_str) {
            return Err(Error::IllegalArgument(format!("Path cannot contain {:?}", bad_str)))
        }
    }

    for component in path.split('/') {
        for bad_str in PATH_ILLEGAL_COMPONENTS {
            if component == *bad_str {
                return Err(Error::IllegalArgument(format!("Path cannot have component {:?}", component)))
            }
        }

        let component_lower = component.to_lowercase();
        for bad_str in PATH_ILLEGAL_COMPONENTS_CASE_INSENSITIVE {
            if component_lower.as_str() == *bad_str {
                return Err(Error::IllegalArgument(format!("Path cannot have component {:?}", component)))
            }
        }
    }

    Ok(())
}

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
            _ => false 
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
    /// **WARNING**: This data is untrusted.
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
    /// assert_eq!(path.components::<JsonDataInterchange>(&MetadataVersion::Hash(HashValue::from_hex("abcd").unwrap())),
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

impl<'de> Deserialize<'de> for MetadataPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        MetadataPath::new(s).map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
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
    length: Option<usize>,
    hashes: Option<HashMap<HashAlgorithm, HashValue>>,
}

impl MetadataDescription {
    /// Create a new `MetadataDescription`.
    pub fn new(
        version: u32,
        length: Option<usize>,
        hashes: Option<HashMap<HashAlgorithm, HashValue>>,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        Ok(MetadataDescription {
            version: version,
            length: length,
            hashes: hashes,
        })
    }

    /// The version of the described metadata.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The optional length of the described metadata.
    pub fn length(&self) -> Option<usize> {
        self.length
    }

    /// An immutable reference to the optional calculated hashes of the described metadata.
    pub fn hashes(&self) -> Option<&HashMap<HashAlgorithm, HashValue>> {
        self.hashes.as_ref()
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
#[derive(Debug, Clone, PartialEq, Hash, Eq, Serialize)]
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

impl<'de> Deserialize<'de> for TargetPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        TargetPath::new(s).map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
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
    /// use tuf::crypto::{HashAlgorithm,HashValue};
    /// use tuf::metadata::TargetDescription;
    ///
    /// let bytes: &[u8] = b"it was a pleasure to burn";
    /// let target_description = TargetDescription::from_reader(bytes).unwrap();
    ///
    /// // $ printf 'it was a pleasure to burn' | sha256sum
    /// let sha256 = HashValue::from_hex("45df7395bceb7567de2fb8272048b4e57f98bf64c2a72e2aa9933537bd99590b").unwrap();
    /// // $ printf 'it was a pleasure to burn' | sha512sum
    /// let sha512 = HashValue::from_hex("b6e231c0ac9b61dbc9a56b948fa76e6efa70864028cd607a84c248473aa7da339476d0d3060dfcd5bad5e0a054d7328ff064a1a09b9712d09fe4d9034c210981").unwrap();
    ///
    /// assert_eq!(target_description.length(), bytes.len() as u64);
    /// assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha256), Some(&sha256));
    /// assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha512), Some(&sha512));
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
        let _ = hashes.insert(HashAlgorithm::Sha256, HashValue::new(sha256.finish().as_ref().to_vec()));
        let _ = hashes.insert(HashAlgorithm::Sha512, HashValue::new(sha512.finish().as_ref().to_vec()));
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
}

impl TargetsMetadata {
    /// Create new `TargetsMetadata`.
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        targets: HashMap<TargetPath, TargetDescription>,
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

    /// An immutable reference descriptions of targets.
    pub fn targets(&self) -> &HashMap<TargetPath, TargetDescription> {
        &self.targets
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
