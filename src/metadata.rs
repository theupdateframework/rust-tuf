//! TUF metadata.

use chrono::DateTime;
use chrono::offset::Utc;
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, Error as SerializeError};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Display};
use std::io::Read;
use std::iter::FromIterator;
use std::marker::PhantomData;

use Result;
use crypto::{self, KeyId, PublicKey, Signature, HashAlgorithm, HashValue, PrivateKey};
use error::Error;
use interchange::DataInterchange;
use shims;

static PATH_ILLEGAL_COMPONENTS: &'static [&str] = &[
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
    if path.is_empty() {
        return Err(Error::IllegalArgument("Path cannot be empty".into()));
    }

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
            &Role::Targets if !&["root", "snapshot", "targets"].contains(&path.0.as_str()) => true,
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
    /// The metadata is unversioned. This is the latest version of the metadata.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    metadata: PhantomData<M>,
}

impl<D, M> SignedMetadata<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    /// Create a new `SignedMetadata`. The supplied private key is used to sign the canonicalized
    /// bytes of the provided metadata with the provided scheme.
    ///
    /// ```
    /// # extern crate chrono;
    /// # extern crate tuf;
    /// #
    /// # use chrono::prelude::*;
    /// # use tuf::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    /// # use tuf::interchange::Json;
    /// # use tuf::metadata::{MetadataDescription, TimestampMetadata, SignedMetadata};
    /// #
    /// # fn main() {
    /// # let key: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    /// let key = PrivateKey::from_pkcs8(&key, SignatureScheme::Ed25519).unwrap();
    ///
    /// let timestamp = TimestampMetadata::new(
    ///     1,
    ///     Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
    ///     MetadataDescription::from_reader(&*vec![0x01, 0x02, 0x03], 1,
    ///         &[HashAlgorithm::Sha256]).unwrap()
    /// ).unwrap();
    ///
    /// SignedMetadata::<Json, TimestampMetadata>::new(&timestamp, &key).unwrap();
    /// # }
    /// ```
    pub fn new(metadata: &M, private_key: &PrivateKey) -> Result<SignedMetadata<D, M>> {
        let raw = D::serialize(metadata)?;
        let bytes = D::canonicalize(&raw)?;
        let sig = private_key.sign(&bytes)?;
        Ok(SignedMetadata {
            signatures: vec![sig],
            signed: raw,
            _interchage: PhantomData,
            metadata: PhantomData,
        })
    }

    /// Append a signature to this signed metadata. Will overwrite signature by keys with the same
    /// ID.
    ///
    /// **WARNING**: You should never have multiple TUF private keys on the same machine, so if
    /// you're using this to append several signatures are once, you are doing something wrong. The
    /// preferred method is to generate your copy of the metadata locally and use `merge_signatures`
    /// to perform the "append" operations.
    ///
    /// ```
    /// # extern crate chrono;
    /// # extern crate tuf;
    /// #
    /// # use chrono::prelude::*;
    /// # use tuf::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    /// # use tuf::interchange::Json;
    /// # use tuf::metadata::{MetadataDescription, TimestampMetadata, SignedMetadata};
    /// #
    /// # fn main() {
    /// let key_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    /// let key_1 = PrivateKey::from_pkcs8(&key_1, SignatureScheme::Ed25519).unwrap();
    ///
    /// // Note: This is for demonstration purposes only.
    /// // You should never have multiple private keys on the same device.
    /// let key_2: &[u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
    /// let key_2 = PrivateKey::from_pkcs8(&key_2, SignatureScheme::Ed25519).unwrap();
    ///
    /// let timestamp = TimestampMetadata::new(
    ///     1,
    ///     Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
    ///     MetadataDescription::from_reader(&*vec![0x01, 0x02, 0x03], 1,
    ///         &[HashAlgorithm::Sha256]).unwrap()
    /// ).unwrap();
    /// let mut timestamp = SignedMetadata::<Json, TimestampMetadata>::new(
    ///     &timestamp, &key_1).unwrap();
    ///
    /// timestamp.add_signature(&key_2).unwrap();
    /// assert_eq!(timestamp.signatures().len(), 2);
    ///
    /// timestamp.add_signature(&key_2).unwrap();
    /// assert_eq!(timestamp.signatures().len(), 2);
    /// # }
    /// ```
    pub fn add_signature(&mut self, private_key: &PrivateKey) -> Result<()> {
        let raw = D::serialize(&self.signed)?;
        let bytes = D::canonicalize(&raw)?;
        let sig = private_key.sign(&bytes)?;
        self.signatures.retain(
            |s| s.key_id() != private_key.key_id(),
        );
        self.signatures.push(sig);
        Ok(())
    }

    /// Merge the singatures from `other` into `self` if and only if
    /// `self.signed() == other.signed()`. If `self` and `other` contain signatures from the same
    /// key ID, then the signatures from `self` will replace the signatures from `other`.
    pub fn merge_signatures(&mut self, other: &Self) -> Result<()> {
        if self.signed() != other.signed() {
            return Err(Error::IllegalArgument(
                "Attempted to merge unequal metadata".into(),
            ));
        }

        let key_ids = self.signatures
            .iter()
            .map(|s| s.key_id().clone())
            .collect::<HashSet<KeyId>>();

        self.signatures.extend(
            other
                .signatures
                .iter()
                .filter(|s| !key_ids.contains(s.key_id()))
                .cloned(),
        );

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
    ///
    /// ```
    /// # extern crate chrono;
    /// # #[macro_use]
    /// # extern crate maplit;
    /// # extern crate tuf;
    ///
    /// # use chrono::prelude::*;
    /// # use tuf::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    /// # use tuf::interchange::Json;
    /// # use tuf::metadata::{MetadataDescription, TimestampMetadata, SignedMetadata};
    ///
    /// # fn main() {
    /// let key_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    /// let key_1 = PrivateKey::from_pkcs8(&key_1, SignatureScheme::Ed25519).unwrap();
    ///
    /// let key_2: &[u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
    /// let key_2 = PrivateKey::from_pkcs8(&key_2, SignatureScheme::Ed25519).unwrap();
    ///
    /// let timestamp = TimestampMetadata::new(
    ///     1,
    ///     Utc.ymd(2017, 1, 1).and_hms(0, 0, 0),
    ///     MetadataDescription::from_reader(&*vec![0x01, 0x02, 0x03], 1,
    ///         &[HashAlgorithm::Sha256]).unwrap()
    /// ).unwrap();
    /// let timestamp = SignedMetadata::<Json, TimestampMetadata>::new(
    ///     &timestamp, &key_1).unwrap();
    ///
    /// assert!(timestamp.verify(
    ///     1,
    ///     vec![key_1.public()],
    /// ).is_ok());
    ///
    /// // fail with increased threshold
    /// assert!(timestamp.verify(
    ///     2,
    ///     vec![key_1.public()],
    /// ).is_err());
    ///
    /// // fail when the keys aren't authorized
    /// assert!(timestamp.verify(
    ///     1,
    ///     vec![key_2.public()],
    /// ).is_err());
    ///
    /// // fail when the keys don't exist
    /// assert!(timestamp.verify(
    ///     1,
    ///     &[],
    /// ).is_err());
    /// # }
    pub fn verify<'a, I>(&self, threshold: u32, authorized_keys: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
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

        let authorized_keys = authorized_keys
            .into_iter()
            .map(|k| (k.key_id(), k))
            .collect::<HashMap<&KeyId, &PublicKey>>();

        let canonical_bytes = D::canonicalize(&self.signed)?;

        let mut signatures_needed = threshold;
        for sig in self.signatures.iter() {
            match authorized_keys.get(sig.key_id()) {
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
                        "Key ID {:?} was not found in the set of authorized keys.",
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
#[derive(Debug, Clone, PartialEq)]
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

        let keys_len = keys.len();
        let keys = HashMap::from_iter(keys.drain(..).map(|k| (k.key_id().clone(), k)));

        if keys.len() != keys_len {
            return Err(Error::IllegalArgument("Cannot have duplicate keys".into()));
        }

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

/// Wrapper for a path to metadata.
///
/// Note: This should **not** contain the file extension. This is automatically added by the
/// library depending on what type of data interchange format is being used.
///
/// ```
/// use tuf::metadata::MetadataPath;
///
/// // right
/// let _ = MetadataPath::new("root".into());
///
/// // wrong
/// let _ = MetadataPath::new("root.json".into());
/// ```
#[derive(Debug, Clone, PartialEq, Hash, Eq, Serialize)]
pub struct MetadataPath(String);

impl MetadataPath {
    /// Create a new `MetadataPath` from a `String`.
    ///
    /// ```
    /// # use tuf::metadata::MetadataPath;
    /// assert!(MetadataPath::new("foo".into()).is_ok());
    /// assert!(MetadataPath::new("/foo".into()).is_err());
    /// assert!(MetadataPath::new("../foo".into()).is_err());
    /// assert!(MetadataPath::new("foo/..".into()).is_err());
    /// assert!(MetadataPath::new("foo/../bar".into()).is_err());
    /// assert!(MetadataPath::new("..foo".into()).is_ok());
    /// assert!(MetadataPath::new("foo/..bar".into()).is_ok());
    /// assert!(MetadataPath::new("foo/bar..".into()).is_ok());
    /// ```
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(MetadataPath(path))
    }

    /// Create a metadata path from the given role.
    ///
    /// ```
    /// # use tuf::metadata::{Role, MetadataPath};
    /// assert_eq!(MetadataPath::from_role(&Role::Root),
    ///            MetadataPath::new("root".into()).unwrap());
    /// assert_eq!(MetadataPath::from_role(&Role::Snapshot),
    ///            MetadataPath::new("snapshot".into()).unwrap());
    /// assert_eq!(MetadataPath::from_role(&Role::Targets),
    ///            MetadataPath::new("targets".into()).unwrap());
    /// assert_eq!(MetadataPath::from_role(&Role::Timestamp),
    ///            MetadataPath::new("timestamp".into()).unwrap());
    /// ```
    pub fn from_role(role: &Role) -> Self {
        Self::new(format!("{}", role)).unwrap()
    }

    /// Split `MetadataPath` into components that can be joined to create URL paths, Unix paths, or
    /// Windows paths.
    ///
    /// ```
    /// # use tuf::crypto::HashValue;
    /// # use tuf::interchange::Json;
    /// # use tuf::metadata::{MetadataPath, MetadataVersion};
    /// #
    /// let path = MetadataPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components::<Json>(&MetadataVersion::None),
    ///            ["foo".to_string(), "bar.json".to_string()]);
    /// assert_eq!(path.components::<Json>(&MetadataVersion::Number(1)),
    ///            ["foo".to_string(), "1.bar.json".to_string()]);
    /// assert_eq!(path.components::<Json>(
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
#[derive(Debug, Clone, PartialEq)]
pub struct TimestampMetadata {
    version: u32,
    expires: DateTime<Utc>,
    snapshot: MetadataDescription,
}

impl TimestampMetadata {
    /// Create new `TimestampMetadata`.
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        snapshot: MetadataDescription,
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
            snapshot: snapshot,
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

    /// An immutable reference to the snapshot description.
    pub fn snapshot(&self) -> &MetadataDescription {
        &self.snapshot
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
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetadataDescription {
    version: u32,
    size: usize,
    hashes: HashMap<HashAlgorithm, HashValue>,
}

impl MetadataDescription {
    /// Create a `MetadataDescription` from a given reader. Size and hashes will be calculated.
    pub fn from_reader<R: Read>(
        read: R,
        version: u32,
        hash_algs: &[HashAlgorithm],
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(
                "Version must be greater than zero".into(),
            ));
        }

        let (size, hashes) = crypto::calculate_hashes(read, hash_algs)?;

        if size > ::std::usize::MAX as u64 {
            return Err(Error::IllegalArgument(
                "Calculated size exceeded usize".into(),
            ));
        }

        Ok(MetadataDescription {
            version: version,
            size: size as usize,
            hashes: hashes,
        })
    }

    /// Create a new `MetadataDescription`.
    pub fn new(
        version: u32,
        size: usize,
        hashes: HashMap<HashAlgorithm, HashValue>,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        if hashes.is_empty() {
            return Err(Error::IllegalArgument(
                "Cannot have empty set of hashes".into(),
            ));
        }

        Ok(MetadataDescription {
            version: version,
            size: size,
            hashes: hashes,
        })
    }

    /// The version of the described metadata.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The size of the described metadata.
    pub fn size(&self) -> usize {
        self.size
    }

    /// An immutable reference to the hashes of the described metadata.
    pub fn hashes(&self) -> &HashMap<HashAlgorithm, HashValue> {
        &self.hashes
    }
}

impl<'de> Deserialize<'de> for MetadataDescription {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::MetadataDescription = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

/// Metadata for the snapshot role.
#[derive(Debug, Clone, PartialEq)]
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


/// Wrapper for the virtual path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct VirtualTargetPath(String);

impl VirtualTargetPath {
    /// Create a new `VirtualTargetPath` from a `String`.
    ///
    /// ```
    /// # use tuf::metadata::VirtualTargetPath;
    /// assert!(VirtualTargetPath::new("foo".into()).is_ok());
    /// assert!(VirtualTargetPath::new("/foo".into()).is_err());
    /// assert!(VirtualTargetPath::new("../foo".into()).is_err());
    /// assert!(VirtualTargetPath::new("foo/..".into()).is_err());
    /// assert!(VirtualTargetPath::new("foo/../bar".into()).is_err());
    /// assert!(VirtualTargetPath::new("..foo".into()).is_ok());
    /// assert!(VirtualTargetPath::new("foo/..bar".into()).is_ok());
    /// assert!(VirtualTargetPath::new("foo/bar..".into()).is_ok());
    /// ```
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(VirtualTargetPath(path))
    }

    /// Split `VirtualTargetPath` into components that can be joined to create URL paths, Unix
    /// paths, or Windows paths.
    ///
    /// ```
    /// # use tuf::metadata::VirtualTargetPath;
    /// let path = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components(), ["foo".to_string(), "bar".to_string()]);
    /// ```
    pub fn components(&self) -> Vec<String> {
        self.0.split('/').map(|s| s.to_string()).collect()
    }

    /// Return whether this path is the child of another path.
    ///
    /// ```
    /// # use tuf::metadata::VirtualTargetPath;
    /// let path1 = VirtualTargetPath::new("foo".into()).unwrap();
    /// let path2 = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert!(!path2.is_child(&path1));
    ///
    /// let path1 = VirtualTargetPath::new("foo/".into()).unwrap();
    /// let path2 = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert!(path2.is_child(&path1));
    ///
    /// let path2 = VirtualTargetPath::new("foo/bar/baz".into()).unwrap();
    /// assert!(path2.is_child(&path1));
    ///
    /// let path2 = VirtualTargetPath::new("wat".into()).unwrap();
    /// assert!(!path2.is_child(&path1))
    /// ```
    pub fn is_child(&self, parent: &Self) -> bool {
        if !parent.0.ends_with('/') {
            return false;
        }

        self.0.starts_with(&parent.0)
    }

    /// Whether or not the current target is available at the end of the given chain of target
    /// paths. For the chain to be valid, each target path in a group must be a child of of all
    /// previous groups.
    // TODO this is hideous and uses way too much clone/heap but I think recursively,
    // so here we are
    pub fn matches_chain(&self, parents: &[HashSet<VirtualTargetPath>]) -> bool {
        if parents.is_empty() {
            return false;
        }
        if parents.len() == 1 {
            return parents[0].iter().any(|p| p == self || self.is_child(p));
        }

        let new = parents[1..]
            .iter()
            .map(|group| {
                group
                    .iter()
                    .filter(|parent| {
                        parents[0].iter().any(
                            |p| parent.is_child(p) || parent == &p,
                        )
                    })
                    .cloned()
                    .collect::<HashSet<_>>()
            })
            .collect::<Vec<_>>();
        self.matches_chain(&*new)
    }

    /// The string value of the path.
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl ToString for VirtualTargetPath {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for VirtualTargetPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        VirtualTargetPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Wrapper for the real path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct TargetPath(String);

impl TargetPath {
    /// Create a new `TargetPath`.
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(TargetPath(path))
    }

    /// Split `TargetPath` into components that can be joined to create URL paths, Unix paths, or
    /// Windows paths.
    ///
    /// ```
    /// # use tuf::metadata::TargetPath;
    /// let path = TargetPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components(), ["foo".to_string(), "bar".to_string()]);
    /// ```
    pub fn components(&self) -> Vec<String> {
        self.0.split('/').map(|s| s.to_string()).collect()
    }

    /// The string value of the path.
    pub fn value(&self) -> &str {
        &self.0
    }
}

/// Description of a target, used in verification.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TargetDescription {
    size: u64,
    hashes: HashMap<HashAlgorithm, HashValue>,
}

impl TargetDescription {
    /// Create a new `TargetDescription`.
    ///
    /// Note: Creating this manually could lead to errors, and the `from_reader` method is
    /// preferred.
    pub fn new(size: u64, hashes: HashMap<HashAlgorithm, HashValue>) -> Result<Self> {
        if hashes.is_empty() {
            return Err(Error::IllegalArgument(
                "Cannot have empty set of hashes".into(),
            ));
        }

        Ok(TargetDescription {
            size: size,
            hashes: hashes,
        })
    }

    /// Read the from the given reader and calculate the size and hash values.
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
    ///
    ///     let s = "Rd9zlbzrdWfeL7gnIEi05X-Yv2TCpy4qqZM1N72ZWQs=";
    ///     let sha256 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     let target_description =
    ///         TargetDescription::from_reader(bytes, &[HashAlgorithm::Sha256]).unwrap();
    ///     assert_eq!(target_description.size(), bytes.len() as u64);
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha256), Some(&sha256));
    ///
    ///     let s ="tuIxwKybYdvJpWuUj6dubvpwhkAozWB6hMJIRzqn2jOUdtDTBg381brV4K\
    ///         BU1zKP8GShoJuXEtCf5NkDTCEJgQ==";
    ///     let sha512 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     let target_description =
    ///         TargetDescription::from_reader(bytes, &[HashAlgorithm::Sha512]).unwrap();
    ///     assert_eq!(target_description.size(), bytes.len() as u64);
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha512), Some(&sha512));
    /// }
    /// ```
    pub fn from_reader<R>(read: R, hash_algs: &[HashAlgorithm]) -> Result<Self>
    where
        R: Read,
    {
        let (size, hashes) = crypto::calculate_hashes(read, hash_algs)?;
        Ok(TargetDescription {
            size: size,
            hashes: hashes,
        })
    }

    /// The maximum size of the target.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// An immutable reference to the list of calculated hashes.
    pub fn hashes(&self) -> &HashMap<HashAlgorithm, HashValue> {
        &self.hashes
    }
}

impl<'de> Deserialize<'de> for TargetDescription {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::TargetDescription = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

/// Metadata for the targets role.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetsMetadata {
    version: u32,
    expires: DateTime<Utc>,
    targets: HashMap<VirtualTargetPath, TargetDescription>,
    delegations: Option<Delegations>,
}

impl TargetsMetadata {
    /// Create new `TargetsMetadata`.
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        targets: HashMap<VirtualTargetPath, TargetDescription>,
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
    pub fn targets(&self) -> &HashMap<VirtualTargetPath, TargetDescription> {
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
#[derive(Debug, PartialEq, Clone)]
pub struct Delegations {
    keys: HashMap<KeyId, PublicKey>,
    roles: Vec<Delegation>,
}

impl Delegations {
    // TODO check all keys are used
    // TODO check all roles have their ID in the set of keys
    /// Create a new `Delegations` wrapper from the given set of trusted keys and roles.
    pub fn new(keys: &HashSet<PublicKey>, roles: Vec<Delegation>) -> Result<Self> {
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
            keys: keys.iter()
                .cloned()
                .map(|k| (k.key_id().clone(), k))
                .collect(),
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

impl Serialize for Delegations {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::Delegations::from(self).serialize(ser)
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
#[derive(Debug, PartialEq, Clone)]
pub struct Delegation {
    role: MetadataPath,
    terminating: bool,
    threshold: u32,
    key_ids: HashSet<KeyId>,
    paths: HashSet<VirtualTargetPath>,
}

impl Delegation {
    /// Create a new delegation.
    pub fn new(
        role: MetadataPath,
        terminating: bool,
        threshold: u32,
        key_ids: HashSet<KeyId>,
        paths: HashSet<VirtualTargetPath>,
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

        if (key_ids.len() as u64) < (threshold as u64) {
            return Err(Error::IllegalArgument(
                "Cannot have threshold less than number of keys".into(),
            ));
        }

        Ok(Delegation {
            role: role,
            terminating: terminating,
            threshold: threshold,
            key_ids: key_ids,
            paths: paths,
        })
    }

    /// An immutable reference to the delegations's metadata path (role).
    pub fn role(&self) -> &MetadataPath {
        &self.role
    }

    /// Whether or not this delegation is terminating.
    pub fn terminating(&self) -> bool {
        self.terminating
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
    pub fn paths(&self) -> &HashSet<VirtualTargetPath> {
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
    use crypto::SignatureScheme;
    use interchange::Json;

    const ED25519_1_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    const ED25519_2_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
    const ED25519_3_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-3.pk8.der");
    const ED25519_4_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-4.pk8.der");

    #[test]
    fn path_matches_chain() {
        let test_cases: &[(bool, &str, &[&[&str]])] =
            &[
                // simplest case
                (true, "foo", &[&["foo"]]),
                // direct delegation case
                (true, "foo", &[&["foo"], &["foo"]]),
                // is a dir
                (false, "foo", &[&["foo/"]]),
                // target not in last position
                (false, "foo", &[&["foo"], &["bar"]]),
                // target nested
                (true, "foo/bar", &[&["foo/"], &["foo/bar"]]),
                // target illegally nested
                (false, "foo/bar", &[&["baz/"], &["foo/bar"]]),
                // target illegally deeply nested
                (
                    false,
                    "foo/bar/baz",
                    &[&["foo/"], &["foo/quux/"], &["foo/bar/baz"]],
                ),
                // empty
                (false, "foo", &[&[]]),
                // empty 2
                (false, "foo", &[&[], &["foo"]]),
                // empty 3
                (false, "foo", &[&["foo"], &[]]),
            ];

        for case in test_cases {
            let expected = case.0;
            let target = VirtualTargetPath::new(case.1.into()).unwrap();
            let parents = case.2
                .iter()
                .map(|group| {
                    group
                        .iter()
                        .map(|p| VirtualTargetPath::new(p.to_string()).unwrap())
                        .collect::<HashSet<_>>()
                })
                .collect::<Vec<_>>();
            println!(
                "CASE: expect: {} path: {:?} parents: {:?}",
                expected,
                target,
                parents
            );
            assert_eq!(target.matches_chain(&parents), expected);
        }
    }

    #[test]
    fn serde_target_path() {
        let s = "foo/bar";
        let t = json::from_str::<VirtualTargetPath>(&format!("\"{}\"", s)).unwrap();
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
        let description = TargetDescription::from_reader(s, &[HashAlgorithm::Sha256]).unwrap();
        let jsn_str = json::to_string(&description).unwrap();
        let jsn = json!({
            "size": 30,
            "hashes": {
                "sha256": "_F10XHEryG6poxJk2sDJVu61OFf2d-7QWCm7cQE8rhg=",
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
        let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519).unwrap();
        let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519).unwrap();
        let timestamp_key = PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519)
            .unwrap();

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
            "keys": [
                {
                    "type": "ed25519",
                    "scheme": "ed25519",
                    "public_key": "MCwwBwYDK2VwBQADIQAUEK4wU6pwu_qYQoqHnWTTACo1\
                        ePffquscsHZOhg9-Cw==",
                },
                {
                    "type": "ed25519",
                    "scheme": "ed25519",
                    "public_key": "MCwwBwYDK2VwBQADIQDrisJrXJ7wJ5474-giYqk7zhb\
                        -WO5CJQDTjK9GHGWjtg==",
                },
                {
                    "type": "ed25519",
                    "scheme": "ed25519",
                    "public_key": "MCwwBwYDK2VwBQADIQAWY3bJCn9xfQJwVicvNhwlL7BQ\
                        vtGgZ_8giaAwL7q3PQ==",
                },
                {
                    "type": "ed25519",
                    "scheme": "ed25519",
                    "public_key": "MCwwBwYDK2VwBQADIQBo2eyzhzcQBajrjmAQUwXDQ1ao_\
                        NhZ1_7zzCKL8rKzsg==",
                },
            ],
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
            MetadataDescription::new(
                1,
                100,
                hashmap! { HashAlgorithm::Sha256 => HashValue::new(vec![]) },
            ).unwrap(),
        ).unwrap();

        let jsn = json!({
            "type": "timestamp",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "snapshot": {
                "version": 1,
                "size": 100,
                "hashes": {
                    "sha256": "",
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
                MetadataPath::new("foo".into()).unwrap() =>
                    MetadataDescription::new(
                        1,
                        100,
                        hashmap! { HashAlgorithm::Sha256 => HashValue::new(vec![]) },
                    ).unwrap(),
            },
        ).unwrap();

        let jsn = json!({
            "type": "snapshot",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "meta": {
                "foo": {
                    "version": 1,
                    "size": 100,
                    "hashes": {
                        "sha256": "",
                    },
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
                VirtualTargetPath::new("foo".into()).unwrap() =>
                    TargetDescription::from_reader(
                        b"foo" as &[u8],
                        &[HashAlgorithm::Sha256],
                    ).unwrap(),
            },
            None,
        ).unwrap();

        let jsn = json!({
            "type": "targets",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "targets": {
                "foo": {
                    "size": 3,
                    "hashes": {
                        "sha256": "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564=",
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
        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let delegations = Delegations::new(
            &hashset![key.public().clone()],
            vec![Delegation::new(
                MetadataPath::new("foo/bar".into()).unwrap(),
                false,
                1,
                hashset!(key.key_id().clone()),
                hashset!(VirtualTargetPath::new("baz/quux".into()).unwrap()),
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
                "keys": [
                    {
                        "type": "ed25519",
                        "scheme": "ed25519",
                        "public_key": "MCwwBwYDK2VwBQADIQDrisJrXJ7wJ5474-giYqk7zhb\
                            -WO5CJQDTjK9GHGWjtg==",
                    },
                ],
                "roles": [
                    {
                        "role": "foo/bar",
                        "terminating": false,
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
                    MetadataDescription::new(
                        1,
                        100,
                        hashmap! { HashAlgorithm::Sha256 => HashValue::new(vec![]) },
                    ).unwrap(),
            },
        ).unwrap();

        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();

        let signed = SignedMetadata::<Json, SnapshotMetadata>::new(&snapshot, &key).unwrap();

        let jsn = json!({
            "signatures": [
                {
                    "key_id": "qfrfBrkB4lBBSDEBlZgaTGS_SrE6UfmON9kP4i3dJFY=",
                    "value": "9QXO-Av15zaWEsheO9JbWdo8iAF9vEbUKVePJpGRX5s6b1G8eqH4kvAE2jZV349JvZ\
                        -2yPGLE20V_7JwhMLYCQ==",
                }
            ],
            "signed": {
                "type": "snapshot",
                "version": 1,
                "expires": "2017-01-01T00:00:00Z",
                "meta": {
                    "foo": {
                        "version": 1,
                        "size": 100,
                        "hashes": {
                            "sha256": "",
                        },
                    },
                },
            },
        });

        let encoded = json::to_value(&signed).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: SignedMetadata<Json, SnapshotMetadata> = json::from_value(encoded).unwrap();
        assert_eq!(decoded, signed);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Here there be test cases about what metadata is allowed to be parsed wherein we do all sorts
    // of naughty things and make sure the parsers puke appropriately.
    //                                   ______________
    //                             ,===:'.,            `-._
    //                                  `:.`---.__         `-._
    //                                    `:.     `--.         `.
    //                                      \.        `.         `.
    //                              (,,(,    \.         `.   ____,-`.,
    //                           (,'     `/   \.   ,--.___`.'
    //                       ,  ,'  ,--.  `,   \.;'         `
    //                        `{o, {    \  :    \;
    //                          |,,'    /  /    //
    //                          j;;    /  ,' ,-//.    ,---.      ,
    //                          \;'   /  ,' /  _  \  /  _  \   ,'/
    //                                \   `'  / \  `'  / \  `.' /
    //                                 `.___,'   `.__,'   `.__,'
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // TODO test for mismatched ed25519/rsa keys/schemes

    fn make_root() -> json::Value {
        let root_def = RoleDefinition::new(
            1,
            hashset!(PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
                     .unwrap().key_id().clone()),
        ).unwrap();

        let snapshot_def = RoleDefinition::new(
            1,
            hashset!(PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519)
                     .unwrap().key_id().clone()),
        ).unwrap();

        let targets_def = RoleDefinition::new(
            1,
            hashset!(PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519)
                     .unwrap().key_id().clone()),
        ).unwrap();

        let timestamp_def = RoleDefinition::new(
            1,
            hashset!(PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519)
                     .unwrap().key_id().clone()),
        ).unwrap();

        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec!(
                PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
                    .unwrap().public().clone(),
                PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519)
                    .unwrap().public().clone(),
                PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519)
                    .unwrap().public().clone(),
                PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519)
                    .unwrap().public().clone(),
            ),
            root_def,
            snapshot_def,
            targets_def,
            timestamp_def,
        ).unwrap();

        json::to_value(&root).unwrap()
    }

    fn make_snapshot() -> json::Value {
        let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!())
            .unwrap();

        json::to_value(&snapshot).unwrap()
    }

    fn make_timestamp() -> json::Value {
        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();

        json::to_value(&timestamp).unwrap()
    }

    fn make_targets() -> json::Value {
        let targets =
            TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!(), None)
                .unwrap();

        json::to_value(&targets).unwrap()
    }

    fn make_delegations() -> json::Value {
        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();
        let delegations = Delegations::new(
            &hashset![key.clone()],
            vec![Delegation::new(
                MetadataPath::new("foo".into()).unwrap(),
                false,
                1,
                hashset!(key.key_id().clone()),
                hashset!(VirtualTargetPath::new("bar".into()).unwrap()),
            ).unwrap()],
        ).unwrap();

        json::to_value(&delegations).unwrap()
    }

    fn make_delegation() -> json::Value {
        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();
        let delegation = Delegation::new(
            MetadataPath::new("foo".into()).unwrap(),
            false,
            1,
            hashset!(key.key_id().clone()),
            hashset!(VirtualTargetPath::new("bar".into()).unwrap()),
        ).unwrap();

        json::to_value(&delegation).unwrap()
    }

    fn set_version(value: &mut json::Value, version: i64) {
        match value.as_object_mut() {
            Some(obj) => {
                let _ = obj.insert("version".into(), json!(version));
            }
            None => panic!(),
        }
    }

    // Refuse to deserialize root metadata if the version is not > 0
    #[test]
    fn deserialize_json_root_illegal_version() {
        let mut root_json = make_root();
        set_version(&mut root_json, 0);
        assert!(json::from_value::<RootMetadata>(root_json.clone()).is_err());

        let mut root_json = make_root();
        set_version(&mut root_json, -1);
        assert!(json::from_value::<RootMetadata>(root_json).is_err());
    }

    // Refuse to deserialize root metadata if it contains duplicate keys
    #[test]
    fn deserialize_json_root_duplicate_keys() {
        let mut root_json = make_root();
        let dupe = root_json
            .as_object()
            .unwrap()
            .get("keys")
            .unwrap()
            .as_array()
            .unwrap()
            [0]
            .clone();
        root_json
            .as_object_mut()
            .unwrap()
            .get_mut("keys")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(dupe);
        assert!(json::from_value::<RootMetadata>(root_json).is_err());
    }

    fn set_threshold(value: &mut json::Value, threshold: i32) {
        match value.as_object_mut() {
            Some(obj) => {
                let _ = obj.insert("threshold".into(), json!(threshold));
            }
            None => panic!(),
        }
    }

    // Refuse to deserialize role definitions with illegal thresholds
    #[test]
    fn deserialize_json_role_definition_illegal_threshold() {
        let role_def = RoleDefinition::new(
            1,
            hashset!(PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
                        .unwrap().key_id().clone()),
        ).unwrap();

        let mut jsn = json::to_value(&role_def).unwrap();
        set_threshold(&mut jsn, 0);
        assert!(json::from_value::<RoleDefinition>(jsn).is_err());

        let mut jsn = json::to_value(&role_def).unwrap();
        set_threshold(&mut jsn, -1);
        assert!(json::from_value::<RoleDefinition>(jsn).is_err());

        let role_def = RoleDefinition::new(
            2,
            hashset!(
                PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
                    .unwrap().key_id().clone(),
                PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519)
                    .unwrap().key_id().clone(),
            ),
        ).unwrap();

        let mut jsn = json::to_value(&role_def).unwrap();
        set_threshold(&mut jsn, 3);
        assert!(json::from_value::<RoleDefinition>(jsn).is_err());
    }

    // Refuse to deserialilze root metadata with wrong type field
    #[test]
    fn deserialize_json_root_bad_type() {
        let mut root = make_root();
        let _ = root.as_object_mut().unwrap().insert(
            "type".into(),
            json!("snapshot"),
        );
        assert!(json::from_value::<RootMetadata>(root).is_err());
    }

    // Refuse to deserialize role definitions with duplicated key ids
    #[test]
    fn deserialize_json_role_definition_duplicate_key_ids() {
        let key_id = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .key_id()
            .clone();
        let role_def = RoleDefinition::new(1, hashset!(key_id.clone())).unwrap();
        let mut jsn = json::to_value(&role_def).unwrap();

        match jsn.as_object_mut() {
            Some(obj) => {
                match obj.get_mut("key_ids").unwrap().as_array_mut() {
                    Some(arr) => arr.push(json!(key_id)),
                    None => panic!(),
                }
            }
            None => panic!(),
        }

        assert!(json::from_value::<RoleDefinition>(jsn).is_err());
    }

    // Refuse to deserialize snapshot metadata with illegal versions
    #[test]
    fn deserialize_json_snapshot_illegal_version() {
        let mut snapshot = make_snapshot();
        set_version(&mut snapshot, 0);
        assert!(json::from_value::<SnapshotMetadata>(snapshot).is_err());

        let mut snapshot = make_snapshot();
        set_version(&mut snapshot, -1);
        assert!(json::from_value::<SnapshotMetadata>(snapshot).is_err());
    }

    // Refuse to deserialilze snapshot metadata with wrong type field
    #[test]
    fn deserialize_json_snapshot_bad_type() {
        let mut snapshot = make_snapshot();
        let _ = snapshot.as_object_mut().unwrap().insert(
            "type".into(),
            json!("root"),
        );
        assert!(json::from_value::<SnapshotMetadata>(snapshot).is_err());
    }

    // Refuse to deserialize timestamp metadata with illegal versions
    #[test]
    fn deserialize_json_timestamp_illegal_version() {
        let mut timestamp = make_timestamp();
        set_version(&mut timestamp, 0);
        assert!(json::from_value::<TimestampMetadata>(timestamp).is_err());

        let mut timestamp = make_timestamp();
        set_version(&mut timestamp, -1);
        assert!(json::from_value::<TimestampMetadata>(timestamp).is_err());
    }

    // Refuse to deserialilze timestamp metadata with wrong type field
    #[test]
    fn deserialize_json_timestamp_bad_type() {
        let mut timestamp = make_timestamp();
        let _ = timestamp.as_object_mut().unwrap().insert(
            "type".into(),
            json!("root"),
        );
        assert!(json::from_value::<TimestampMetadata>(timestamp).is_err());
    }

    // Refuse to deserialize targets metadata with illegal versions
    #[test]
    fn deserialize_json_targets_illegal_version() {
        let mut targets = make_targets();
        set_version(&mut targets, 0);
        assert!(json::from_value::<TargetsMetadata>(targets).is_err());

        let mut targets = make_targets();
        set_version(&mut targets, -1);
        assert!(json::from_value::<TargetsMetadata>(targets).is_err());
    }

    // Refuse to deserialilze targets metadata with wrong type field
    #[test]
    fn deserialize_json_targets_bad_type() {
        let mut targets = make_targets();
        let _ = targets.as_object_mut().unwrap().insert(
            "type".into(),
            json!("root"),
        );
        assert!(json::from_value::<TargetsMetadata>(targets).is_err());
    }

    // Refuse to deserialize delegations with no keys
    #[test]
    fn deserialize_json_delegations_no_keys() {
        let mut delegations = make_delegations();
        delegations
            .as_object_mut()
            .unwrap()
            .get_mut("keys".into())
            .unwrap()
            .as_array_mut()
            .unwrap()
            .clear();
        assert!(json::from_value::<Delegations>(delegations).is_err());
    }

    // Refuse to deserialize delegations with no roles
    #[test]
    fn deserialize_json_delegations_no_roles() {
        let mut delegations = make_delegations();
        delegations
            .as_object_mut()
            .unwrap()
            .get_mut("roles".into())
            .unwrap()
            .as_array_mut()
            .unwrap()
            .clear();
        assert!(json::from_value::<Delegations>(delegations).is_err());
    }

    // Refuse to deserialize delegations with duplicated roles
    #[test]
    fn deserialize_json_delegations_duplicated_roles() {
        let mut delegations = make_delegations();
        let dupe = delegations
            .as_object()
            .unwrap()
            .get("roles".into())
            .unwrap()
            .as_array()
            .unwrap()
            [0]
            .clone();
        delegations
            .as_object_mut()
            .unwrap()
            .get_mut("roles".into())
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(dupe);
        assert!(json::from_value::<Delegations>(delegations).is_err());
    }

    // Refuse to deserialize a delegation with insufficient threshold
    #[test]
    fn deserialize_json_delegation_bad_threshold() {
        let mut delegation = make_delegation();
        set_threshold(&mut delegation, 0);
        assert!(json::from_value::<Delegation>(delegation).is_err());

        let mut delegation = make_delegation();
        set_threshold(&mut delegation, 2);
        assert!(json::from_value::<Delegation>(delegation).is_err());
    }

    // Refuse to deserialize a delegation with duplicate key IDs
    #[test]
    fn deserialize_json_delegation_duplicate_key_ids() {
        let mut delegation = make_delegation();
        let dupe = delegation
            .as_object()
            .unwrap()
            .get("key_ids".into())
            .unwrap()
            .as_array()
            .unwrap()
            [0]
            .clone();
        delegation
            .as_object_mut()
            .unwrap()
            .get_mut("key_ids".into())
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(dupe);
        assert!(json::from_value::<Delegation>(delegation).is_err());
    }

    // Refuse to deserialize a delegation with duplicate paths
    #[test]
    fn deserialize_json_delegation_duplicate_paths() {
        let mut delegation = make_delegation();
        let dupe = delegation
            .as_object()
            .unwrap()
            .get("paths".into())
            .unwrap()
            .as_array()
            .unwrap()
            [0]
            .clone();
        delegation
            .as_object_mut()
            .unwrap()
            .get_mut("paths".into())
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(dupe);
        assert!(json::from_value::<Delegation>(delegation).is_err());
    }

    // Refuse to deserialize a Delegations struct with duplicate keys
    #[test]
    fn deserialize_json_delegations_duplicate_keys() {
        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();
        let delegations = Delegations::new(
            &hashset!(key.clone()),
            vec![Delegation::new(
                MetadataPath::new("foo".into()).unwrap(),
                false,
                1,
                hashset!(key.key_id().clone()),
                hashset!(VirtualTargetPath::new("bar".into()).unwrap()),
            ).unwrap()],
        ).unwrap();
        let mut delegations = json::to_value(delegations).unwrap();

        let dupe = delegations
            .as_object()
            .unwrap()
            .get("keys".into())
            .unwrap()
            .as_array()
            .unwrap()
            [0]
            .clone();
        delegations
            .as_object_mut()
            .unwrap()
            .get_mut("keys".into())
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(dupe);
        assert!(json::from_value::<Delegations>(delegations).is_err());
    }
}
