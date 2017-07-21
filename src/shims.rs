use chrono::DateTime;
use chrono::offset::Utc;
use data_encoding::BASE64URL;
use std::collections::{HashMap, HashSet};

use Result;
use crypto;
use error::Error;
use metadata;

#[derive(Debug, Serialize, Deserialize)]
pub struct RootMetadata {
    #[serde(rename = "type")]
    typ: metadata::Role,
    version: u32,
    consistent_snapshot: bool,
    expires: DateTime<Utc>,
    keys: HashMap<crypto::KeyId, crypto::PublicKey>,
    roles: HashMap<metadata::Role, metadata::RoleDefinition>,
}

impl RootMetadata {
    pub fn from(meta: &metadata::RootMetadata) -> Result<Self> {
        let mut roles = HashMap::new();
        let _ = roles.insert(metadata::Role::Root, meta.root().clone());
        let _ = roles.insert(metadata::Role::Snapshot, meta.snapshot().clone());
        let _ = roles.insert(metadata::Role::Targets, meta.targets().clone());
        let _ = roles.insert(metadata::Role::Timestamp, meta.timestamp().clone());

        Ok(RootMetadata {
            typ: metadata::Role::Root,
            version: meta.version(),
            expires: meta.expires().clone(),
            consistent_snapshot: meta.consistent_snapshot(),
            keys: meta.keys().clone(),
            roles: roles,
        })
    }

    pub fn try_into(mut self) -> Result<metadata::RootMetadata> {
        if self.typ != metadata::Role::Root {
            return Err(Error::Encoding(format!(
                "Attempted to decode root metdata labeled as {:?}",
                self.typ
            )));
        }

        let mut keys = Vec::new();
        for (key_id, value) in self.keys.drain() {
            if &key_id != value.key_id() {
                warn!(
                    "Received key with ID {:?} but calculated it's value as {:?}. \
                       Refusing to add it to the set of trusted keys.",
                    key_id,
                    value.key_id()
                );
            } else {
                debug!(
                    "Found key with good ID {:?}. Adding it to the set of trusted keys.",
                    key_id
                );
                keys.push(value);
            }
        }

        let root = self.roles.remove(&metadata::Role::Root).ok_or_else(|| {
            Error::Encoding("Missing root role definition".into())
        })?;
        let snapshot = self.roles.remove(&metadata::Role::Snapshot).ok_or_else(
            || {
                Error::Encoding("Missing snapshot role definition".into())
            },
        )?;
        let targets = self.roles.remove(&metadata::Role::Targets).ok_or_else(|| {
            Error::Encoding("Missing targets role definition".into())
        })?;
        let timestamp = self.roles.remove(&metadata::Role::Timestamp).ok_or_else(
            || {
                Error::Encoding("Missing timestamp role definition".into())
            },
        )?;

        metadata::RootMetadata::new(
            self.version,
            self.expires,
            self.consistent_snapshot,
            keys,
            root,
            snapshot,
            targets,
            timestamp,
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct RoleDefinition {
    threshold: u32,
    key_ids: Vec<crypto::KeyId>,
}

impl RoleDefinition {
    pub fn from(role: &metadata::RoleDefinition) -> Result<Self> {
        let mut key_ids = role.key_ids()
            .iter()
            .cloned()
            .collect::<Vec<crypto::KeyId>>();
        key_ids.sort();

        Ok(RoleDefinition {
            threshold: role.threshold(),
            key_ids: key_ids,
        })
    }

    pub fn try_into(mut self) -> Result<metadata::RoleDefinition> {
        let vec_len = self.key_ids.len();
        if vec_len < 1 {
            return Err(Error::Encoding(
                "Role defined with no assoiciated key IDs.".into(),
            ));
        }

        let key_ids = self.key_ids.drain(0..).collect::<HashSet<crypto::KeyId>>();
        let dupes = vec_len - key_ids.len();

        if dupes != 0 {
            return Err(Error::Encoding(
                format!("Found {} duplicate key IDs.", dupes),
            ));
        }

        Ok(metadata::RoleDefinition::new(self.threshold, key_ids)?)
    }
}

#[derive(Serialize, Deserialize)]
pub struct TimestampMetadata {
    #[serde(rename = "type")]
    typ: metadata::Role,
    version: u32,
    expires: DateTime<Utc>,
    meta: HashMap<metadata::MetadataPath, metadata::MetadataDescription>,
}

impl TimestampMetadata {
    pub fn from(metadata: &metadata::TimestampMetadata) -> Result<Self> {
        Ok(TimestampMetadata {
            typ: metadata::Role::Timestamp,
            version: metadata.version(),
            expires: metadata.expires().clone(),
            meta: metadata.meta().clone(),
        })
    }

    pub fn try_into(self) -> Result<metadata::TimestampMetadata> {
        if self.typ != metadata::Role::Timestamp {
            return Err(Error::Encoding(format!(
                "Attempted to decode timestamp metdata labeled as {:?}",
                self.typ
            )));
        }

        metadata::TimestampMetadata::new(self.version, self.expires, self.meta)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SnapshotMetadata {
    #[serde(rename = "type")]
    typ: metadata::Role,
    version: u32,
    expires: DateTime<Utc>,
    meta: HashMap<metadata::MetadataPath, metadata::MetadataDescription>,
}

impl SnapshotMetadata {
    pub fn from(metadata: &metadata::SnapshotMetadata) -> Result<Self> {
        Ok(SnapshotMetadata {
            typ: metadata::Role::Snapshot,
            version: metadata.version(),
            expires: metadata.expires().clone(),
            meta: metadata.meta().clone(),
        })
    }

    pub fn try_into(self) -> Result<metadata::SnapshotMetadata> {
        if self.typ != metadata::Role::Snapshot {
            return Err(Error::Encoding(format!(
                "Attempted to decode snapshot metdata labeled as {:?}",
                self.typ
            )));
        }

        metadata::SnapshotMetadata::new(self.version, self.expires, self.meta)
    }
}


#[derive(Serialize, Deserialize)]
pub struct TargetsMetadata {
    #[serde(rename = "type")]
    typ: metadata::Role,
    version: u32,
    expires: DateTime<Utc>,
    targets: HashMap<metadata::TargetPath, metadata::TargetDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegations: Option<metadata::Delegations>,
}

impl TargetsMetadata {
    pub fn from(metadata: &metadata::TargetsMetadata) -> Result<Self> {
        Ok(TargetsMetadata {
            typ: metadata::Role::Targets,
            version: metadata.version(),
            expires: metadata.expires().clone(),
            targets: metadata.targets().clone(),
            delegations: metadata.delegations().cloned(),
        })
    }

    pub fn try_into(self) -> Result<metadata::TargetsMetadata> {
        if self.typ != metadata::Role::Targets {
            return Err(Error::Encoding(format!(
                "Attempted to decode targets metdata labeled as {:?}",
                self.typ
            )));
        }

        metadata::TargetsMetadata::new(self.version, self.expires, self.targets, self.delegations)
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(rename = "type")]
    typ: crypto::KeyType,
    public_key: String,
}

impl PublicKey {
    pub fn new(typ: crypto::KeyType, public_key_bytes: &[u8]) -> Self {
        PublicKey {
            typ: typ,
            public_key: BASE64URL.encode(public_key_bytes),
        }
    }

    pub fn public_key(&self) -> &String {
        &self.public_key
    }

    pub fn typ(&self) -> &crypto::KeyType {
        &self.typ
    }
}

#[derive(Serialize, Deserialize)]
pub struct Delegation {
    role: metadata::MetadataPath,
    terminating: bool,
    threshold: u32,
    key_ids: Vec<crypto::KeyId>,
    paths: Vec<metadata::TargetPath>,
}

impl Delegation {
    pub fn from(meta: &metadata::Delegation) -> Self {
        let mut paths = meta.paths()
            .iter()
            .cloned()
            .collect::<Vec<metadata::TargetPath>>();
        paths.sort();
        let mut key_ids = meta.key_ids()
            .iter()
            .cloned()
            .collect::<Vec<crypto::KeyId>>();
        key_ids.sort();

        Delegation {
            role: meta.role().clone(),
            terminating: meta.terminating(),
            threshold: meta.threshold(),
            key_ids: key_ids,
            paths: paths,
        }
    }

    pub fn try_into(self) -> Result<metadata::Delegation> {
        let paths = self.paths
            .iter()
            .cloned()
            .collect::<HashSet<metadata::TargetPath>>();
        if paths.len() != self.paths.len() {
            return Err(Error::Encoding("Non-unique delegation paths.".into()));
        }

        let key_ids = self.key_ids
            .iter()
            .cloned()
            .collect::<HashSet<crypto::KeyId>>();
        if key_ids.len() != self.key_ids.len() {
            return Err(Error::Encoding("Non-unique delegation key IDs.".into()));
        }

        metadata::Delegation::new(self.role, self.terminating, self.threshold, key_ids, paths)
    }
}

#[derive(Deserialize)]
pub struct Delegations {
    keys: HashMap<crypto::KeyId, crypto::PublicKey>,
    roles: Vec<metadata::Delegation>,
}


impl Delegations {
    pub fn try_into(mut self) -> Result<metadata::Delegations> {
        let mut keys = Vec::new();
        for (key_id, value) in self.keys.drain() {
            if &key_id != value.key_id() {
                warn!(
                    "Received key with ID {:?} but calculated it's value as {:?}. \
                       Refusing to add it to the set of trusted keys.",
                    key_id,
                    value.key_id()
                );
            } else {
                debug!(
                    "Found key with good ID {:?}. Adding it to the set of trusted keys.",
                    key_id
                );
                keys.push(value);
            }
        }

        metadata::Delegations::new(keys, self.roles)
    }
}

#[derive(Deserialize)]
pub struct TargetDescription {
    size: u64,
    hashes: HashMap<crypto::HashAlgorithm, crypto::HashValue>,
}

impl TargetDescription {
    pub fn try_into(self) -> Result<metadata::TargetDescription> {
        metadata::TargetDescription::new(self.size, self.hashes)
    }
}

#[derive(Deserialize)]
pub struct MetadataDescription {
    version: u32,
    size: usize,
    hashes: HashMap<crypto::HashAlgorithm, crypto::HashValue>,
}

impl MetadataDescription {
    pub fn try_into(self) -> Result<metadata::MetadataDescription> {
        metadata::MetadataDescription::new(self.version, self.size, self.hashes)
    }
}
