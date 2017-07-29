use chrono::prelude::*;
use chrono::offset::Utc;
use data_encoding::BASE64URL;
use std::collections::{HashMap, HashSet};

use Result;
use crypto;
use error::Error;
use metadata;

fn parse_datetime(ts: &str) -> Result<DateTime<Utc>> {
    Utc.datetime_from_str(ts, "%FT%TZ").map_err(|e| {
        Error::Encoding(format!("Can't parse DateTime: {:?}", e))
    })
}

fn format_datetime(ts: &DateTime<Utc>) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        ts.year(),
        ts.month(),
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second()
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootMetadata {
    #[serde(rename = "type")]
    typ: metadata::Role,
    version: u32,
    consistent_snapshot: bool,
    expires: String,
    keys: Vec<crypto::PublicKey>,
    root: metadata::RoleDefinition,
    snapshot: metadata::RoleDefinition,
    targets: metadata::RoleDefinition,
    timestamp: metadata::RoleDefinition,
}

impl RootMetadata {
    pub fn from(meta: &metadata::RootMetadata) -> Result<Self> {
        let mut keys = meta.keys()
            .iter()
            .map(|(_, v)| v.clone())
            .collect::<Vec<crypto::PublicKey>>();
        keys.sort_by_key(|k| k.key_id().clone());

        Ok(RootMetadata {
            typ: metadata::Role::Root,
            version: meta.version(),
            expires: format_datetime(&meta.expires()),
            consistent_snapshot: meta.consistent_snapshot(),
            keys: keys,
            root: meta.root().clone(),
            snapshot: meta.snapshot().clone(),
            targets: meta.targets().clone(),
            timestamp: meta.timestamp().clone(),
        })
    }

    pub fn try_into(self) -> Result<metadata::RootMetadata> {
        if self.typ != metadata::Role::Root {
            return Err(Error::Encoding(format!(
                "Attempted to decode root metdata labeled as {:?}",
                self.typ
            )));
        }

        metadata::RootMetadata::new(
            self.version,
            parse_datetime(&self.expires)?,
            self.consistent_snapshot,
            self.keys,
            self.root,
            self.snapshot,
            self.targets,
            self.timestamp,
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
    expires: String,
    snapshot: metadata::MetadataDescription,
}

impl TimestampMetadata {
    pub fn from(metadata: &metadata::TimestampMetadata) -> Result<Self> {
        Ok(TimestampMetadata {
            typ: metadata::Role::Timestamp,
            version: metadata.version(),
            expires: format_datetime(metadata.expires()),
            snapshot: metadata.snapshot().clone(),
        })
    }

    pub fn try_into(self) -> Result<metadata::TimestampMetadata> {
        if self.typ != metadata::Role::Timestamp {
            return Err(Error::Encoding(format!(
                "Attempted to decode datetime metdata labeled as {:?}",
                self.typ
            )));
        }

        metadata::TimestampMetadata::new(
            self.version,
            parse_datetime(&self.expires)?,
            self.snapshot,
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct SnapshotMetadata {
    #[serde(rename = "type")]
    typ: metadata::Role,
    version: u32,
    expires: String,
    meta: HashMap<metadata::MetadataPath, metadata::MetadataDescription>,
}

impl SnapshotMetadata {
    pub fn from(metadata: &metadata::SnapshotMetadata) -> Result<Self> {
        Ok(SnapshotMetadata {
            typ: metadata::Role::Snapshot,
            version: metadata.version(),
            expires: format_datetime(&metadata.expires()),
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

        metadata::SnapshotMetadata::new(self.version, parse_datetime(&self.expires)?, self.meta)
    }
}


#[derive(Serialize, Deserialize)]
pub struct TargetsMetadata {
    #[serde(rename = "type")]
    typ: metadata::Role,
    version: u32,
    expires: String,
    targets: HashMap<metadata::TargetPath, metadata::TargetDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegations: Option<metadata::Delegations>,
}

impl TargetsMetadata {
    pub fn from(metadata: &metadata::TargetsMetadata) -> Result<Self> {
        Ok(TargetsMetadata {
            typ: metadata::Role::Targets,
            version: metadata.version(),
            expires: format_datetime(&metadata.expires()),
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

        metadata::TargetsMetadata::new(
            self.version,
            parse_datetime(&self.expires)?,
            self.targets,
            self.delegations,
        )
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
