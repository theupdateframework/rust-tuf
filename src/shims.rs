use chrono::offset::Utc;
use chrono::prelude::*;
use data_encoding::BASE64URL;
use serde_derive::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use crate::crypto;
use crate::error::Error;
use crate::metadata::{self, Metadata};
use crate::Result;

fn parse_datetime(ts: &str) -> Result<DateTime<Utc>> {
    Utc.datetime_from_str(ts, "%FT%TZ")
        .map_err(|e| Error::Encoding(format!("Can't parse DateTime: {:?}", e)))
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
    #[serde(rename = "_type")]
    typ: metadata::Role,
    version: u32,
    consistent_snapshot: bool,
    expires: String,
    #[serde(deserialize_with = "deserialize_reject_duplicates::deserialize")]
    keys: BTreeMap<crypto::KeyId, crypto::PublicKey>,
    roles: RoleDefinitions,
}

impl RootMetadata {
    pub fn from(meta: &metadata::RootMetadata) -> Result<Self> {
        Ok(RootMetadata {
            typ: metadata::Role::Root,
            version: meta.version(),
            expires: format_datetime(&meta.expires()),
            consistent_snapshot: meta.consistent_snapshot(),
            keys: meta.keys().iter().map(|(id, key)| (id.clone(), key.clone())).collect(),
            roles: RoleDefinitions {
                root: meta.root().clone(),
                snapshot: meta.snapshot().clone(),
                targets: meta.targets().clone(),
                timestamp: meta.timestamp().clone(),
            },
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
            self.keys.into_iter().collect(),
            self.roles.root,
            self.roles.snapshot,
            self.roles.targets,
            self.roles.timestamp,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RoleDefinitions {
    root: metadata::RoleDefinition,
    snapshot: metadata::RoleDefinition,
    targets: metadata::RoleDefinition,
    timestamp: metadata::RoleDefinition,
}

#[derive(Serialize, Deserialize)]
pub struct RoleDefinition {
    threshold: u32,
    #[serde(rename = "keyids")]
    key_ids: Vec<crypto::KeyId>,
}

impl RoleDefinition {
    pub fn from(role: &metadata::RoleDefinition) -> Result<Self> {
        let mut key_ids = role.key_ids().iter().cloned().collect::<Vec<crypto::KeyId>>();
        key_ids.sort();

        Ok(RoleDefinition { threshold: role.threshold(), key_ids })
    }

    pub fn try_into(mut self) -> Result<metadata::RoleDefinition> {
        let vec_len = self.key_ids.len();
        if vec_len < 1 {
            return Err(Error::Encoding("Role defined with no assoiciated key IDs.".into()));
        }

        let key_ids = self.key_ids.drain(0..).collect::<HashSet<crypto::KeyId>>();
        let dupes = vec_len - key_ids.len();

        if dupes != 0 {
            return Err(Error::Encoding(format!("Found {} duplicate key IDs.", dupes)));
        }

        Ok(metadata::RoleDefinition::new(self.threshold, key_ids)?)
    }
}

#[derive(Serialize, Deserialize)]
pub struct TimestampMetadata {
    #[serde(rename = "_type")]
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
    #[serde(rename = "_type")]
    typ: metadata::Role,
    version: u32,
    expires: String,
    meta: BTreeMap<metadata::MetadataPath, metadata::MetadataDescription>,
}

impl SnapshotMetadata {
    pub fn from(metadata: &metadata::SnapshotMetadata) -> Result<Self> {
        Ok(SnapshotMetadata {
            typ: metadata::Role::Snapshot,
            version: metadata.version(),
            expires: format_datetime(&metadata.expires()),
            meta: metadata.meta().iter().map(|(p, d)| (p.clone(), d.clone())).collect(),
        })
    }

    pub fn try_into(self) -> Result<metadata::SnapshotMetadata> {
        if self.typ != metadata::Role::Snapshot {
            return Err(Error::Encoding(format!(
                "Attempted to decode snapshot metdata labeled as {:?}",
                self.typ
            )));
        }

        metadata::SnapshotMetadata::new(
            self.version,
            parse_datetime(&self.expires)?,
            self.meta.into_iter().collect(),
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct TargetsMetadata {
    #[serde(rename = "_type")]
    typ: metadata::Role,
    version: u32,
    expires: String,
    targets: BTreeMap<metadata::VirtualTargetPath, metadata::TargetDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegations: Option<metadata::Delegations>,
}

impl TargetsMetadata {
    pub fn from(metadata: &metadata::TargetsMetadata) -> Result<Self> {
        Ok(TargetsMetadata {
            typ: metadata::Role::Targets,
            version: metadata.version(),
            expires: format_datetime(&metadata.expires()),
            targets: metadata.targets().iter().map(|(p, d)| (p.clone(), d.clone())).collect(),
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
            self.targets.into_iter().collect(),
            self.delegations,
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(rename = "type")]
    typ: crypto::KeyType,
    scheme: crypto::SignatureScheme,
    public_key: String,
}

impl PublicKey {
    pub fn new(
        typ: crypto::KeyType,
        scheme: crypto::SignatureScheme,
        public_key_bytes: &[u8],
    ) -> Self {
        PublicKey { typ, scheme, public_key: BASE64URL.encode(public_key_bytes) }
    }

    pub fn public_key(&self) -> &String {
        &self.public_key
    }

    pub fn scheme(&self) -> &crypto::SignatureScheme {
        &self.scheme
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
    #[serde(rename = "keyids")]
    key_ids: Vec<crypto::KeyId>,
    paths: Vec<metadata::VirtualTargetPath>,
}

impl Delegation {
    pub fn from(meta: &metadata::Delegation) -> Self {
        let mut paths = meta.paths().iter().cloned().collect::<Vec<metadata::VirtualTargetPath>>();
        paths.sort();
        let mut key_ids = meta.key_ids().iter().cloned().collect::<Vec<crypto::KeyId>>();
        key_ids.sort();

        Delegation {
            role: meta.role().clone(),
            terminating: meta.terminating(),
            threshold: meta.threshold(),
            key_ids,
            paths,
        }
    }

    pub fn try_into(self) -> Result<metadata::Delegation> {
        let paths = self.paths.iter().cloned().collect::<HashSet<metadata::VirtualTargetPath>>();
        if paths.len() != self.paths.len() {
            return Err(Error::Encoding("Non-unique delegation paths.".into()));
        }

        let key_ids = self.key_ids.iter().cloned().collect::<HashSet<crypto::KeyId>>();
        if key_ids.len() != self.key_ids.len() {
            return Err(Error::Encoding("Non-unique delegation key IDs.".into()));
        }

        metadata::Delegation::new(self.role, self.terminating, self.threshold, key_ids, paths)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Delegations {
    #[serde(deserialize_with = "deserialize_reject_duplicates::deserialize")]
    keys: BTreeMap<crypto::KeyId, crypto::PublicKey>,
    roles: Vec<metadata::Delegation>,
}

impl Delegations {
    pub fn from(delegations: &metadata::Delegations) -> Delegations {
        Delegations {
            keys: delegations.keys().iter().map(|(id, key)| (id.clone(), key.clone())).collect(),
            roles: delegations.roles().clone(),
        }
    }

    pub fn try_into(self) -> Result<metadata::Delegations> {
        metadata::Delegations::new(self.keys.into_iter().collect(), self.roles)
    }
}

#[derive(Deserialize)]
pub struct TargetDescription {
    length: u64,
    hashes: BTreeMap<crypto::HashAlgorithm, crypto::HashValue>,
}

impl TargetDescription {
    pub fn try_into(self) -> Result<metadata::TargetDescription> {
        metadata::TargetDescription::new(self.length, self.hashes.into_iter().collect())
    }
}

#[derive(Deserialize)]
pub struct MetadataDescription {
    version: u32,
    length: usize,
    hashes: BTreeMap<crypto::HashAlgorithm, crypto::HashValue>,
}

impl MetadataDescription {
    pub fn try_into(self) -> Result<metadata::MetadataDescription> {
        metadata::MetadataDescription::new(
            self.version,
            self.length,
            self.hashes.into_iter().collect(),
        )
    }
}

/// Custom deserialize to reject duplicate keys.
mod deserialize_reject_duplicates {
    use serde::de::{Deserialize, Deserializer, Error, MapAccess, Visitor};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::marker::PhantomData;
    use std::result::Result;

    pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        struct BTreeVisitor<K, V> {
            marker: PhantomData<(K, V)>,
        };

        impl<'de, K, V> Visitor<'de> for BTreeVisitor<K, V>
        where
            K: Deserialize<'de> + Ord,
            V: Deserialize<'de>,
        {
            type Value = BTreeMap<K, V>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("map")
            }

            fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry()? {
                    if map.insert(key, value).is_some() {
                        return Err(M::Error::custom("Cannot have duplicate keys"));
                    }
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(BTreeVisitor { marker: PhantomData })
    }
}
