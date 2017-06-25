use chrono::DateTime;
use chrono::offset::Utc;
use data_encoding::HEXLOWER;
use pem::{self, Pem};
use std::collections::{HashMap, HashSet};

use Result;
use crypto;
use error::Error;
use metadata;
use rsa;

#[derive(Serialize, Deserialize)]
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
    pub fn from(metadata: &metadata::RootMetadata) -> Result<Self> {
        let mut roles = HashMap::new();
        let _ = roles.insert(metadata::Role::Root, metadata.root().clone());
        let _ = roles.insert(metadata::Role::Snapshot, metadata.snapshot().clone());
        let _ = roles.insert(metadata::Role::Targets, metadata.targets().clone());
        let _ = roles.insert(metadata::Role::Timestamp, metadata.timestamp().clone());

        Ok(RootMetadata {
            typ: metadata::Role::Root,
            version: metadata.version(),
            expires: metadata.expires().clone(),
            consistent_snapshot: metadata.consistent_snapshot(),
            keys: metadata.keys().clone(),
            roles: roles,
        })
    }

    pub fn try_into(mut self) -> Result<metadata::RootMetadata> {
        if self.typ != metadata::Role::Root {
            return Err(Error::Decode(format!(
                "Attempted to decode root metdata labeled as {:?}",
                self.typ
            )));
        }

        let mut keys = Vec::new();
        for (key_id, value) in self.keys.drain() {
            let calculated = crypto::calculate_key_id(value.value());
            if key_id != calculated {
                warn!(
                    "Received key with ID {:?} but calculated it's value as {:?}. \
                       Refusing to add it to the set of trusted keys.",
                    key_id,
                    calculated
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
            Error::Decode("Missing root role definition".into())
        })?;
        let snapshot = self.roles.remove(&metadata::Role::Snapshot).ok_or_else(
            || {
                Error::Decode("Missing snapshot role definition".into())
            },
        )?;
        let targets = self.roles.remove(&metadata::Role::Targets).ok_or_else(|| {
            Error::Decode("Missing targets role definition".into())
        })?;
        let timestamp = self.roles.remove(&metadata::Role::Timestamp).ok_or_else(
            || {
                Error::Decode("Missing timestamp role definition".into())
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
pub struct PublicKey {
    #[serde(rename = "type")]
    typ: crypto::KeyType,
    value: PublicKeyValue,
}

impl PublicKey {
    pub fn from(public_key: &crypto::PublicKey) -> Result<Self> {
        let key_str = match public_key.format() {
            &crypto::KeyFormat::HexLower => HEXLOWER.encode(&*public_key.value().value()),
            &crypto::KeyFormat::Pkcs1 => {
                pem::encode(&Pem {
                    tag: "RSA PUBLIC KEY".to_string(),
                    contents: public_key.value().value().to_vec(),
                }).replace("\r", "")
                    .trim()
                    .into()
            }
            &crypto::KeyFormat::Spki => {
                pem::encode(&Pem {
                    tag: "PUBLIC KEY".to_string(),
                    contents: rsa::write_spki(&public_key.value().value().to_vec())?,
                }).replace("\r", "")
                    .trim()
                    .into()
            }
        };

        Ok(PublicKey {
            typ: public_key.typ().clone(),
            value: PublicKeyValue { public: key_str },
        })
    }

    pub fn try_into(self) -> Result<crypto::PublicKey> {
        match self.typ {
            crypto::KeyType::Ed25519 => {
                let bytes = HEXLOWER.decode(self.value.public.as_bytes())?;
                crypto::PublicKey::from_ed25519(crypto::PublicKeyValue::new(bytes))
            }
            crypto::KeyType::Rsa => {
                let _pem = pem::parse(self.value.public.as_bytes())?;
                match _pem.tag.as_str() {
                    "RSA PUBLIC KEY" => {
                        crypto::PublicKey::from_rsa(
                            crypto::PublicKeyValue::new(_pem.contents),
                            crypto::KeyFormat::Pkcs1,
                        )
                    }
                    "PUBLIC KEY" => {
                        crypto::PublicKey::from_rsa(
                            crypto::PublicKeyValue::new(_pem.contents),
                            crypto::KeyFormat::Spki,
                        )
                    }
                    x => {
                        return Err(Error::UnsupportedKeyFormat(
                            format!("PEM with bad tag: {}", x),
                        ))
                    }
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PublicKeyValue {
    public: String,
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
            return Err(Error::Decode(
                "Role defined with no assoiciated key IDs.".into(),
            ));
        }

        let key_ids = self.key_ids.drain(0..).collect::<HashSet<crypto::KeyId>>();
        let dupes = vec_len - key_ids.len();

        if dupes != 0 {
            return Err(Error::Decode(format!("Found {} duplicate key IDs.", dupes)));
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
            return Err(Error::Decode(format!(
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
            return Err(Error::Decode(format!(
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
}

impl TargetsMetadata {
    pub fn from(metadata: &metadata::TargetsMetadata) -> Result<Self> {
        Ok(TargetsMetadata {
            typ: metadata::Role::Targets,
            version: metadata.version(),
            expires: metadata.expires().clone(),
            targets: metadata.targets().clone(),
        })
    }

    pub fn try_into(self) -> Result<metadata::TargetsMetadata> {
        if self.typ != metadata::Role::Targets {
            return Err(Error::Decode(format!(
                "Attempted to decode targets metdata labeled as {:?}",
                self.typ
            )));
        }

        metadata::TargetsMetadata::new(self.version, self.expires, self.targets)
    }
}
