use chrono::DateTime;
use chrono::offset::Utc;
use data_encoding::HEXLOWER;
use pem::{self, Pem};
use std::collections::{HashMap, HashSet};

use Result;
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
    keys: HashMap<metadata::KeyId, metadata::PublicKey>,
    roles: HashMap<metadata::Role, metadata::RoleDefinition>,
}

impl RootMetadata {
    pub fn from(root_metadata: &metadata::RootMetadata) -> Result<Self> {
        let mut roles = HashMap::new();
        let _ = roles.insert(metadata::Role::Root, root_metadata.root().clone());
        let _ = roles.insert(metadata::Role::Snapshot, root_metadata.snapshot().clone());
        let _ = roles.insert(metadata::Role::Targets, root_metadata.targets().clone());
        let _ = roles.insert(metadata::Role::Timestamp, root_metadata.timestamp().clone());

        Ok(RootMetadata {
            typ: metadata::Role::Root,
            version: root_metadata.version(),
            expires: root_metadata.expires().clone(),
            consistent_snapshot: root_metadata.consistent_snapshot(),
            keys: root_metadata.keys().clone(),
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
            let calculated = metadata::calculate_key_id(value.value());
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

        let root = self.roles.remove(&metadata::Role::Root).ok_or(
            Error::Decode(
                "Missing root role definition"
                    .into(),
            ),
        )?;
        let snapshot = self.roles.remove(&metadata::Role::Snapshot).ok_or(
            Error::Decode(
                "Missing snapshot role definition"
                    .into(),
            ),
        )?;
        let targets = self.roles.remove(&metadata::Role::Targets).ok_or(
            Error::Decode(
                "Missing targets role definition"
                    .into(),
            ),
        )?;
        let timestamp = self.roles.remove(&metadata::Role::Timestamp).ok_or(
            Error::Decode(
                "Missing timestamp role definition"
                    .into(),
            ),
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
    typ: metadata::KeyType,
    value: PublicKeyValue,
}

impl PublicKey {
    pub fn from(public_key: &metadata::PublicKey) -> Result<Self> {
        let key_str = match public_key.format() {
            &metadata::KeyFormat::HexLower => HEXLOWER.encode(&*public_key.value().value()),
            &metadata::KeyFormat::Pkcs1 => {
                pem::encode(&Pem {
                    tag: "RSA PUBLIC KEY".to_string(),
                    contents: public_key.value().value().to_vec(),
                }).replace("\r", "")
                    .trim()
                    .into()
            }
            &metadata::KeyFormat::Spki => {
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

    pub fn try_into(self) -> Result<metadata::PublicKey> {
        let (key_bytes, format) = match self.typ {
            metadata::KeyType::Ed25519 => {
                let bytes = HEXLOWER.decode(self.value.public.as_bytes())?;
                (bytes, metadata::KeyFormat::HexLower)
            }
            metadata::KeyType::Rsa => {
                let _pem = pem::parse(self.value.public.as_bytes())?;
                match _pem.tag.as_str() {
                    "RSA PUBLIC KEY" => {
                        let bytes = rsa::from_pkcs1(&_pem.contents).ok_or(
                            Error::UnsupportedKeyFormat(
                                "PEM claimed to PKCS1 but could not be parsed"
                                    .into(),
                            ),
                        )?;
                        (bytes, metadata::KeyFormat::Pkcs1)
                    }
                    "PUBLIC KEY" => {
                        let bytes = rsa::from_spki(&_pem.contents).ok_or(
                            Error::UnsupportedKeyFormat(
                                "PEM claimed to SPKI but could not be parsed"
                                    .into(),
                            ),
                        )?;
                        (bytes, metadata::KeyFormat::Spki)
                    }
                    x => {
                        return Err(Error::UnsupportedKeyFormat(
                            format!("PEM with bad tag: {}", x),
                        ))
                    }
                }
            }
        };

        let key = metadata::PublicKeyValue::new(key_bytes);

        Ok(metadata::PublicKey::new(self.typ, format, key))
    }
}

#[derive(Serialize, Deserialize)]
struct PublicKeyValue {
    public: String,
}

#[derive(Serialize, Deserialize)]
pub struct RoleDefinition {
    threshold: u32,
    key_ids: Vec<metadata::KeyId>,
}

impl RoleDefinition {
    pub fn from(role: &metadata::RoleDefinition) -> Result<Self> {
        let mut key_ids = role.key_ids()
            .iter()
            .cloned()
            .collect::<Vec<metadata::KeyId>>();
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

        let key_ids = self.key_ids
            .drain(0..)
            .collect::<HashSet<metadata::KeyId>>();
        let dupes = vec_len - key_ids.len();

        if dupes != 0 {
            return Err(Error::Decode(format!("Found {} duplicate key IDs.", dupes)));
        }

        Ok(metadata::RoleDefinition::new(self.threshold, key_ids)?)
    }
}
