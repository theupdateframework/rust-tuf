use std::collections::HashMap;
use std::path::Path;
use url::Url;

use core::{SignedRootMetadata, SignedSnapshotMetadata, SignedTargetsMetadata,
    SignedTimestampMetadata, Role, Signature, SignedMetadata, Key, KeyId};
use error::{TufError, VerificationFailure};

pub struct Tuf {
    url: Url,
    local_path: Box<Path>,
}

impl Tuf {
    pub fn init(config: Config) -> Result<Self, TufError> {
        // TODO load the curren metadata ?

        let mut tuf = UnverifiedTuf {
            url: config.url,
            local_path: config.local_path,
            root: None,
            snapshot: None,
            targets: None,
            timestamp: None,
        };

        tuf.verify()
    }
}


struct UnverifiedTuf {
    url: Url,
    local_path: Box<Path>,
    root: Option<SignedRootMetadata>,
    snapshot: Option<SignedSnapshotMetadata>,
    targets: Option<SignedTargetsMetadata>,
    timestamp: Option<SignedTimestampMetadata>,
}

impl UnverifiedTuf {
    fn verify(&mut self) -> Result<Tuf, TufError> {
        // update once
        self.verify_root()?;
        self.update()?;

        // reverify everything
        self.verify_root()?;
        self.verify_snapshot()?;
        self.verify_targets()?;
        self.verify_timestamp()?;

        Err(TufError::VerificationFailure(VerificationFailure::Undefined)) // TODO actually verify
    }

    fn update(&mut self) -> Result<(), TufError> {
        unimplemented!() // TODO
    }

    fn verify_root(&self) -> Result<(), TufError> {
        if let Some(ref root) = self.root {
            Self::unique_signatures(&root.signatures())?;
            let ref key_ids = root.signed.roles.get(&Role::Root).unwrap().key_ids; // TODO unwrap
            let keys = key_ids.iter()
                .map(|id| (id, root.signed.keys.get(id).unwrap())) // TODO unwrap
                .fold(HashMap::new(), |mut map, (id, key)| {
                    // TODO check that we don't overwrite ?
                    let _ = map.insert(id, key);
                    map
                });

            let (valid, errors) =
                Self::verify_signatures(&root.signed(), root.signatures(), &keys);

            // TODO unwrap
            if valid < root.signed.roles.get(&Role::Root).unwrap().threshold {
                Err(TufError::ThresholdNotMet(Role::Root))
            } else {
                Ok(()) // TODO more?
            }
        } else {
            Err(TufError::MissingRole(Role::Root))
        }
    }

    fn verify_snapshot(&self) -> Result<(), TufError> {
        if let Some(ref snapshot) = self.snapshot {
            Self::unique_signatures(&snapshot.signatures())
        } else {
            Err(TufError::MissingRole(Role::Snapshot))
        }?;
        unimplemented!() // TODO
    }

    fn verify_targets(&self) -> Result<(), TufError> {
        if let Some(ref targets) = self.targets {
            Self::unique_signatures(&targets.signatures())
        } else {
            Err(TufError::MissingRole(Role::Targets))
        }?;
        unimplemented!() // TODO
    }

    fn verify_timestamp(&self) -> Result<(), TufError> {
        if let Some(ref timestamp) = self.timestamp {
            Self::unique_signatures(&timestamp.signatures())
        } else {
            Err(TufError::MissingRole(Role::Timestamp))
        }?;
        unimplemented!() // TODO
    }

    fn verify_signatures(signed: &[u8],
                         signatures: &[Signature],
                         available_keys: &HashMap<&KeyId, &Key>) -> (i32, Vec<TufError>) {
        signatures.iter().map(|signature| {
            if let Some(key) = available_keys.get(&signature.key_id) {
                key.verify(&signed, &signature.method)
            } else {
                Err(TufError::UnknownKey(signature.key_id.clone()))
            }
        }).fold((0, Vec::new()), |(counter, mut errors), result| {
            if let Err(err) = result {
                errors.push(err);
                (counter, errors)
            } else {
                (counter + 1, errors)
            }
        })
    }

    // TODO this function might need to be pulled into the SignedMetadata trait
    fn unique_signatures(signatures: &[Signature]) -> Result<(), TufError> {
        let sig_len = signatures.len();
        let unique_len = signatures.iter().map(|s| s.key_id.clone()).len();

        if sig_len == unique_len {
            Ok(())
        } else {
            Err(TufError::NonUniqueSignatures)
        }
    }
}

pub struct Config {
    url: Url,
    local_path: Box<Path>,
}

impl Config {
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}


pub struct ConfigBuilder {
    url: Option<Url>,
    local_path: Option<Box<Path>>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        ConfigBuilder {
            url: None,
            local_path: None,
        }
    }

    pub fn url(mut self, url: Url) -> Self {
        self.url = Some(url);
        self
    }

    pub fn local_path(mut self, local_path: Box<Path>) -> Self {
        self.local_path = Some(local_path);
        self
    }

    pub fn finish(self) -> Result<Config, TufError> {
        let url = self.url.ok_or(TufError::InvalidConfig("Repository URL was not set".to_string()))?;
        let local_path = self.local_path.ok_or(TufError::InvalidConfig("Local path was not set".to_string()))?;

        // TODO error if path is not fully owned by the current user
        // TODO create path if not exists

        Ok(Config {
            url: url,
            local_path: local_path,
        })
    }
}
