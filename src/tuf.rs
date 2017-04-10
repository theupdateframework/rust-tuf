use std::collections::HashMap;
use std::path::Path;
use url::Url;

use core::{SignedRootMetadata, SignedSnapshotMetadata, SignedTargetsMetadata,
    SignedTimestampMetadata, Role, Signature, SignedMetadata, Key, KeyId, RootMetadata};
use error::{TufError, VerificationFailure};

pub struct Tuf {
    url: Url,
    local_path: Box<Path>,
    // TODO add repo name
}

impl Tuf {
    pub fn init(config: Config) -> Result<Self, TufError> {
        // TODO load the current metadata ?

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


    // TODO real return type
    pub fn list_targets() -> Vec<String> {
        unimplemented!() // TODO
    }

    // TODO real input type
    pub fn fetch_target(target: String) -> Result<Box<Path>, TufError> {
        unimplemented!() // TODO
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
        // TODO this can probably be done with `.or_ok(...)?`
        if let Some(ref root) = self.root {
            Self::unique_signatures(&root.signatures())
            // TODO verify root chain
        } else {
            Err(TufError::MissingRole(Role::Root))
        }
    }

    fn verify_snapshot(&self) -> Result<(), TufError> {
        if let Some(ref snapshot) = self.snapshot {
            Self::unique_signatures(&snapshot.signatures())?;
            // TODO unwrap
            self.verify_role(&self.root.as_ref().unwrap().signed, &Role::Snapshot, snapshot)
            // TODO check expiration
        } else {
            Err(TufError::MissingRole(Role::Snapshot))
        }?;
        unimplemented!() // TODO
    }

    fn verify_targets(&self) -> Result<(), TufError> {
        if let Some(ref targets) = self.targets {
            Self::unique_signatures(&targets.signatures())?;
            // TODO unwrap
            self.verify_role(&self.root.as_ref().unwrap().signed, &Role::Targets, targets)
            // TODO check expiration
        } else {
            Err(TufError::MissingRole(Role::Targets))
        }?;
        unimplemented!() // TODO
    }

    fn verify_timestamp(&self) -> Result<(), TufError> {
        if let Some(ref timestamp) = self.timestamp {
            Self::unique_signatures(&timestamp.signatures())?;
            // TODO unwrap
            self.verify_role(&self.root.as_ref().unwrap().signed, &Role::Timestamp, timestamp)
            // TODO check expiration
        } else {
            Err(TufError::MissingRole(Role::Timestamp))
        }?;
        unimplemented!() // TODO
    }

    fn verify_role<M: SignedMetadata>(&self,
                                      root: &RootMetadata,
                                      role: &Role,
                                      metadata: &M) -> Result<(), TufError> {
        // TODO check M.role == *role

        let role_def = root.roles.get(role).unwrap(); // TODO unwrap
        let keys = role_def.key_ids.iter()
            .map(|id| (id, root.keys.get(id).unwrap())) // TODO unwrap
            // TODO collect instead of fold ?
            .fold(HashMap::new(), |mut map, (id, key)| {
                // TODO check that we don't overwrite ?
                let _ = map.insert(id, key);
                map
            });

        let (valid, errors) =
            Self::verify_signatures(&metadata.signed(), metadata.signatures(), &keys);

        // TODO unwrap
        if valid < root.roles.get(role).unwrap().threshold {
            Err(TufError::ThresholdNotMet(role.clone()))
        } else {
            Ok(()) // TODO more?
        }
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
