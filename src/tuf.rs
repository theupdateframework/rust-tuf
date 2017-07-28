//! Components needed to verify TUF metadata and targets.

use chrono::offset::Utc;
use std::collections::{HashSet, HashMap};
use std::marker::PhantomData;

use Result;
use crypto::KeyId;
use error::Error;
use interchange::DataInterchange;
use metadata::{SignedMetadata, RootMetadata, TimestampMetadata, Role, SnapshotMetadata,
               MetadataPath, TargetsMetadata, TargetPath, TargetDescription, Delegations};

/// Contains trusted TUF metadata and can be used to verify other metadata and targets.
#[derive(Debug)]
pub struct Tuf<D: DataInterchange> {
    root: RootMetadata,
    snapshot: Option<SnapshotMetadata>,
    targets: Option<TargetsMetadata>,
    timestamp: Option<TimestampMetadata>,
    delegations: HashMap<MetadataPath, TargetsMetadata>,
    _interchange: PhantomData<D>,
}

impl<D: DataInterchange> Tuf<D> {
    /// Create a new `TUF` struct from a known set of pinned root keys that are used to verify the
    /// signed metadata.
    pub fn from_root_pinned<'a, I>(
        mut signed_root: SignedMetadata<D, RootMetadata>,
        root_key_ids: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = &'a KeyId>,
    {
        let root_key_ids = root_key_ids.into_iter().collect::<HashSet<&KeyId>>();

        signed_root.signatures_mut().retain(|s| {
            root_key_ids.contains(s.key_id())
        });
        Self::from_root(signed_root)
    }

    /// Create a new `TUF` struct from a piece of metadata that is assumed to be trusted.
    ///
    /// **WARNING**: This is trust-on-first-use (TOFU) and offers weaker security guarantees than
    /// the related method `from_root_pinned`.
    pub fn from_root(signed_root: SignedMetadata<D, RootMetadata>) -> Result<Self> {
        let root = D::deserialize::<RootMetadata>(signed_root.signed())?;
        let _ = signed_root.verify(
            root.root().threshold(),
            root.keys().iter().filter_map(
                |(k, v)| if root.root()
                    .key_ids()
                    .contains(k)
                {
                    Some(v)
                } else {
                    None
                },
            ),
        )?;
        Ok(Tuf {
            root: root,
            snapshot: None,
            targets: None,
            timestamp: None,
            delegations: HashMap::new(),
            _interchange: PhantomData,
        })
    }

    /// An immutable reference to the root metadata.
    pub fn root(&self) -> &RootMetadata {
        &self.root
    }

    /// An immutable reference to the optional snapshot metadata.
    pub fn snapshot(&self) -> Option<&SnapshotMetadata> {
        self.snapshot.as_ref()
    }

    /// An immutable reference to the optional targets metadata.
    pub fn targets(&self) -> Option<&TargetsMetadata> {
        self.targets.as_ref()
    }

    /// An immutable reference to the optional timestamp metadata.
    pub fn timestamp(&self) -> Option<&TimestampMetadata> {
        self.timestamp.as_ref()
    }

    /// An immutable reference to the delegated metadata.
    pub fn delegations(&self) -> &HashMap<MetadataPath, TargetsMetadata> {
        &self.delegations
    }

    /// Verify and update the root metadata.
    pub fn update_root(&mut self, signed_root: SignedMetadata<D, RootMetadata>) -> Result<bool> {
        signed_root.verify(
            self.root.root().threshold(),
            self.root.keys().iter().filter_map(|(k, v)| {
                if self.root.root().key_ids().contains(k) {
                    Some(v)
                } else {
                    None
                }
            }),
        )?;

        let root = D::deserialize::<RootMetadata>(signed_root.signed())?;

        match root.version() {
            x if x == self.root.version() => {
                info!(
                    "Attempted to update root to new metadata with the same version. \
                      Refusing to update."
                );
                return Ok(false);
            }
            x if x < self.root.version() => {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back root metadata at version {} to {}.",
                    self.root.version(),
                    x
                )))
            }
            _ => (),
        }

        let _ = signed_root.verify(
            root.root().threshold(),
            root.keys().iter().filter_map(
                |(k, v)| if root.root()
                    .key_ids()
                    .contains(k)
                {
                    Some(v)
                } else {
                    None
                },
            ),
        )?;

        self.purge_metadata();

        self.root = root;
        Ok(true)
    }

    /// Verify and update the timestamp metadata.
    pub fn update_timestamp(
        &mut self,
        signed_timestamp: SignedMetadata<D, TimestampMetadata>,
    ) -> Result<bool> {
        signed_timestamp.verify(
            self.root.timestamp().threshold(),
            self.root.keys().iter().filter_map(
                |(k, v)| {
                    if self.root.timestamp().key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                },
            ),
        )?;

        let current_version = self.timestamp.as_ref().map(|t| t.version()).unwrap_or(0);
        let timestamp: TimestampMetadata = D::deserialize(&signed_timestamp.signed())?;

        if timestamp.expires() <= &Utc::now() {
            return Err(Error::ExpiredMetadata(Role::Timestamp));
        }

        if timestamp.version() < current_version {
            Err(Error::VerificationFailure(format!(
                "Attempted to roll back timestamp metadata at version {} to {}.",
                current_version,
                timestamp.version()
            )))
        } else if timestamp.version() == current_version {
            Ok(false)
        } else {
            if self.snapshot.as_ref().map(|s| s.version()).unwrap_or(0) != timestamp.snapshot().version() {
                self.snapshot = None;
            }

            self.timestamp = Some(timestamp);

            Ok(true)
        }
    }

    /// Verify and update the snapshot metadata.
    pub fn update_snapshot(
        &mut self,
        signed_snapshot: SignedMetadata<D, SnapshotMetadata>,
    ) -> Result<bool> {
        let snapshot = {
            let root = self.safe_root_ref()?;
            let timestamp = self.safe_timestamp_ref()?;
            let current_version = self.snapshot.as_ref().map(|t| t.version()).unwrap_or(0);

            if timestamp.snapshot().version() < current_version {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back snapshot metadata at version {} to {}.",
                    current_version,
                    timestamp.snapshot().version()
                )));
            } else if timestamp.snapshot().version() == current_version {
                return Ok(false);
            }

            signed_snapshot.verify(
                root.snapshot().threshold(),
                self.root.keys().iter().filter_map(
                    |(k, v)| {
                        if root.snapshot().key_ids().contains(k) {
                            Some(v)
                        } else {
                            None
                        }
                    },
                ),
            )?;

            let snapshot: SnapshotMetadata = D::deserialize(&signed_snapshot.signed())?;

            if snapshot.version() != timestamp.snapshot().version() {
                return Err(Error::VerificationFailure(format!(
                    "The timestamp metadata reported that the snapshot metadata should be at \
                    version {} but version {} was found instead.",
                    timestamp.snapshot().version(),
                    snapshot.version()
                )));
            }

            // Note: this doesn't check the expiration because we need to be able to update it
            // regardless so we can prevent rollback attacks againsts targets/delegations.

            snapshot
        };

        if self.targets.as_ref().map(|s| s.version()).unwrap_or(0) != snapshot.meta().get(&MetadataPath::from_role(&Role::Targets)).map(|m| m.version()).unwrap_or(0) {
            self.targets = None;
        }

        self.snapshot = Some(snapshot);
        self.purge_delegations();
        Ok(true)

    }

    fn purge_delegations(&mut self) {
        let purge = {
            let snapshot = match self.snapshot() {
                Some(s) => s,
                None => return,
            };
            let mut purge = HashSet::new();
            for (role, definition) in snapshot.meta().iter() {
                let delegation = match self.delegations.get(role) {
                    Some(d) => d,
                    None => continue,
                };

                if delegation.version() > definition.version() {
                    let _ = purge.insert(role.clone());
                    continue;
                }
            }

            purge
        };

        for role in purge.iter() {
            let _ = self.delegations.remove(role);
        }
    }

    /// Verify and update the targets metadata.
    pub fn update_targets(
        &mut self,
        signed_targets: SignedMetadata<D, TargetsMetadata>,
    ) -> Result<bool> {
        let targets = {
            let root = self.safe_root_ref()?;
            let snapshot = self.safe_snapshot_ref()?;
            let targets_description = snapshot
                .meta()
                .get(&MetadataPath::from_role(&Role::Targets))
                .ok_or_else(|| {
                    Error::VerificationFailure(
                        "Snapshot metadata had no description of the targets metadata".into(),
                    )
                })?;

            let current_version = self.targets.as_ref().map(|t| t.version()).unwrap_or(0);

            if targets_description.version() < current_version {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back targets metadata at version {} to {}.",
                    current_version,
                    targets_description.version()
                )));
            } else if targets_description.version() == current_version {
                return Ok(false);
            }

            signed_targets.verify(
                root.targets().threshold(),
                root.keys().iter().filter_map(|(k, v)| {
                    if root.targets().key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                }),
            )?;

            let targets: TargetsMetadata = D::deserialize(&signed_targets.signed())?;

            if targets.version() != targets_description.version() {
                return Err(Error::VerificationFailure(format!(
                    "The timestamp metadata reported that the targets metadata should be at \
                    version {} but version {} was found instead.",
                    targets_description.version(),
                    targets.version()
                )));
            }

            if targets.expires() <= &Utc::now() {
                return Err(Error::ExpiredMetadata(Role::Snapshot));
            }
            targets
        };

        self.targets = Some(targets);
        Ok(true)
    }

    /// Verify and update a delegation metadata.
    pub fn update_delegation(
        &mut self,
        role: &MetadataPath,
        signed: SignedMetadata<D, TargetsMetadata>,
    ) -> Result<bool> {
        let delegation = {
            let _ = self.safe_root_ref()?;
            let snapshot = self.safe_snapshot_ref()?;
            let targets = self.safe_targets_ref()?;
            let targets_delegations = match targets.delegations() {
                Some(d) => d,
                None => {
                    return Err(Error::VerificationFailure(
                        "Delegations not authorized".into(),
                    ))
                }
            };

            let delegation_description = match snapshot.meta().get(role) {
                Some(d) => d,
                None => {
                    return Err(Error::VerificationFailure(format!(
                        "The degated role {:?} was not present in the snapshot metadata.",
                        role
                    )))
                }
            };

            let current_version = self.delegations.get(role).map(|t| t.version()).unwrap_or(0);
            if delegation_description.version() < current_version {
                return Err(Error::VerificationFailure(format!(
                    "Snapshot metadata did listed delegation {:?} version as {} but current\
                    version is {}",
                    role,
                    delegation_description.version(),
                    current_version
                )));
            } else if current_version == delegation_description.version() {
                return Ok(false);
            }

            for (_, delegated_targets) in self.delegations.iter() {
                let parent = match delegated_targets.delegations() {
                    Some(d) => d,
                    None => &targets_delegations,
                };

                let delegation = match parent.roles().iter().filter(|r| r.role() == role).next() {
                    Some(d) => d,
                    None => continue,
                };

                signed.verify(
                    delegation.threshold(),
                    parent.keys().iter().filter_map(
                        |(k, v)| if delegation
                            .key_ids()
                            .contains(k)
                        {
                            Some(v)
                        } else {
                            None
                        },
                    ),
                )?;
            }

            let delegation: TargetsMetadata = D::deserialize(signed.signed())?;
            if delegation.version() != delegation_description.version() {
                return Err(Error::VerificationFailure(format!(
                    "The snapshot metadata reported that the delegation {:?} should be at \
                    version {} but version {} was found instead.",
                    role,
                    delegation_description.version(),
                    delegation.version(),
                    )));
            }

            if delegation.expires() <= &Utc::now() {
                // TODO this needs to be chagned to accept a MetadataPath and not Role
                return Err(Error::ExpiredMetadata(Role::Targets));
            }

            delegation
        };

        let _ = self.delegations.insert(role.clone(), delegation);
        Ok(true)
    }

    /// Get a reference to the description needed to verify the target defined by the given
    /// `TargetPath`. Returns an `Error` if the target is not defined in the trusted metadata. This
    /// may mean the target exists somewhere in the metadata, but the chain of trust to that target
    /// may be invalid or incomplete.
    pub fn target_description(&self, target_path: &TargetPath) -> Result<TargetDescription> {
        let _ = self.safe_root_ref()?;
        let _ = self.safe_snapshot_ref()?;
        let targets = self.safe_targets_ref()?;

        match targets.targets().get(target_path) {
            Some(d) => return Ok(d.clone()),
            None => (),
        }

        fn lookup<D: DataInterchange>(
            tuf: &Tuf<D>,
            default_terminate: bool,
            current_depth: u32,
            target_path: &TargetPath,
            delegations: &Delegations,
            parents: Vec<HashSet<TargetPath>>,
            visited: &mut HashSet<MetadataPath>,
        ) -> (bool, Option<TargetDescription>) {
            for delegation in delegations.roles() {
                if visited.contains(delegation.role()) {
                    return (delegation.terminating(), None);
                }
                let _ = visited.insert(delegation.role().clone());

                let mut new_parents = parents.clone();
                new_parents.push(delegation.paths().clone());

                if current_depth > 0 && !target_path.matches_chain(&parents) {
                    return (delegation.terminating(), None);
                }

                let targets = match tuf.delegations.get(delegation.role()) {
                    Some(t) => t,
                    None => return (delegation.terminating(), None),
                };

                if targets.expires() <= &Utc::now() {
                    return (delegation.terminating(), None);
                }

                if let Some(d) = targets.targets().get(target_path) {
                    return (delegation.terminating(), Some(d.clone()));
                }

                if let Some(d) = targets.delegations() {
                    let mut new_parents = parents.to_vec();
                    new_parents.push(delegation.paths().clone());
                    let (term, res) = lookup(
                        tuf,
                        delegation.terminating(),
                        current_depth + 1,
                        target_path,
                        d,
                        new_parents,
                        visited,
                    );
                    if term {
                        return (true, res);
                    } else if res.is_some() {
                        return (term, res);
                    }
                }
            }
            (default_terminate, None)
        }

        match targets.delegations() {
            Some(d) => {
                let mut visited = HashSet::new();
                lookup(self, false, 0, target_path, d, vec![], &mut visited)
                    .1
                    .ok_or_else(|| Error::TargetUnavailable)
            }
            None => Err(Error::TargetUnavailable),
        }
    }

    fn purge_metadata(&mut self) {
        self.snapshot = None;
        self.targets = None;
        self.timestamp = None;
        self.delegations.clear();
    }

    fn safe_root_ref(&self) -> Result<&RootMetadata> {
        if self.root.expires() <= &Utc::now() {
            return Err(Error::ExpiredMetadata(Role::Root));
        }
        Ok(&self.root)
    }

    fn safe_snapshot_ref(&self) -> Result<&SnapshotMetadata> {
        match &self.snapshot {
            &Some(ref snapshot) => {
                if snapshot.expires() <= &Utc::now() {
                    return Err(Error::ExpiredMetadata(Role::Snapshot));
                }
                Ok(snapshot)
            }
            &None => Err(Error::MissingMetadata(Role::Snapshot)),
        }
    }

    fn safe_targets_ref(&self) -> Result<&TargetsMetadata> {
        match &self.targets {
            &Some(ref targets) => {
                if targets.expires() <= &Utc::now() {
                    return Err(Error::ExpiredMetadata(Role::Targets));
                }
                Ok(targets)
            }
            &None => Err(Error::MissingMetadata(Role::Targets)),
        }
    }
    fn safe_timestamp_ref(&self) -> Result<&TimestampMetadata> {
        match &self.timestamp {
            &Some(ref timestamp) => {
                if timestamp.expires() <= &Utc::now() {
                    return Err(Error::ExpiredMetadata(Role::Timestamp));
                }
                Ok(timestamp)
            }
            &None => Err(Error::MissingMetadata(Role::Timestamp)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    use interchange::JsonDataInterchange;
    use metadata::{RoleDefinition, MetadataDescription};

    lazy_static! {
        static ref KEYS: Vec<PrivateKey> = {
            let keys: &[&[u8]] = &[
                include_bytes!("../tests/ed25519/ed25519-1.pk8.der"),
                include_bytes!("../tests/ed25519/ed25519-2.pk8.der"),
                include_bytes!("../tests/ed25519/ed25519-3.pk8.der"),
                include_bytes!("../tests/ed25519/ed25519-4.pk8.der"),
                include_bytes!("../tests/ed25519/ed25519-5.pk8.der"),
                include_bytes!("../tests/ed25519/ed25519-6.pk8.der"),
            ];
            keys.iter().map(|b| PrivateKey::from_pkcs8(b).unwrap()).collect()
        };
    }

    #[test]
    fn root_pinned_success() {
        let root_key = &KEYS[0];
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![KEYS[0].public().clone()],
            RoleDefinition::new(1, hashset!(root_key.key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &root_key, SignatureScheme::Ed25519).unwrap();

        assert!(Tuf::from_root_pinned(root, &[root_key.key_id().clone()]).is_ok());
    }

    #[test]
    fn root_pinned_failure() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![KEYS[0].public().clone()],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        assert!(Tuf::from_root_pinned(root, &[KEYS[1].key_id().clone()]).is_err());
    }

    #[test]
    fn good_root_rotation() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![KEYS[0].public().clone()],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let root = RootMetadata::new(
            2,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![KEYS[1].public().clone()],
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
        ).unwrap();
        let mut root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[1], SignatureScheme::Ed25519).unwrap();

        // add the original key's signature to make it cross signed
        root.add_signature(&KEYS[0], SignatureScheme::Ed25519)
            .unwrap();

        assert_eq!(tuf.update_root(root.clone()), Ok(true));

        // second update should do nothing
        assert_eq!(tuf.update_root(root), Ok(false));
    }

    #[test]
    fn no_cross_sign_root_rotation() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![KEYS[0].public().clone()],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let root = RootMetadata::new(
            2,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            // include the old key to prevent short circuiting the verify logic
            vec![KEYS[0].public().clone(), KEYS[1].public().clone()],
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[1], SignatureScheme::Ed25519).unwrap();

        assert!(tuf.update_root(root).is_err());
    }

    #[test]
    fn good_timestamp_update() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![KEYS[0].public().clone(), KEYS[1].public().clone()],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();
        let timestamp: SignedMetadata<JsonDataInterchange, TimestampMetadata> =
            SignedMetadata::new(&timestamp, &KEYS[1], SignatureScheme::Ed25519).unwrap();

        assert_eq!(tuf.update_timestamp(timestamp.clone()), Ok(true));

        // second update should do nothing
        assert_eq!(tuf.update_timestamp(timestamp), Ok(false))
    }

    #[test]
    fn bad_timestamp_update_wrong_key() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![KEYS[0].public().clone(), KEYS[1].public().clone()],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();

        // sign it with the root key
        let timestamp: SignedMetadata<JsonDataInterchange, TimestampMetadata> =
            SignedMetadata::new(&timestamp, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        assert!(tuf.update_timestamp(timestamp).is_err())
    }

    #[test]
    fn good_snapshot_update() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![
                KEYS[0].public().clone(),
                KEYS[1].public().clone(),
                KEYS[2].public().clone(),
            ],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();
        let timestamp: SignedMetadata<JsonDataInterchange, TimestampMetadata> =
            SignedMetadata::new(&timestamp, &KEYS[2], SignatureScheme::Ed25519).unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!())
            .unwrap();
        let snapshot: SignedMetadata<JsonDataInterchange, SnapshotMetadata> =
            SignedMetadata::new(&snapshot, &KEYS[1], SignatureScheme::Ed25519).unwrap();

        assert_eq!(tuf.update_snapshot(snapshot.clone()), Ok(true));

        // second update should do nothing
        assert_eq!(tuf.update_snapshot(snapshot), Ok(false));
    }

    #[test]
    fn bad_snapshot_update_wrong_key() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![
                KEYS[0].public().clone(),
                KEYS[1].public().clone(),
                KEYS[2].public().clone(),
            ],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();
        let timestamp: SignedMetadata<JsonDataInterchange, TimestampMetadata> =
            SignedMetadata::new(&timestamp, &KEYS[2], SignatureScheme::Ed25519).unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!())
            .unwrap();
        let snapshot: SignedMetadata<JsonDataInterchange, SnapshotMetadata> =
            SignedMetadata::new(&snapshot, &KEYS[2], SignatureScheme::Ed25519).unwrap();

        assert!(tuf.update_snapshot(snapshot.clone()).is_err());
    }

    #[test]
    fn bad_snapshot_update_wrong_version() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![
                KEYS[0].public().clone(),
                KEYS[1].public().clone(),
                KEYS[2].public().clone(),
            ],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 2, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();
        let timestamp: SignedMetadata<JsonDataInterchange, TimestampMetadata> =
            SignedMetadata::new(&timestamp, &KEYS[2], SignatureScheme::Ed25519).unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!())
            .unwrap();
        let snapshot: SignedMetadata<JsonDataInterchange, SnapshotMetadata> =
            SignedMetadata::new(&snapshot, &KEYS[1], SignatureScheme::Ed25519).unwrap();

        assert!(tuf.update_snapshot(snapshot).is_err());
    }

    #[test]
    fn good_targets_update() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![
                KEYS[0].public().clone(),
                KEYS[1].public().clone(),
                KEYS[2].public().clone(),
                KEYS[3].public().clone(),
            ],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[3].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();
        let timestamp: SignedMetadata<JsonDataInterchange, TimestampMetadata> =
            SignedMetadata::new(&timestamp, &KEYS[3], SignatureScheme::Ed25519).unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        let meta_map =
            hashmap!(
            MetadataPath::from_role(&Role::Targets) =>
                MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256]).unwrap(),
        );
        let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map)
            .unwrap();
        let snapshot: SignedMetadata<JsonDataInterchange, SnapshotMetadata> =
            SignedMetadata::new(&snapshot, &KEYS[1], SignatureScheme::Ed25519).unwrap();

        tuf.update_snapshot(snapshot).unwrap();

        let targets =
            TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!(), None)
                .unwrap();
        let targets: SignedMetadata<JsonDataInterchange, TargetsMetadata> =
            SignedMetadata::new(&targets, &KEYS[2], SignatureScheme::Ed25519).unwrap();

        assert_eq!(tuf.update_targets(targets.clone()), Ok(true));

        // second update should do nothing
        assert_eq!(tuf.update_targets(targets), Ok(false));
    }

    #[test]
    fn bad_targets_update_wrong_key() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![
                KEYS[0].public().clone(),
                KEYS[1].public().clone(),
                KEYS[2].public().clone(),
                KEYS[3].public().clone(),
            ],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[3].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();
        let timestamp: SignedMetadata<JsonDataInterchange, TimestampMetadata> =
            SignedMetadata::new(&timestamp, &KEYS[3], SignatureScheme::Ed25519).unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        let meta_map =
            hashmap!(
            MetadataPath::from_role(&Role::Targets) =>
                MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256]).unwrap(),
        );
        let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map)
            .unwrap();
        let snapshot: SignedMetadata<JsonDataInterchange, SnapshotMetadata> =
            SignedMetadata::new(&snapshot, &KEYS[1], SignatureScheme::Ed25519).unwrap();

        tuf.update_snapshot(snapshot).unwrap();

        let targets =
            TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!(), None)
                .unwrap();
        let targets: SignedMetadata<JsonDataInterchange, TargetsMetadata> =
            SignedMetadata::new(&targets, &KEYS[3], SignatureScheme::Ed25519).unwrap();

        assert!(tuf.update_targets(targets).is_err());
    }

    #[test]
    fn bad_targets_update_wrong_version() {
        let root = RootMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![
                KEYS[0].public().clone(),
                KEYS[1].public().clone(),
                KEYS[2].public().clone(),
                KEYS[3].public().clone(),
            ],
            RoleDefinition::new(1, hashset!(KEYS[0].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[1].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[3].key_id().clone())).unwrap(),
        ).unwrap();
        let root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0], SignatureScheme::Ed25519).unwrap();

        let mut tuf = Tuf::from_root(root).unwrap();

        let timestamp = TimestampMetadata::new(
            1,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            MetadataDescription::from_reader(&*vec![], 1, &[HashAlgorithm::Sha256])
                .unwrap(),
        ).unwrap();
        let timestamp: SignedMetadata<JsonDataInterchange, TimestampMetadata> =
            SignedMetadata::new(&timestamp, &KEYS[3], SignatureScheme::Ed25519).unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        let meta_map =
            hashmap!(
            MetadataPath::from_role(&Role::Targets) =>
                MetadataDescription::from_reader(&*vec![], 2, &[HashAlgorithm::Sha256]).unwrap(),
        );
        let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map)
            .unwrap();
        let snapshot: SignedMetadata<JsonDataInterchange, SnapshotMetadata> =
            SignedMetadata::new(&snapshot, &KEYS[1], SignatureScheme::Ed25519).unwrap();

        tuf.update_snapshot(snapshot).unwrap();

        let targets =
            TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!(), None)
                .unwrap();
        let targets: SignedMetadata<JsonDataInterchange, TargetsMetadata> =
            SignedMetadata::new(&targets, &KEYS[2], SignatureScheme::Ed25519).unwrap();

        assert!(tuf.update_targets(targets).is_err());
    }
}
