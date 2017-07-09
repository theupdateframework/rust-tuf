//! Components needed to verify TUF metadata and targets.

use chrono::offset::Utc;
use std::collections::{HashSet, HashMap};
use std::marker::PhantomData;

use Result;
use crypto::KeyId;
use error::Error;
use interchange::DataInterchange;
use metadata::{SignedMetadata, RootMetadata, TimestampMetadata, Role, SnapshotMetadata,
               MetadataPath, TargetsMetadata, TargetPath, TargetDescription};

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
    pub fn from_root_pinned(
        mut signed_root: SignedMetadata<D, RootMetadata>,
        root_key_ids: &[KeyId],
    ) -> Result<Self> {
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
            root.root().key_ids(),
            root.keys(),
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

    /// Return the list of all available targets.
    pub fn available_targets(&self) -> Result<HashSet<&TargetPath>> {
        let _ = self.safe_root_ref()?; // ensure root still valid
        let _ = self.safe_snapshot_ref()?;
        let targets = self.safe_targets_ref()?
            .targets()
            .keys()
            .collect::<HashSet<&TargetPath>>();

        // TODO delegations

        Ok(targets)
    }

    /// Verify and update the root metadata.
    pub fn update_root(&mut self, signed_root: SignedMetadata<D, RootMetadata>) -> Result<bool> {
        signed_root.verify(
            self.root.root().threshold(),
            self.root.root().key_ids(),
            self.root.keys(),
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
            root.root().key_ids(),
            root.keys(),
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
            self.root.timestamp().key_ids(),
            self.root.keys(),
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
            let snapshot_description = timestamp
                .meta()
                .get(&MetadataPath::from_role(&Role::Snapshot))
                .ok_or_else(|| {
                    Error::VerificationFailure(
                        "Timestamp metadata had no description of the snapshot metadata".into(),
                    )
                })?;

            let current_version = self.snapshot.as_ref().map(|t| t.version()).unwrap_or(0);

            if snapshot_description.version() < current_version {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back snapshot metadata at version {} to {}.",
                    current_version,
                    snapshot_description.version()
                )));
            } else if snapshot_description.version() == current_version {
                return Ok(false);
            }

            signed_snapshot.verify(
                root.snapshot().threshold(),
                root.snapshot().key_ids(),
                root.keys(),
            )?;

            let snapshot: SnapshotMetadata = D::deserialize(&signed_snapshot.signed())?;

            if snapshot.version() != snapshot_description.version() {
                return Err(Error::VerificationFailure(format!(
                    "The timestamp metadata reported that the snapshot metadata should be at \
                    version {} but version {} was found instead.",
                    snapshot_description.version(),
                    snapshot.version()
                )));
            }

            if snapshot.expires() <= &Utc::now() {
                return Err(Error::ExpiredMetadata(Role::Snapshot));
            }

            snapshot
        };

        self.snapshot = Some(snapshot);
        Ok(true)
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
                root.targets().key_ids(),
                root.keys(),
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
                    delegation.key_ids(),
                    parent.keys(),
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

            delegation
        };

        let _ = self.delegations.insert(role.clone(), delegation);
        Ok(true)
    }

    /// Get a reference to the description needed to verify the target defined by the given
    /// `TargetPath`. Returns an `Error` if the target is not defined in the trusted metadata. This
    /// may mean the target exists somewhere in the metadata, but the chain of trust to that target
    /// may be invalid or incomplete.
    pub fn target_description(&self, target_path: &TargetPath) -> Result<&TargetDescription> {
        let _ = self.safe_root_ref()?;
        let _ = self.safe_snapshot_ref()?;
        let targets = self.safe_targets_ref()?;

        targets.targets().get(target_path).ok_or(
            Error::TargetUnavailable,
        )

        // TODO include searching delegations
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
