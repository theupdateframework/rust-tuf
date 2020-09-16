//! Components needed to verify TUF metadata and targets.

use chrono::offset::Utc;
use log::info;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use crate::crypto::PublicKey;
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{
    Delegations, Metadata, MetadataPath, Role, RootMetadata, SignedMetadata, SnapshotMetadata,
    TargetDescription, TargetsMetadata, TimestampMetadata, VirtualTargetPath,
};
use crate::Result;

/// Contains trusted TUF metadata and can be used to verify other metadata and targets.
#[derive(Debug)]
pub struct Tuf<D: DataInterchange> {
    trusted_root: RootMetadata,
    trusted_snapshot: Option<SnapshotMetadata>,
    trusted_targets: Option<TargetsMetadata>,
    trusted_timestamp: Option<TimestampMetadata>,
    trusted_delegations: HashMap<MetadataPath, TargetsMetadata>,
    interchange: PhantomData<D>,
}

impl<D: DataInterchange> Tuf<D> {
    /// Create a new [`Tuf`] struct from a set of trusted root keys that are used to verify the
    /// signed metadata. The signed root metadata must be signed with at least a `root_threshold`
    /// of the provided root_keys. It is not necessary for the root metadata to contain these keys.
    pub fn from_root_with_trusted_keys<'a, I>(
        signed_root: SignedMetadata<D, RootMetadata>,
        root_threshold: u32,
        root_keys: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        signed_root.verify(root_threshold, root_keys)?;
        Self::from_trusted_root(signed_root)
    }

    /// Create a new [`Tuf`] struct from a piece of metadata that is assumed to be trusted.
    ///
    /// **WARNING**: This is trust-on-first-use (TOFU) and offers weaker security guarantees than
    /// the related method [`Tuf::from_root_with_trusted_keys`].
    pub fn from_trusted_root(signed_root: SignedMetadata<D, RootMetadata>) -> Result<Self> {
        let verified = {
            let root = signed_root.assume_valid()?;

            signed_root.verify(
                root.root().threshold(),
                root.keys().iter().filter_map(|(k, v)| {
                    if root.root().key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                }),
            )?
        };

        Ok(Tuf {
            trusted_root: verified,
            trusted_snapshot: None,
            trusted_targets: None,
            trusted_timestamp: None,
            trusted_delegations: HashMap::new(),
            interchange: PhantomData,
        })
    }

    /// An immutable reference to the root metadata.
    pub fn trusted_root(&self) -> &RootMetadata {
        &self.trusted_root
    }

    /// An immutable reference to the optional snapshot metadata.
    pub fn trusted_snapshot(&self) -> Option<&SnapshotMetadata> {
        self.trusted_snapshot.as_ref()
    }

    /// An immutable reference to the optional targets metadata.
    pub fn trusted_targets(&self) -> Option<&TargetsMetadata> {
        self.trusted_targets.as_ref()
    }

    /// An immutable reference to the optional timestamp metadata.
    pub fn trusted_timestamp(&self) -> Option<&TimestampMetadata> {
        self.trusted_timestamp.as_ref()
    }

    /// An immutable reference to the delegated metadata.
    pub fn trusted_delegations(&self) -> &HashMap<MetadataPath, TargetsMetadata> {
        &self.trusted_delegations
    }

    fn trusted_timestamp_version(&self) -> u32 {
        self.trusted_timestamp
            .as_ref()
            .map(|t| t.version())
            .unwrap_or(0)
    }

    fn trusted_snapshot_version(&self) -> u32 {
        self.trusted_snapshot
            .as_ref()
            .map(|t| t.version())
            .unwrap_or(0)
    }

    fn trusted_targets_version(&self) -> u32 {
        self.trusted_targets
            .as_ref()
            .map(|t| t.version())
            .unwrap_or(0)
    }

    fn trusted_delegation_version(&self, role: &MetadataPath) -> u32 {
        self.trusted_delegations
            .get(role)
            .map(|t| t.version())
            .unwrap_or(0)
    }

    /// Verify and update the root metadata.
    pub fn update_root(&mut self, signed_root: SignedMetadata<D, RootMetadata>) -> Result<bool> {
        let verified = {
            let trusted_root = &self.trusted_root;

            // First, check that the new root was signed by the old root.
            let new_root = signed_root.verify(
                trusted_root.root().threshold(),
                trusted_root.keys().iter().filter_map(|(k, v)| {
                    if trusted_root.root().key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                }),
            )?;

            // Next, make sure the new root has a higher version than the old root.
            if new_root.version() == trusted_root.version() {
                info!(
                    "Attempted to update root to new metadata with the same version. \
                     Refusing to update."
                );
                return Ok(false);
            } else if new_root.version() < trusted_root.version() {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back root metadata at version {} to {}.",
                    trusted_root.version(),
                    new_root.version()
                )));
            }

            // Finally, make sure the new root was signed by the keys in the new root.
            signed_root.verify(
                new_root.root().threshold(),
                new_root.keys().iter().filter_map(|(k, v)| {
                    if new_root.root().key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                }),
            )?
        };

        self.purge_metadata();

        self.trusted_root = verified;
        Ok(true)
    }

    /// Verify and update the timestamp metadata.
    ///
    /// Returns a reference to the parsed metadata if the metadata was newer.
    pub fn update_timestamp(
        &mut self,
        signed_timestamp: SignedMetadata<D, TimestampMetadata>,
    ) -> Result<Option<&TimestampMetadata>> {
        let verified = {
            // FIXME(https://github.com/theupdateframework/specification/issues/113) Should we
            // check if the root metadata is expired here? We do that in the other `Tuf::update_*`
            // methods, but not here.
            let trusted_root = &self.trusted_root;

            // First, make sure the root signed the metadata.
            let new_timestamp = signed_timestamp.verify(
                trusted_root.timestamp().threshold(),
                trusted_root.keys().iter().filter_map(|(k, v)| {
                    if trusted_root.timestamp().key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                }),
            )?;

            // Next, make sure the timestamp hasn't expired.
            if new_timestamp.expires() <= &Utc::now() {
                return Err(Error::ExpiredMetadata(Role::Timestamp));
            }

            // Next, make sure the new metadata has a higher version than the old metadata.
            let trusted_timestamp_version = self.trusted_timestamp_version();

            if new_timestamp.version() < trusted_timestamp_version {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back timestamp metadata at version {} to {}.",
                    trusted_timestamp_version,
                    new_timestamp.version()
                )));
            } else if new_timestamp.version() == trusted_timestamp_version {
                return Ok(None);
            }

            if self.trusted_snapshot_version() != new_timestamp.snapshot().version() {
                self.trusted_snapshot = None;
            }

            new_timestamp
        };

        self.trusted_timestamp = Some(verified);
        Ok(self.trusted_timestamp.as_ref())
    }

    /// Verify and update the snapshot metadata.
    pub fn update_snapshot(
        &mut self,
        signed_snapshot: SignedMetadata<D, SnapshotMetadata>,
    ) -> Result<bool> {
        let verified = {
            // FIXME(https://github.com/theupdateframework/specification/issues/113) Checking if
            // this metadata expired isn't part of the spec. Do we actually want to do this?
            let trusted_root = self.trusted_root_unexpired()?;
            let trusted_timestamp = self.trusted_timestamp_unexpired()?;
            let trusted_snapshot_version = self.trusted_snapshot_version();

            if trusted_timestamp.snapshot().version() < trusted_snapshot_version {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back snapshot metadata at version {} to {}.",
                    trusted_snapshot_version,
                    trusted_timestamp.snapshot().version()
                )));
            } else if trusted_timestamp.snapshot().version() == trusted_snapshot_version {
                return Ok(false);
            }

            let new_snapshot = signed_snapshot.verify(
                trusted_root.snapshot().threshold(),
                trusted_root.keys().iter().filter_map(|(k, v)| {
                    if trusted_root.snapshot().key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                }),
            )?;

            if new_snapshot.version() != trusted_timestamp.snapshot().version() {
                return Err(Error::VerificationFailure(format!(
                    "The timestamp metadata reported that the snapshot metadata should be at \
                     version {} but version {} was found instead.",
                    trusted_timestamp.snapshot().version(),
                    new_snapshot.version()
                )));
            }

            // Note: this doesn't check the expiration because we need to be able to update it
            // regardless so we can prevent rollback attacks againsts targets/delegations.
            new_snapshot
        };

        if self
            .trusted_targets
            .as_ref()
            .map(|s| s.version())
            .unwrap_or(0)
            != verified
                .meta()
                .get(&MetadataPath::from_role(&Role::Targets))
                .map(|m| m.version())
                .unwrap_or(0)
        {
            self.trusted_targets = None;
        }

        self.trusted_snapshot = Some(verified);
        self.purge_delegations();
        Ok(true)
    }

    fn purge_delegations(&mut self) {
        let purge = {
            let trusted_snapshot = match self.trusted_snapshot() {
                Some(s) => s,
                None => return,
            };
            let mut purge = HashSet::new();
            for (role, trusted_definition) in trusted_snapshot.meta().iter() {
                let trusted_delegation = match self.trusted_delegations.get(role) {
                    Some(d) => d,
                    None => continue,
                };

                if trusted_delegation.version() > trusted_definition.version() {
                    let _ = purge.insert(role.clone());
                    continue;
                }
            }

            purge
        };

        for role in &purge {
            let _ = self.trusted_delegations.remove(role);
        }
    }

    /// Verify and update the targets metadata.
    pub fn update_targets(
        &mut self,
        signed_targets: SignedMetadata<D, TargetsMetadata>,
    ) -> Result<bool> {
        let verified = {
            // FIXME(https://github.com/theupdateframework/specification/issues/113) Checking if
            // this metadata expired isn't part of the spec. Do we actually want to do this?
            let trusted_root = self.trusted_root_unexpired()?;
            let trusted_snapshot = self.trusted_snapshot_unexpired()?;

            let trusted_targets_description = trusted_snapshot
                .meta()
                .get(&MetadataPath::from_role(&Role::Targets))
                .ok_or_else(|| {
                    Error::VerificationFailure(
                        "Snapshot metadata had no description of the targets metadata".into(),
                    )
                })?;

            let trusted_targets_version = self.trusted_targets_version();

            if trusted_targets_description.version() < trusted_targets_version {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back targets metadata at version {} to {}.",
                    trusted_targets_version,
                    trusted_targets_description.version()
                )));
            } else if trusted_targets_description.version() == trusted_targets_version {
                return Ok(false);
            }

            let new_targets = signed_targets.verify(
                trusted_root.targets().threshold(),
                trusted_root.keys().iter().filter_map(|(k, v)| {
                    if trusted_root.targets().key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                }),
            )?;

            if new_targets.version() != trusted_targets_description.version() {
                return Err(Error::VerificationFailure(format!(
                    "The timestamp metadata reported that the targets metadata should be at \
                     version {} but version {} was found instead.",
                    trusted_targets_description.version(),
                    new_targets.version()
                )));
            }

            if new_targets.expires() <= &Utc::now() {
                return Err(Error::ExpiredMetadata(Role::Snapshot));
            }

            new_targets
        };

        self.trusted_targets = Some(verified);
        Ok(true)
    }

    /// Find the signing keys and metadata for the delegation given by `role`, as seen from the
    /// point of view of `parent_role`.
    fn find_delegation_threshold_and_keys(
        &self,
        parent_role: &MetadataPath,
        role: &MetadataPath,
    ) -> Option<(u32, Vec<&PublicKey>)> {
        // Find the parent TargetsMetadata that is expected to refer to `role`.
        let trusted_parent = {
            if parent_role == &MetadataPath::from_role(&Role::Targets) {
                if let Some(trusted_targets) = self.trusted_targets() {
                    trusted_targets
                } else {
                    return None;
                }
            } else {
                if let Some(trusted_delegation) = self.trusted_delegations.get(parent_role) {
                    trusted_delegation
                } else {
                    return None;
                }
            }
        };

        // Only consider targets metadata that define delegations.
        let trusted_delegations = match trusted_parent.delegations() {
            Some(d) => d,
            None => return None,
        };

        for trusted_delegation in trusted_delegations.roles() {
            if trusted_delegation.role() != role {
                continue;
            }

            // Filter the delegations keys to just the ones for this delegation.
            let authorized_keys = trusted_delegations
                .keys()
                .iter()
                .filter_map(|(k, v)| {
                    if trusted_delegation.key_ids().contains(k) {
                        Some(v)
                    } else {
                        None
                    }
                })
                .collect();

            return Some((trusted_delegation.threshold(), authorized_keys));
        }

        None
    }

    /// Verify and update a delegation metadata.
    pub fn update_delegation(
        &mut self,
        parent_role: &MetadataPath,
        role: &MetadataPath,
        signed_delegation: SignedMetadata<D, TargetsMetadata>,
    ) -> Result<bool> {
        let verified = {
            // FIXME(https://github.com/theupdateframework/specification/issues/113) Checking if
            // this metadata expired isn't part of the spec. Do we actually want to do this?
            let _ = self.trusted_root_unexpired()?;
            let trusted_snapshot = self.trusted_snapshot_unexpired()?;
            let trusted_targets = self.trusted_targets_unexpired()?;

            if trusted_targets.delegations().is_none() {
                return Err(Error::VerificationFailure(
                    "Delegations not authorized".into(),
                ));
            };

            let trusted_delegation_description = match trusted_snapshot.meta().get(role) {
                Some(d) => d,
                None => {
                    return Err(Error::VerificationFailure(format!(
                        "The degated role {:?} was not present in the snapshot metadata.",
                        role
                    )));
                }
            };

            let trusted_delegation_version = self.trusted_delegation_version(role);

            if trusted_delegation_description.version() < trusted_delegation_version {
                return Err(Error::VerificationFailure(format!(
                    "Snapshot metadata did listed delegation {:?} version as {} but current\
                     version is {}",
                    role,
                    trusted_delegation_description.version(),
                    trusted_delegation_version
                )));
            }

            // FIXME(#279) update_delegation trusts tuf::Client to provide too much information,
            // making this difficult to verify as correct.

            let (threshold, keys) = self
                .find_delegation_threshold_and_keys(parent_role, role)
                .ok_or(Error::VerificationFailure(format!(
                    "The delegated role {:?} is not known to the base \
                        targets metadata or any known delegated targets metadata",
                    role
                )))?;

            let new_delegation = signed_delegation.verify(threshold, keys)?;

            if trusted_delegation_version == trusted_delegation_description.version() {
                return Ok(false);
            }

            if new_delegation.version() != trusted_delegation_description.version() {
                return Err(Error::VerificationFailure(format!(
                    "The snapshot metadata reported that the delegation {:?} should be at \
                     version {} but version {} was found instead.",
                    role,
                    trusted_delegation_description.version(),
                    new_delegation.version(),
                )));
            }

            if new_delegation.expires() <= &Utc::now() {
                // TODO this needs to be chagned to accept a MetadataPath and not Role
                return Err(Error::ExpiredMetadata(Role::Targets));
            }

            new_delegation
        };

        let _ = self.trusted_delegations.insert(role.clone(), verified);

        Ok(true)
    }

    /// Get a reference to the description needed to verify the target defined by the given
    /// `VirtualTargetPath`. Returns an `Error` if the target is not defined in the trusted
    /// metadata. This may mean the target exists somewhere in the metadata, but the chain of trust
    /// to that target may be invalid or incomplete.
    pub fn target_description(&self, target_path: &VirtualTargetPath) -> Result<TargetDescription> {
        let _ = self.trusted_root_unexpired()?;
        let _ = self.trusted_snapshot_unexpired()?;
        let targets = self.trusted_targets_unexpired()?;

        if let Some(d) = targets.targets().get(target_path) {
            return Ok(d.clone());
        }

        fn lookup<D: DataInterchange>(
            tuf: &Tuf<D>,
            default_terminate: bool,
            current_depth: u32,
            target_path: &VirtualTargetPath,
            delegations: &Delegations,
            parents: &[HashSet<VirtualTargetPath>],
            visited: &mut HashSet<MetadataPath>,
        ) -> (bool, Option<TargetDescription>) {
            for delegation in delegations.roles() {
                if visited.contains(delegation.role()) {
                    return (delegation.terminating(), None);
                }
                let _ = visited.insert(delegation.role().clone());

                let mut new_parents = parents.to_owned();
                new_parents.push(delegation.paths().clone());

                if current_depth > 0 && !target_path.matches_chain(&parents) {
                    return (delegation.terminating(), None);
                }

                let trusted_delegation = match tuf.trusted_delegations.get(delegation.role()) {
                    Some(trusted_delegation) => trusted_delegation,
                    None => return (delegation.terminating(), None),
                };

                if trusted_delegation.expires() <= &Utc::now() {
                    return (delegation.terminating(), None);
                }

                if let Some(target) = trusted_delegation.targets().get(target_path) {
                    return (delegation.terminating(), Some(target.clone()));
                }

                if let Some(trusted_child_delegation) = trusted_delegation.delegations() {
                    let mut new_parents = parents.to_vec();
                    new_parents.push(delegation.paths().clone());
                    let (term, res) = lookup(
                        tuf,
                        delegation.terminating(),
                        current_depth + 1,
                        target_path,
                        trusted_child_delegation,
                        &new_parents,
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
                lookup(self, false, 0, target_path, d, &[], &mut visited)
                    .1
                    .ok_or_else(|| Error::TargetUnavailable)
            }
            None => Err(Error::TargetUnavailable),
        }
    }

    fn purge_metadata(&mut self) {
        self.trusted_snapshot = None;
        self.trusted_targets = None;
        self.trusted_timestamp = None;
        self.trusted_delegations.clear();
    }

    fn trusted_root_unexpired(&self) -> Result<&RootMetadata> {
        let trusted_root = &self.trusted_root;
        if trusted_root.expires() <= &Utc::now() {
            return Err(Error::ExpiredMetadata(Role::Root));
        }
        Ok(&trusted_root)
    }

    fn trusted_snapshot_unexpired(&self) -> Result<&SnapshotMetadata> {
        match self.trusted_snapshot {
            Some(ref trusted_snapshot) => {
                if trusted_snapshot.expires() <= &Utc::now() {
                    return Err(Error::ExpiredMetadata(Role::Snapshot));
                }
                Ok(trusted_snapshot)
            }
            None => Err(Error::MissingMetadata(Role::Snapshot)),
        }
    }

    fn trusted_targets_unexpired(&self) -> Result<&TargetsMetadata> {
        match self.trusted_targets {
            Some(ref trusted_targets) => {
                if trusted_targets.expires() <= &Utc::now() {
                    return Err(Error::ExpiredMetadata(Role::Targets));
                }
                Ok(trusted_targets)
            }
            None => Err(Error::MissingMetadata(Role::Targets)),
        }
    }
    fn trusted_timestamp_unexpired(&self) -> Result<&TimestampMetadata> {
        match self.trusted_timestamp {
            Some(ref trusted_timestamp) => {
                if trusted_timestamp.expires() <= &Utc::now() {
                    return Err(Error::ExpiredMetadata(Role::Timestamp));
                }
                Ok(trusted_timestamp)
            }
            None => Err(Error::MissingMetadata(Role::Timestamp)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{HashAlgorithm, PrivateKey, SignatureScheme};
    use crate::interchange::Json;
    use crate::metadata::{
        RootMetadataBuilder, SnapshotMetadataBuilder, TargetsMetadataBuilder,
        TimestampMetadataBuilder,
    };
    use lazy_static::lazy_static;
    use matches::assert_matches;
    use std::iter::once;

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
            keys.iter()
                .map(|b| PrivateKey::from_pkcs8(b, SignatureScheme::Ed25519).unwrap())
                .collect()
        };
    }

    #[test]
    fn root_trusted_keys_success() {
        let root_key = &KEYS[0];
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[0].public().clone())
            .targets_key(KEYS[0].public().clone())
            .timestamp_key(KEYS[0].public().clone())
            .signed::<Json>(&root_key)
            .unwrap();

        assert_matches!(
            Tuf::from_root_with_trusted_keys(root, 1, once(root_key.public())),
            Ok(_)
        );
    }

    #[test]
    fn root_trusted_keys_failure() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[0].public().clone())
            .targets_key(KEYS[0].public().clone())
            .timestamp_key(KEYS[0].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        assert_matches!(
            Tuf::from_root_with_trusted_keys(root, 1, once(KEYS[1].public())),
            Err(Error::VerificationFailure(s)) if s == "Signature threshold not met: 0/1"
        );
    }

    #[test]
    fn good_root_rotation() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[0].public().clone())
            .targets_key(KEYS[0].public().clone())
            .timestamp_key(KEYS[0].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let mut root = RootMetadataBuilder::new()
            .version(2)
            .root_key(KEYS[1].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[1].public().clone())
            .timestamp_key(KEYS[1].public().clone())
            .signed::<Json>(&KEYS[1])
            .unwrap();

        // add the original key's signature to make it cross signed
        root.add_signature(&KEYS[0]).unwrap();

        assert_matches!(tuf.update_root(root.clone()), Ok(true));

        // second update should do nothing
        assert_matches!(tuf.update_root(root), Ok(false));
    }

    #[test]
    fn no_cross_sign_root_rotation() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[0].public().clone())
            .targets_key(KEYS[0].public().clone())
            .timestamp_key(KEYS[0].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let root = RootMetadataBuilder::new()
            .root_key(KEYS[1].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[1].public().clone())
            .timestamp_key(KEYS[1].public().clone())
            .signed::<Json>(&KEYS[1])
            .unwrap();

        assert!(tuf.update_root(root).is_err());
    }

    #[test]
    fn good_timestamp_update() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[1].public().clone())
            .timestamp_key(KEYS[1].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let snapshot = SnapshotMetadataBuilder::new()
            .signed::<Json>(&KEYS[1])
            .unwrap();

        let timestamp =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
                .unwrap()
                .signed::<Json>(&KEYS[1])
                .unwrap();
        let _parsed_timestamp = timestamp.assume_valid().unwrap();

        assert_matches!(
            tuf.update_timestamp(timestamp.clone()),
            Ok(Some(_parsed_timestamp))
        );

        // second update should do nothing
        assert_matches!(tuf.update_timestamp(timestamp), Ok(None))
    }

    #[test]
    fn bad_timestamp_update_wrong_key() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[1].public().clone())
            .timestamp_key(KEYS[1].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let snapshot = SnapshotMetadataBuilder::new()
            .signed::<Json>(&KEYS[1])
            .unwrap();

        let timestamp =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
                .unwrap()
                // sign it with the root key
                .signed::<Json>(&KEYS[0])
                .unwrap();

        assert!(tuf.update_timestamp(timestamp).is_err())
    }

    #[test]
    fn good_snapshot_update() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[2].public().clone())
            .timestamp_key(KEYS[2].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let snapshot = SnapshotMetadataBuilder::new().signed(&KEYS[1]).unwrap();

        let timestamp =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
                .unwrap()
                .signed::<Json>(&KEYS[2])
                .unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        assert_matches!(tuf.update_snapshot(snapshot.clone()), Ok(true));

        // second update should do nothing
        assert_matches!(tuf.update_snapshot(snapshot), Ok(false));
    }

    #[test]
    fn bad_snapshot_update_wrong_key() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[2].public().clone())
            .timestamp_key(KEYS[2].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let snapshot = SnapshotMetadataBuilder::new()
            .signed::<Json>(&KEYS[2])
            .unwrap();

        let timestamp =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
                .unwrap()
                // sign it with the targets key
                .signed::<Json>(&KEYS[2])
                .unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        assert!(tuf.update_snapshot(snapshot).is_err());
    }

    #[test]
    fn bad_snapshot_update_wrong_version() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[2].public().clone())
            .timestamp_key(KEYS[2].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let snapshot = SnapshotMetadataBuilder::new()
            .version(2)
            .signed::<Json>(&KEYS[2])
            .unwrap();

        let timestamp =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
                .unwrap()
                .signed::<Json>(&KEYS[2])
                .unwrap();

        tuf.update_timestamp(timestamp).unwrap();

        let snapshot = SnapshotMetadataBuilder::new()
            .version(1)
            .signed::<Json>(&KEYS[1])
            .unwrap();

        assert!(tuf.update_snapshot(snapshot).is_err());
    }

    #[test]
    fn good_targets_update() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[2].public().clone())
            .timestamp_key(KEYS[3].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let signed_targets = TargetsMetadataBuilder::new()
            .signed::<Json>(&KEYS[2])
            .unwrap();

        let snapshot = SnapshotMetadataBuilder::new()
            .insert_metadata(&signed_targets, &[HashAlgorithm::Sha256])
            .unwrap()
            .signed::<Json>(&KEYS[1])
            .unwrap();

        let timestamp =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
                .unwrap()
                .signed::<Json>(&KEYS[3])
                .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        tuf.update_timestamp(timestamp).unwrap();
        tuf.update_snapshot(snapshot).unwrap();

        assert_matches!(tuf.update_targets(signed_targets.clone()), Ok(true));

        // second update should do nothing
        assert_matches!(tuf.update_targets(signed_targets), Ok(false));
    }

    #[test]
    fn bad_targets_update_wrong_key() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[2].public().clone())
            .timestamp_key(KEYS[3].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let signed_targets = TargetsMetadataBuilder::new()
            // sign it with the timestamp key
            .signed::<Json>(&KEYS[3])
            .unwrap();

        let snapshot = SnapshotMetadataBuilder::new()
            .insert_metadata(&signed_targets, &[HashAlgorithm::Sha256])
            .unwrap()
            .signed::<Json>(&KEYS[1])
            .unwrap();

        let timestamp =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
                .unwrap()
                .signed::<Json>(&KEYS[3])
                .unwrap();

        tuf.update_timestamp(timestamp).unwrap();
        tuf.update_snapshot(snapshot).unwrap();

        assert!(tuf.update_targets(signed_targets).is_err());
    }

    #[test]
    fn bad_targets_update_wrong_version() {
        let root = RootMetadataBuilder::new()
            .root_key(KEYS[0].public().clone())
            .snapshot_key(KEYS[1].public().clone())
            .targets_key(KEYS[2].public().clone())
            .timestamp_key(KEYS[3].public().clone())
            .signed::<Json>(&KEYS[0])
            .unwrap();

        let mut tuf = Tuf::from_trusted_root(root).unwrap();

        let signed_targets = TargetsMetadataBuilder::new()
            .version(2)
            .signed::<Json>(&KEYS[2])
            .unwrap();

        let snapshot = SnapshotMetadataBuilder::new()
            .insert_metadata(&signed_targets, &[HashAlgorithm::Sha256])
            .unwrap()
            .signed::<Json>(&KEYS[1])
            .unwrap();

        let timestamp =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
                .unwrap()
                .signed::<Json>(&KEYS[3])
                .unwrap();

        tuf.update_timestamp(timestamp).unwrap();
        tuf.update_snapshot(snapshot).unwrap();

        let signed_targets = TargetsMetadataBuilder::new()
            .version(1)
            .signed::<Json>(&KEYS[2])
            .unwrap();

        assert!(tuf.update_targets(signed_targets).is_err());
    }
}
