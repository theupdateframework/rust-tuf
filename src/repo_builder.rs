use std::collections::HashMap;

use crate::crypto::{HashAlgorithm, PrivateKey};
use crate::interchange::DataInterchange;
use crate::metadata::{
    Delegations, Metadata, MetadataPath, MetadataVersion, Role, RootMetadata, RootMetadataBuilder,
    SignedMetadata, SnapshotMetadataBuilder, TargetDescription, TargetsMetadata,
    TargetsMetadataBuilder, TimestampMetadataBuilder, VirtualTargetPath,
};
use crate::repository::{Repository, RepositoryProvider, RepositoryStorage};
use crate::Result;

// This is a helper crate to keep track of the private keys necessary to create new metadata.
//
// FIXME: This is not ready yet for public use, it is only intended for internal testing until the
// design is complete.
pub(crate) struct RepoKeys<'a> {
    pub(crate) root: Vec<&'a PrivateKey>,
    pub(crate) targets: Vec<&'a PrivateKey>,
    pub(crate) snapshot: Vec<&'a PrivateKey>,
    pub(crate) timestamp: Vec<&'a PrivateKey>,
}

// This helper builder simplifies the process of creating new metadata.
//
// FIXME: This is not ready yet for public use, it is only intended for internal testing until the
// design is complete.
pub(crate) struct RepoBuilder<'a, R, D>
where
    R: RepositoryProvider<D> + RepositoryStorage<D>,
    D: DataInterchange + Sync,
{
    repo_keys: RepoKeys<'a>,
    repo: Repository<R, D>,
    root_builder: RootMetadataBuilder,
    targets_builder: TargetsMetadataBuilder,
    snapshot_version: u32,
    timestamp_version: u32,
    delegated_targets: HashMap<MetadataPath, SignedMetadata<D, TargetsMetadata>>,
}

impl<'a, R, D> RepoBuilder<'a, R, D>
where
    R: RepositoryProvider<D> + RepositoryStorage<D>,
    D: DataInterchange + Sync,
{
    pub(crate) fn new(repo_keys: RepoKeys<'a>, repo: R) -> Self {
        let repo = Repository::new(repo);

        let mut root_builder = RootMetadataBuilder::new();

        for key in &repo_keys.root {
            root_builder = root_builder.root_key(key.public().clone());
        }

        for key in &repo_keys.targets {
            root_builder = root_builder.targets_key(key.public().clone());
        }

        for key in &repo_keys.snapshot {
            root_builder = root_builder.snapshot_key(key.public().clone());
        }

        for key in &repo_keys.timestamp {
            root_builder = root_builder.timestamp_key(key.public().clone());
        }

        Self {
            repo_keys,
            repo,
            root_builder,
            targets_builder: TargetsMetadataBuilder::new(),
            snapshot_version: 1,
            timestamp_version: 1,
            delegated_targets: HashMap::new(),
        }
    }

    pub(crate) fn with_root<F>(mut self, f: F) -> Self
    where
        F: FnOnce(RootMetadataBuilder) -> RootMetadataBuilder,
    {
        self.root_builder = f(self.root_builder);
        self
    }

    pub(crate) fn set_root_version(mut self, version: u32) -> Self {
        self.root_builder = self.root_builder.version(version);
        self
    }

    pub(crate) fn set_targets_version(mut self, version: u32) -> Self {
        self.targets_builder = self.targets_builder.version(version);
        self
    }

    pub(crate) fn set_snapshot_version(mut self, version: u32) -> Self {
        self.snapshot_version = version;
        self
    }

    pub(crate) fn set_timestamp_version(mut self, version: u32) -> Self {
        self.timestamp_version = version;
        self
    }

    pub(crate) fn delegations(mut self, delegations: Delegations) -> Self {
        self.targets_builder = self.targets_builder.delegations(delegations);
        self
    }

    pub(crate) fn insert_delegated_target(
        mut self,
        path: MetadataPath,
        targets: SignedMetadata<D, TargetsMetadata>,
    ) -> Self {
        self.delegated_targets.insert(path, targets);
        self
    }

    pub(crate) fn insert_target_description(
        mut self,
        path: VirtualTargetPath,
        description: TargetDescription,
    ) -> Self {
        self.targets_builder = self
            .targets_builder
            .insert_target_description(path, description);
        self
    }

    // Commit the metadata to the database.
    //
    // FIXME: this currently always generates the timestamp/snapshot/targets/delegation metadata,
    // and will overwrite it if that version already exists.
    pub(crate) async fn commit(mut self) -> Result<SignedMetadata<D, RootMetadata>> {
        let root_path = MetadataPath::from_role(&Role::Root);
        let targets_path = MetadataPath::from_role(&Role::Targets);
        let snapshot_path = MetadataPath::from_role(&Role::Snapshot);
        let timestamp_path = MetadataPath::from_role(&Role::Timestamp);

        // Construct and sign the root metadata.
        let root_metadata = self.root_builder.build()?;
        let root = sign::<D, _>(&root_metadata, &self.repo_keys.root)?;

        // Sign the targets metadata.
        let targets_metadata = self.targets_builder.build()?;
        let targets = sign(&targets_metadata, &self.repo_keys.targets)?;

        // Construct and sign the snapshot metadata.
        let mut snapshot_builder = SnapshotMetadataBuilder::new()
            .version(self.snapshot_version)
            .insert_metadata(&targets, &[HashAlgorithm::Sha256])?;

        for (path, delegated_target) in &self.delegated_targets {
            snapshot_builder = snapshot_builder.insert_metadata_with_path(
                path.to_string(),
                &delegated_target,
                &[HashAlgorithm::Sha256],
            )?;
        }
        let snapshot_metadata = snapshot_builder.build()?;

        let snapshot = sign(&snapshot_metadata, &self.repo_keys.snapshot)?;

        // Construct and sign the timestamp metadata.
        let timestamp_metadata =
            TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])?
                .version(self.timestamp_version)
                .build()?;
        let timestamp = sign(&timestamp_metadata, &self.repo_keys.timestamp)?;

        // Commit the root metadata.
        let raw_root = root.to_raw()?;
        self.repo
            .store_metadata(
                &root_path,
                &MetadataVersion::Number(root_metadata.version()),
                &raw_root,
            )
            .await?;

        self.repo
            .store_metadata(&root_path, &MetadataVersion::None, &raw_root)
            .await?;

        // Commit the delegated targets metadata.
        for (path, delegated_targets) in self.delegated_targets {
            let raw_delegated_targets = delegated_targets.to_raw()?;

            if root_metadata.consistent_snapshot() {
                let version = delegated_targets.parse_version_untrusted()?;
                self.repo
                    .store_metadata(
                        &path,
                        &MetadataVersion::Number(version),
                        &raw_delegated_targets,
                    )
                    .await?;
            } else {
                self.repo
                    .store_metadata(&path, &MetadataVersion::None, &raw_delegated_targets)
                    .await?;
            }
        }

        // Commit the target metadata.
        let raw_targets = targets.to_raw()?;
        if root_metadata.consistent_snapshot() {
            self.repo
                .store_metadata(
                    &targets_path,
                    &MetadataVersion::Number(targets_metadata.version()),
                    &raw_targets,
                )
                .await?;
        } else {
            self.repo
                .store_metadata(&targets_path, &MetadataVersion::None, &raw_targets)
                .await?;
        }

        // Commit the snapshot metadata.
        let raw_snapshot = snapshot.to_raw()?;
        if root_metadata.consistent_snapshot() {
            self.repo
                .store_metadata(
                    &snapshot_path,
                    &MetadataVersion::Number(snapshot_metadata.version()),
                    &raw_snapshot,
                )
                .await?;
        } else {
            self.repo
                .store_metadata(&snapshot_path, &MetadataVersion::None, &raw_snapshot)
                .await?;
        }

        // Commit the timestamp metadata.
        self.repo
            .store_metadata(
                &timestamp_path,
                &MetadataVersion::None,
                &timestamp.to_raw()?,
            )
            .await?;

        Ok(root)
    }
}

fn sign<D, M>(metadata: &M, private_keys: &[&PrivateKey]) -> Result<SignedMetadata<D, M>>
where
    D: DataInterchange,
    M: Metadata,
{
    let mut private_keys = private_keys.into_iter();
    let mut signed_metadata = SignedMetadata::new(metadata, private_keys.next().unwrap())?;

    for private_key in private_keys {
        signed_metadata.add_signature(private_key)?;
    }

    Ok(signed_metadata)
}
