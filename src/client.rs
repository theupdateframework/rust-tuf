//! Clients for high level interactions with TUF repositories.

use Result;
use crypto;
use error::Error;
use interchange::DataInterchange;
use metadata::{MetadataVersion, RootMetadata, Role, MetadataPath, TargetPath, TargetDescription,
               TargetsMetadata, SnapshotMetadata};
use repository::Repository;
use tuf::Tuf;

/// A client that interacts with TUF repositories.
pub struct Client<D, L, R>
where
    D: DataInterchange,
    L: Repository<D>,
    R: Repository<D>,
{
    tuf: Tuf<D>,
    config: Config,
    local: L,
    remote: R,
}

impl<D, L, R> Client<D, L, R>
where
    D: DataInterchange,
    L: Repository<D>,
    R: Repository<D>,
{
    /// Create a new TUF client from the given `Tuf` (metadata storage) and local and remote
    /// repositories.
    pub fn new(tuf: Tuf<D>, config: Config, mut local: L, mut remote: R) -> Result<Self> {
        local.initialize()?;
        remote.initialize()?;

        Ok(Client {
            tuf: tuf,
            config: config,
            local: local,
            remote: remote,
        })
    }

    /// Update TUF metadata from the local repository.
    ///
    /// Returns `true` if an update occurred and `false` otherwise.
    pub fn update_local(&mut self) -> Result<bool> {
        let r = Self::update_root(
            &mut self.tuf,
            &mut self.local,
            &self.config.max_root_size,
            self.config.min_bytes_per_second,
        )?;
        let ts = match Self::update_timestamp(
            &mut self.tuf,
            &mut self.local,
            &self.config.max_timestamp_size,
            self.config.min_bytes_per_second,
        ) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Error updating timestamp metadata from local sources: {:?}",
                    e
                );
                false
            }
        };
        let sn = match Self::update_snapshot(
            &mut self.tuf,
            &mut self.local,
            self.config.min_bytes_per_second,
        ) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Error updating snapshot metadata from local sources: {:?}",
                    e
                );
                false
            }
        };
        let ta = match Self::update_targets(
            &mut self.tuf,
            &mut self.local,
            self.config.min_bytes_per_second,
        ) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Error updating targets metadata from local sources: {:?}",
                    e
                );
                false
            }
        };

        Ok(r || ts || sn || ta)
    }

    /// Update TUF metadata from the remote repository.
    ///
    /// Returns `true` if an update occurred and `false` otherwise.
    pub fn update_remote(&mut self) -> Result<bool> {
        let r = Self::update_root(
            &mut self.tuf,
            &mut self.remote,
            &self.config.max_root_size,
            self.config.min_bytes_per_second,
        )?;
        let ts = Self::update_timestamp(
            &mut self.tuf,
            &mut self.remote,
            &self.config.max_timestamp_size,
            self.config.min_bytes_per_second,
        )?;
        let sn = Self::update_snapshot(
            &mut self.tuf,
            &mut self.remote,
            self.config.min_bytes_per_second,
        )?;
        let ta = Self::update_targets(
            &mut self.tuf,
            &mut self.remote,
            self.config.min_bytes_per_second,
        )?;

        Ok(r || ts || sn || ta)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_root<T>(
        tuf: &mut Tuf<D>,
        repo: &mut T,
        max_root_size: &Option<usize>,
        min_bytes_per_second: u32,
    ) -> Result<bool>
    where
        T: Repository<D>,
    {
        let latest_root = repo.fetch_metadata(
            &Role::Root,
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::None,
            max_root_size,
            min_bytes_per_second,
            None,
        )?;
        let latest_version = D::deserialize::<RootMetadata>(latest_root.signed())?
            .version();

        if latest_version < tuf.root().version() {
            return Err(Error::VerificationFailure(format!(
                "Latest root version is lower than current root version: {} < {}",
                latest_version,
                tuf.root().version()
            )));
        } else if latest_version == tuf.root().version() {
            return Ok(false);
        }

        let err_msg = "TUF claimed no update occurred when one should have. \
                       This is a programming error. Please report this as a bug.";

        for i in (tuf.root().version() + 1)..latest_version {
            let signed = repo.fetch_metadata(
                &Role::Root,
                &MetadataPath::from_role(&Role::Root),
                &MetadataVersion::Number(i),
                max_root_size,
                min_bytes_per_second,
                None,
            )?;
            if !tuf.update_root(signed)? {
                error!("{}", err_msg);
                return Err(Error::Programming(err_msg.into()));
            }
        }

        if !tuf.update_root(latest_root)? {
            error!("{}", err_msg);
            return Err(Error::Programming(err_msg.into()));
        }
        Ok(true)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_timestamp<T>(
        tuf: &mut Tuf<D>,
        repo: &mut T,
        max_timestamp_size: &Option<usize>,
        min_bytes_per_second: u32,
    ) -> Result<bool>
    where
        T: Repository<D>,
    {
        let ts = repo.fetch_metadata(
            &Role::Timestamp,
            &MetadataPath::from_role(&Role::Timestamp),
            &MetadataVersion::None,
            max_timestamp_size,
            min_bytes_per_second,
            None,
        )?;
        tuf.update_timestamp(ts)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_snapshot<T>(tuf: &mut Tuf<D>, repo: &mut T, min_bytes_per_second: u32) -> Result<bool>
    where
        T: Repository<D>,
    {
        let snapshot_description = match tuf.timestamp() {
            Some(ts) => {
                match ts.meta().get(&MetadataPath::from_role(&Role::Snapshot)) {
                    Some(d) => Ok(d),
                    None => Err(Error::VerificationFailure(
                        "Timestamp metadata did not contain a description of the \
                                current snapshot metadata."
                            .into(),
                    )),
                }
            }
            None => Err(Error::MissingMetadata(Role::Timestamp)),
        }?
            .clone();

        if snapshot_description.version() <= tuf.snapshot().map(|s| s.version()).unwrap_or(0) {
            return Ok(false);
        }

        let (alg, value) = crypto::hash_preference(snapshot_description.hashes())?;

        let snap = repo.fetch_metadata(
            &Role::Snapshot,
            &MetadataPath::from_role(&Role::Snapshot),
            &MetadataVersion::None,
            &Some(snapshot_description.size()),
            min_bytes_per_second,
            Some((alg, value.clone())),
        )?;
        tuf.update_snapshot(snap)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_targets<T>(tuf: &mut Tuf<D>, repo: &mut T, min_bytes_per_second: u32) -> Result<bool>
    where
        T: Repository<D>,
    {
        let targets_description = match tuf.snapshot() {
            Some(sn) => {
                match sn.meta().get(&MetadataPath::from_role(&Role::Targets)) {
                    Some(d) => Ok(d),
                    None => Err(Error::VerificationFailure(
                        "Snapshot metadata did not contain a description of the \
                                current targets metadata."
                            .into(),
                    )),
                }
            }
            None => Err(Error::MissingMetadata(Role::Snapshot)),
        }?
            .clone();

        if targets_description.version() <= tuf.targets().map(|t| t.version()).unwrap_or(0) {
            return Ok(false);
        }

        let (alg, value) = crypto::hash_preference(targets_description.hashes())?;

        let targets = repo.fetch_metadata(
            &Role::Targets,
            &MetadataPath::from_role(&Role::Targets),
            &MetadataVersion::None,
            &Some(targets_description.size()),
            min_bytes_per_second,
            Some((alg, value.clone())),
        )?;
        tuf.update_targets(targets)
    }

    /// Fetch a target from the remote repo and write it to the local repo.
    pub fn fetch_target(&mut self, target: &TargetPath) -> Result<()> {
        fn lookup<_D, _L, _R>(
            tuf: &mut Tuf<_D>,
            config: &Config,
            default_terminate: bool,
            target: &TargetPath,
            snapshot: &SnapshotMetadata,
            targets: Option<&TargetsMetadata>,
            local: &mut _L,
            remote: &mut _R,
        ) -> (bool, Result<TargetDescription>)
        where
            _D: DataInterchange,
            _L: Repository<_D>,
            _R: Repository<_D>,
        {
            // these clones are dumb, but we need immutable values and not references for update
            // tuf in the loop below
            let targets = match targets {
                Some(t) => t.clone(),
                None => {
                    match tuf.targets() {
                        Some(t) => t.clone(),
                        None => {
                            return (
                                default_terminate,
                                Err(Error::MissingMetadata(Role::Targets)),
                            )
                        }
                    }
                }
            };

            match targets.targets().get(target) {
                Some(t) => return (default_terminate, Ok(t.clone())),
                None => (),
            }

            let delegations = match targets.delegations() {
                Some(d) => d,
                None => return (default_terminate, Err(Error::NotFound)),
            };

            for delegation in delegations.roles().iter() {
                if !delegation.paths().iter().any(|p| target.is_child(p)) {
                    if delegation.terminating() {
                        return (true, Err(Error::NotFound));
                    } else {
                        continue;
                    }
                }

                let role_meta = match snapshot.meta().get(delegation.role()) {
                    Some(m) => m,
                    None if !delegation.terminating() => continue,
                    None => return (true, Err(Error::NotFound)),
                };

                let meta = match local
                    .fetch_metadata::<TargetsMetadata>(
                        &Role::Targets,
                        delegation.role(),
                        &MetadataVersion::None,
                        &None, // TODO max size
                        config.min_bytes_per_second(),
                        None, // TODO hashes
                    )
                    .or_else(|_| {
                        remote.fetch_metadata::<TargetsMetadata>(
                            &Role::Targets,
                            delegation.role(),
                            &MetadataVersion::None,
                            &None, // TODO max size
                            config.min_bytes_per_second(),
                            None, // TODO hashes
                        )
                    }) {
                    Ok(m) => m,
                    Err(ref e) if !delegation.terminating() => {
                        warn!("Failed to fetch metadata {:?}: {:?}", delegation.role(), e);
                        continue;
                    }
                    Err(e) => {
                        warn!("Failed to fetch metadata {:?}: {:?}", delegation.role(), e);
                        return (true, Err(e));
                    }
                };

                match tuf.update_delegation(delegation.role(), meta) {
                    Ok(_) => {
                        let meta = tuf.delegations().get(delegation.role()).unwrap().clone();
                        let (term, res) = lookup(
                            tuf,
                            config,
                            delegation.terminating(),
                            target,
                            snapshot,
                            Some(&meta),
                            local,
                            remote,
                        );

                        if term && res.is_err() {
                            return (true, res);
                        }

                        // TODO end recursion early
                    }
                    Err(_) if !delegation.terminating() => continue,
                    Err(e) => return (true, Err(e)),

                };
            }

            (default_terminate, Err(Error::NotFound))
        }

        let snapshot = self.tuf
            .snapshot()
            .ok_or_else(|| Error::MissingMetadata(Role::Snapshot))?
            .clone();
        let (_, target_description) = lookup(
            &mut self.tuf,
            &self.config,
            false,
            target,
            &snapshot,
            None,
            &mut self.local,
            &mut self.remote,
        );
        let target_description = target_description?;

        let read = self.remote.fetch_target(
            target,
            &target_description,
            self.config.min_bytes_per_second,
        )?;
        self.local.store_target(read, target)
    }
}

/// Configuration for a TUF `Client`.
#[derive(Debug)]
pub struct Config {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
    min_bytes_per_second: u32,
}

impl Config {
    /// Initialize a `ConfigBuilder` with the default values.
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Return the optional maximum root metadata size.
    pub fn max_root_size(&self) -> &Option<usize> {
        &self.max_root_size
    }

    /// Return the optional maximum timestamp metadata size.
    pub fn max_timestamp_size(&self) -> &Option<usize> {
        &self.max_timestamp_size
    }

    /// The minimum bytes per second for a read to be considered good.
    pub fn min_bytes_per_second(&self) -> u32 {
        self.min_bytes_per_second
    }
}

/// Helper for building and validating a TUF `Config`.
#[derive(Debug, PartialEq)]
pub struct ConfigBuilder {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
    min_bytes_per_second: u32,
}

impl ConfigBuilder {
    /// Validate this builder return a `Config` if validation succeeds.
    pub fn finish(self) -> Result<Config> {
        Ok(Config {
            max_root_size: self.max_root_size,
            max_timestamp_size: self.max_timestamp_size,
            min_bytes_per_second: self.min_bytes_per_second,
        })
    }

    /// Set the optional maximum download size for root metadata.
    pub fn max_root_size(mut self, max: Option<usize>) -> Self {
        self.max_root_size = max;
        self
    }

    /// Set the optional maximum download size for timestamp metadata.
    pub fn max_timestamp_size(mut self, max: Option<usize>) -> Self {
        self.max_timestamp_size = max;
        self
    }

    /// Set the minimum bytes per second for a read to be considered good.
    pub fn min_bytes_per_second(mut self, min: u32) -> Self {
        self.min_bytes_per_second = min;
        self
    }
}

impl Default for ConfigBuilder {
    /// ```
    /// use tuf::client::ConfigBuilder;
    ///
    /// let default = ConfigBuilder::default();
    /// let config = ConfigBuilder::default()
    ///     .max_root_size(Some(1024 * 1024))
    ///     .max_timestamp_size(Some(32 * 1024))
    ///     .min_bytes_per_second(4096);
    /// assert_eq!(config, default);
    /// assert!(default.finish().is_ok())
    /// ```
    fn default() -> Self {
        ConfigBuilder {
            max_root_size: Some(1024 * 1024),
            max_timestamp_size: Some(32 * 1024),
            min_bytes_per_second: 4096,
        }
    }
}
