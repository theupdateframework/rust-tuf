//! Clients for high level interactions with TUF repositories.

use std::collections::{HashSet, VecDeque};

use Result;
use error::Error;
use interchange::DataInterchange;
use metadata::{MetadataVersion, RootMetadata, Role, MetadataPath, TargetPath};
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
        let r = Self::update_root(&mut self.tuf, &mut self.local, &self.config.max_root_size)?;
        let ts = match Self::update_timestamp(
            &mut self.tuf,
            &mut self.local,
            &self.config.max_timestamp_size,
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
        let sn = match Self::update_snapshot(&mut self.tuf, &mut self.local) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Error updating snapshot metadata from local sources: {:?}",
                    e
                );
                false
            }
        };
        let ta = match Self::update_targets(&mut self.tuf, &mut self.local) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Error updating targets metadata from local sources: {:?}",
                    e
                );
                false
            }
        };

        let de = match Self::update_delegations(&mut self.tuf, &mut self.local) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Error updating delegation metadata from local sources: {:?}",
                    e
                );
                // TODO this might be untrue because of a partial update
                false
            }
        };

        Ok(r || ts || sn || ta || de)
    }

    /// Update TUF metadata from the remote repository.
    ///
    /// Returns `true` if an update occurred and `false` otherwise.
    pub fn update_remote(&mut self) -> Result<bool> {
        let r = Self::update_root(&mut self.tuf, &mut self.remote, &self.config.max_root_size)?;
        let ts = Self::update_timestamp(
            &mut self.tuf,
            &mut self.remote,
            &self.config.max_timestamp_size,
        )?;
        let sn = Self::update_snapshot(&mut self.tuf, &mut self.remote)?;
        let ta = Self::update_targets(&mut self.tuf, &mut self.remote)?;
        let de = Self::update_delegations(&mut self.tuf, &mut self.remote)?;

        Ok(r || ts || sn || ta || de)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_root<T>(tuf: &mut Tuf<D>, repo: &mut T, max_root_size: &Option<usize>) -> Result<bool>
    where
        T: Repository<D>,
    {
        let latest_root = repo.fetch_metadata(
            &Role::Root,
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::None,
            max_root_size,
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
    ) -> Result<bool>
    where
        T: Repository<D>,
    {
        let ts = repo.fetch_metadata(
            &Role::Timestamp,
            &MetadataPath::from_role(&Role::Timestamp),
            &MetadataVersion::None,
            max_timestamp_size,
            None,
        )?;
        tuf.update_timestamp(ts)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_snapshot<T>(tuf: &mut Tuf<D>, repo: &mut T) -> Result<bool>
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

        let snap = repo.fetch_metadata(
            &Role::Snapshot,
            &MetadataPath::from_role(&Role::Snapshot),
            &MetadataVersion::None,
            &None,
            None,
        )?;
        tuf.update_snapshot(snap)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_targets<T>(tuf: &mut Tuf<D>, repo: &mut T) -> Result<bool>
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

        let targets = repo.fetch_metadata(
            &Role::Targets,
            &MetadataPath::from_role(&Role::Targets),
            &MetadataVersion::None,
            &None,
            None,
        )?;
        tuf.update_targets(targets)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_delegations<T>(tuf: &mut Tuf<D>, repo: &mut T) -> Result<bool>
    where
        T: Repository<D>,
    {
        let _ = match tuf.snapshot() {
            Some(s) => s,
            None => return Err(Error::MissingMetadata(Role::Snapshot)),
        }.clone();
        let targets = match tuf.targets() {
            Some(t) => t,
            None => return Err(Error::MissingMetadata(Role::Targets)),
        }.clone();
        let delegations = match targets.delegations() {
            Some(d) => d,
            None => return Ok(false),
        }.clone();

        let mut visited = HashSet::new();
        let mut to_visit = VecDeque::new();

        for role in delegations.roles().iter().map(|r| r.role()) {
            let _ = to_visit.push_back(role.clone());
        }

        let mut updated = false;
        while let Some(role) = to_visit.pop_front() {
            if visited.contains(&role) {
                continue;
            }
            let _ = visited.insert(role.clone());

            let delegation = match repo.fetch_metadata(
                &Role::Targets,
                &role,
                &MetadataVersion::None,
                &None,
                None,
            ) {
                Ok(d) => d,
                Err(e) => {
                    warn!("Failed to fetuch delegation {:?}: {:?}", role, e);
                    continue;
                }
            };

            match tuf.update_delegation(&role, delegation) {
                Ok(u) => updated |= u,
                Err(e) => {
                    warn!("Failed to update delegation {:?}: {:?}", role, e);
                    continue;
                }
            };

            if let Some(ds) = tuf.delegations().get(&role).and_then(|t| t.delegations()) {
                for d in ds.roles() {
                    let _ = to_visit.push_back(d.role().clone());
                }
            }
        }

        Ok(updated)
    }

    /// Fetch a target from the remote repo and write it to the local repo.
    pub fn fetch_target(&mut self, target: &TargetPath) -> Result<()> {
        let target_description = self.tuf.target_description(target)?;
        let read = self.remote.fetch_target(target)?;
        self.local.store_target(read, target, &target_description)
    }
}

/// Configuration for a TUF `Client`.
#[derive(Debug)]
pub struct Config {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
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
}

/// Helper for building and validating a TUF `Config`.
#[derive(Debug, PartialEq)]
pub struct ConfigBuilder {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
}

impl ConfigBuilder {
    /// Validate this builder return a `Config` if validation succeeds.
    pub fn finish(self) -> Result<Config> {
        Ok(Config {
            max_root_size: self.max_root_size,
            max_timestamp_size: self.max_timestamp_size,
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
}

impl Default for ConfigBuilder {
    /// ```
    /// use tuf::client::ConfigBuilder;
    ///
    /// let default = ConfigBuilder::default();
    /// let config = ConfigBuilder::default()
    ///     .max_root_size(Some(1024 * 1024))
    ///     .max_timestamp_size(Some(32 * 1024));
    /// assert_eq!(config, default);
    /// assert!(default.finish().is_ok())
    /// ```
    fn default() -> Self {
        ConfigBuilder {
            max_root_size: Some(1024 * 1024),
            max_timestamp_size: Some(32 * 1024),
        }
    }
}
