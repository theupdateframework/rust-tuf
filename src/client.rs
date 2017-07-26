//! Clients for high level interactions with TUF repositories.

use std::io::{Read, Write};

use Result;
use crypto;
use error::Error;
use interchange::DataInterchange;
use metadata::{MetadataVersion, RootMetadata, Role, MetadataPath, TargetPath, TargetDescription,
               TargetsMetadata, SnapshotMetadata};
use repository::Repository;
use tuf::Tuf;
use util::SafeReader;

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
        let r = Self::update_root(&mut self.tuf, &mut self.local, &self.config)?;
        let ts = match Self::update_timestamp(&mut self.tuf, &mut self.local, &self.config) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Error updating timestamp metadata from local sources: {:?}",
                    e
                );
                false
            }
        };
        let sn = match Self::update_snapshot(&mut self.tuf, &mut self.local, &self.config) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Error updating snapshot metadata from local sources: {:?}",
                    e
                );
                false
            }
        };
        let ta = match Self::update_targets(&mut self.tuf, &mut self.local, &self.config) {
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
        let r = Self::update_root(&mut self.tuf, &mut self.remote, &self.config)?;
        let ts = Self::update_timestamp(&mut self.tuf, &mut self.remote, &self.config)?;
        let sn = Self::update_snapshot(&mut self.tuf, &mut self.remote, &self.config)?;
        let ta = Self::update_targets(&mut self.tuf, &mut self.remote, &self.config)?;

        Ok(r || ts || sn || ta)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_root<T>(tuf: &mut Tuf<D>, repo: &mut T, config: &Config) -> Result<bool>
    where
        T: Repository<D>,
    {
        let latest_root = repo.fetch_metadata(
            &Role::Root,
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::None,
            &config.max_root_size,
            config.min_bytes_per_second,
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
                &config.max_root_size,
                config.min_bytes_per_second,
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
    fn update_timestamp<T>(tuf: &mut Tuf<D>, repo: &mut T, config: &Config) -> Result<bool>
    where
        T: Repository<D>,
    {
        let ts = repo.fetch_metadata(
            &Role::Timestamp,
            &MetadataPath::from_role(&Role::Timestamp),
            &MetadataVersion::None,
            &config.max_timestamp_size,
            config.min_bytes_per_second,
            None,
        )?;
        tuf.update_timestamp(ts)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_snapshot<T>(tuf: &mut Tuf<D>, repo: &mut T, config: &Config) -> Result<bool>
    where
        T: Repository<D>,
    {
        let snapshot_description = match tuf.timestamp() {
            Some(ts) => Ok(ts.snapshot()),
            None => Err(Error::MissingMetadata(Role::Timestamp)),
        }?
            .clone();

        if snapshot_description.version() <= tuf.snapshot().map(|s| s.version()).unwrap_or(0) {
            return Ok(false);
        }

        let (alg, value) = crypto::hash_preference(snapshot_description.hashes())?;

        let version = if tuf.root().consistent_snapshot() {
            MetadataVersion::Hash(value.clone())
        } else {
            MetadataVersion::None
        };

        let snap = repo.fetch_metadata(
            &Role::Snapshot,
            &MetadataPath::from_role(&Role::Snapshot),
            &version,
            &Some(snapshot_description.size()),
            config.min_bytes_per_second,
            Some((alg, value.clone())),
        )?;
        tuf.update_snapshot(snap)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_targets<T>(tuf: &mut Tuf<D>, repo: &mut T, config: &Config) -> Result<bool>
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

        let version = if tuf.root().consistent_snapshot() {
            MetadataVersion::Hash(value.clone())
        } else {
            MetadataVersion::None
        };

        let targets = repo.fetch_metadata(
            &Role::Targets,
            &MetadataPath::from_role(&Role::Targets),
            &version,
            &Some(targets_description.size()),
            config.min_bytes_per_second,
            Some((alg, value.clone())),
        )?;
        tuf.update_targets(targets)
    }

    /// Fetch a target from the remote repo and write it to the local repo.
    pub fn fetch_target(&mut self, target: &TargetPath) -> Result<()> {
        let read = self._fetch_target(target)?;
        self.local.store_target(read, target)
    }

    /// Fetch a target from the remote repo and write it to the provided writer.
    pub fn fetch_target_to_writer<W: Write>(
        &mut self,
        target: &TargetPath,
        mut write: W,
    ) -> Result<()> {
        let mut read = self._fetch_target(target)?;
        let mut buf = [0; 1024];
        loop {
            let bytes_read = read.read(&mut buf)?;
            if bytes_read == 0 {
                break;
            }
            write.write_all(&buf[..bytes_read])?
        }
        Ok(())
    }

    // TODO this should check the local repo first
    fn _fetch_target(&mut self, target: &TargetPath) -> Result<SafeReader<R::TargetRead>> {
        fn lookup<_D, _L, _R>(
            tuf: &mut Tuf<_D>,
            config: &Config,
            default_terminate: bool,
            current_depth: u32,
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
            if current_depth > config.max_delegation_depth {
                warn!(
                    "Walking the delegation graph would have exceeded the configured max depth: {}",
                    config.max_delegation_depth
                );
                return (default_terminate, Err(Error::NotFound));
            }

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

                let (alg, value) = match crypto::hash_preference(role_meta.hashes()) {
                    Ok(h) => h,
                    Err(e) => return (delegation.terminating(), Err(e)),
                };

                let version = if tuf.root().consistent_snapshot() {
                    MetadataVersion::Hash(value.clone())
                } else {
                    MetadataVersion::None
                };

                let signed_meta = match local
                    .fetch_metadata::<TargetsMetadata>(
                        &Role::Targets,
                        delegation.role(),
                        &MetadataVersion::None,
                        &Some(role_meta.size()),
                        config.min_bytes_per_second(),
                        Some((alg, value.clone())),
                    )
                    .or_else(|_| {
                        remote.fetch_metadata::<TargetsMetadata>(
                            &Role::Targets,
                            delegation.role(),
                            &version,
                            &Some(role_meta.size()),
                            config.min_bytes_per_second(),
                            Some((alg, value.clone())),
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

                match tuf.update_delegation(delegation.role(), signed_meta.clone()) {
                    Ok(_) => {
                        match local.store_metadata(
                            &Role::Targets,
                            delegation.role(),
                            &MetadataVersion::None,
                            &signed_meta,
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                warn!(
                                    "Error storing metadata {:?} locally: {:?}",
                                    delegation.role(),
                                    e
                                )
                            }
                        }

                        let meta = tuf.delegations().get(delegation.role()).unwrap().clone();
                        let (term, res) = lookup(
                            tuf,
                            config,
                            delegation.terminating(),
                            current_depth + 1,
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
            0,
            target,
            &snapshot,
            None,
            &mut self.local,
            &mut self.remote,
        );
        let target_description = target_description?;

        self.remote.fetch_target(
            target,
            &target_description,
            self.config.min_bytes_per_second,
        )
    }
}

/// Configuration for a TUF `Client`.
#[derive(Debug)]
pub struct Config {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
    min_bytes_per_second: u32,
    max_delegation_depth: u32,
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

    /// The maximum number of steps used when walking the delegation graph.
    pub fn max_delegation_depth(&self) -> u32 {
        self.max_delegation_depth
    }
}

/// Helper for building and validating a TUF `Config`.
#[derive(Debug, PartialEq)]
pub struct ConfigBuilder {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
    min_bytes_per_second: u32,
    max_delegation_depth: u32,
}

impl ConfigBuilder {
    /// Validate this builder return a `Config` if validation succeeds.
    pub fn finish(self) -> Result<Config> {
        Ok(Config {
            max_root_size: self.max_root_size,
            max_timestamp_size: self.max_timestamp_size,
            min_bytes_per_second: self.min_bytes_per_second,
            max_delegation_depth: self.max_delegation_depth,
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

    /// Set the maximum number of steps used when walking the delegation graph.
    pub fn max_delegation_depth(mut self, max: u32) -> Self {
        self.max_delegation_depth = max;
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
    ///     .min_bytes_per_second(4096)
    ///     .max_delegation_depth(10);
    /// assert_eq!(config, default);
    /// assert!(default.finish().is_ok())
    /// ```
    fn default() -> Self {
        ConfigBuilder {
            max_root_size: Some(1024 * 1024),
            max_timestamp_size: Some(32 * 1024),
            min_bytes_per_second: 4096,
            max_delegation_depth: 10,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use crypto::{PrivateKey, SignatureScheme};
    use interchange::JsonDataInterchange;
    use metadata::{RootMetadata, SignedMetadata, RoleDefinition, MetadataPath, MetadataVersion};
    use repository::EphemeralRepository;

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
    fn root_chain_update() {
        let mut repo = EphemeralRepository::new();
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

        repo.store_metadata(
            &Role::Root,
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::Number(1),
            &root,
        ).unwrap();

        let tuf = Tuf::from_root(root).unwrap();

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

        root.add_signature(
            &KEYS[0],
            SignatureScheme::Ed25519,
        ).unwrap();

        repo.store_metadata(
            &Role::Root,
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::Number(2),
            &root,
        ).unwrap();

        let root = RootMetadata::new(
            3,
            Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
            false,
            vec![KEYS[2].public().clone()],
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
            RoleDefinition::new(1, hashset!(KEYS[2].key_id().clone())).unwrap(),
        ).unwrap();
        let mut root: SignedMetadata<JsonDataInterchange, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[2], SignatureScheme::Ed25519).unwrap();

        root.add_signature(
            &KEYS[1],
            SignatureScheme::Ed25519,
        ).unwrap();

        repo.store_metadata(
            &Role::Root,
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::Number(3),
            &root,
        ).unwrap();
        repo.store_metadata(
            &Role::Root,
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::None,
            &root,
        ).unwrap();

        let mut client = Client::new(tuf, Config::build().finish().unwrap(), repo, EphemeralRepository::new()).unwrap();
        assert_eq!(client.update_local(), Ok(true));
        assert_eq!(client.tuf.root().version(), 3);
    }
}
