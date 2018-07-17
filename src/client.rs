//! Clients for high level interactions with TUF repositories.
//!
//! # Example
//!
//! ```no_run
//! extern crate hyper;
//! extern crate tuf;
//!
//! use hyper::client::Client as HttpClient;
//! use hyper::Url;
//! use std::path::PathBuf;
//! use tuf::Tuf;
//! use tuf::crypto::KeyId;
//! use tuf::client::{Client, Config};
//! use tuf::metadata::{RootMetadata, SignedMetadata, Role, MetadataPath,
//!     MetadataVersion};
//! use tuf::interchange::Json;
//! use tuf::repository::{Repository, FileSystemRepository, HttpRepository};
//!
//! static TRUSTED_ROOT_KEY_IDS: &'static [&str] = &[
//!     "diNfThTFm0PI8R-Bq7NztUIvZbZiaC_weJBgcqaHlWw=",
//!     "ar9AgoRsmeEcf6Ponta_1TZu1ds5uXbDemBig30O7ck=",
//!     "T5vfRrM1iHpgzGwAHe7MbJH_7r4chkOAphV3OPCCv0I=",
//! ];
//!
//! fn main() {
//!     let key_ids: Vec<KeyId> = TRUSTED_ROOT_KEY_IDS.iter()
//!         .map(|k| KeyId::from_string(k).unwrap())
//!         .collect();
//!
//!     let local = FileSystemRepository::<Json>::new(PathBuf::from("~/.rustup"))
//!         .unwrap();
//!
//!     let remote = HttpRepository::new(
//!         Url::parse("https://static.rust-lang.org/").unwrap(),
//!         HttpClient::new(),
//!         Some("rustup/1.4.0".into()),
//!         None);
//!
//!     let mut client = Client::with_root_pinned(
//!         &key_ids,
//!         Config::default(),
//!         local,
//!         remote,
//!     ).unwrap();
//!     let _ = client.update_local().unwrap();
//!     let _ = client.update_remote().unwrap();
//! }
//! ```

use std::io::{Read, Write};

use crypto::{self, KeyId};
use error::Error;
use interchange::DataInterchange;
use metadata::{
    MetadataPath, MetadataVersion, Role, RootMetadata, SnapshotMetadata, TargetDescription,
    TargetPath, TargetsMetadata, VirtualTargetPath,
};
use repository::Repository;
use tuf::Tuf;
use util::SafeReader;
use Result;

/// Translates real paths (where a file is stored) into virtual paths (how it is addressed in TUF)
/// and back.
///
/// Implementations must obey the following identities for all possible inputs.
///
/// ```
/// # use tuf::client::{PathTranslator, DefaultTranslator};
/// # use tuf::metadata::{VirtualTargetPath, TargetPath};
/// # let path = TargetPath::new("foo".into()).unwrap();
/// # let virt = VirtualTargetPath::new("foo".into()).unwrap();
/// # let translator = DefaultTranslator::new();
/// assert_eq!(path,
///            translator.virtual_to_real(&translator.real_to_virtual(&path).unwrap()).unwrap());
/// assert_eq!(virt,
///            translator.real_to_virtual(&translator.virtual_to_real(&virt).unwrap()).unwrap());
/// ```
pub trait PathTranslator {
    /// Convert a real path into a virtual path.
    fn real_to_virtual(&self, path: &TargetPath) -> Result<VirtualTargetPath>;

    /// Convert a virtual path into a real path.
    fn virtual_to_real(&self, path: &VirtualTargetPath) -> Result<TargetPath>;
}

/// A `PathTranslator` that does nothing.
#[derive(Default)]
pub struct DefaultTranslator;

impl DefaultTranslator {
    /// Create a new `DefaultTranslator`.
    pub fn new() -> Self {
        DefaultTranslator
    }
}

impl PathTranslator for DefaultTranslator {
    fn real_to_virtual(&self, path: &TargetPath) -> Result<VirtualTargetPath> {
        VirtualTargetPath::new(path.value().into())
    }

    fn virtual_to_real(&self, path: &VirtualTargetPath) -> Result<TargetPath> {
        TargetPath::new(path.value().into())
    }
}

/// A client that interacts with TUF repositories.
pub struct Client<D, L, R, T>
where
    D: DataInterchange,
    L: Repository<D>,
    R: Repository<D>,
    T: PathTranslator,
{
    tuf: Tuf<D>,
    config: Config<T>,
    local: L,
    remote: R,
}

impl<D, L, R, T> Client<D, L, R, T>
where
    D: DataInterchange,
    L: Repository<D>,
    R: Repository<D>,
    T: PathTranslator,
{
    /// Create a new TUF client. It will attempt to load initial root metadata from the local repo
    /// and return an error if it cannot do so.
    ///
    /// **WARNING**: This method offers weaker security guarantees than the related method
    /// `with_root_pinned`.
    pub fn new(config: Config<T>, local: L, remote: R) -> Result<Self> {
        let root = local
            .fetch_metadata(
                &MetadataPath::from_role(&Role::Root),
                &MetadataVersion::Number(1),
                &config.max_root_size,
                config.min_bytes_per_second,
                None,
            )?;

        let tuf = Tuf::from_root(&root)?;

        Ok(Client {
            tuf,
            config,
            local,
            remote,
        })
    }

    /// Create a new TUF client. It will attempt to load initial root metadata the local and remote
    /// repositories using the provided key IDs to pin the verification.
    ///
    /// This is the preferred method of creating a client.
    pub fn with_root_pinned<'a, I>(
        trusted_root_keys: I,
        config: Config<T>,
        local: L,
        remote: R,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = &'a KeyId>,
        T: PathTranslator,
    {
        let root = local
            .fetch_metadata(
                &MetadataPath::from_role(&Role::Root),
                &MetadataVersion::Number(1),
                &config.max_root_size,
                config.min_bytes_per_second,
                None,
            )
            .or_else(|_| {
                remote.fetch_metadata(
                    &MetadataPath::from_role(&Role::Root),
                    &MetadataVersion::Number(1),
                    &config.max_root_size,
                    config.min_bytes_per_second,
                    None,
                )
            })?;

        let tuf = Tuf::from_root_pinned(root, trusted_root_keys)?;

        Ok(Client {
            tuf,
            config,
            local,
            remote,
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
    fn update_root<V, U>(tuf: &mut Tuf<D>, repo: &mut V, config: &Config<U>) -> Result<bool>
    where
        V: Repository<D>,
        U: PathTranslator,
    {
        let latest_root = repo.fetch_metadata(
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::None,
            &config.max_root_size,
            config.min_bytes_per_second,
            None,
        )?;
        let latest_version = D::deserialize::<RootMetadata>(latest_root.signed())?.version();

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
                &MetadataPath::from_role(&Role::Root),
                &MetadataVersion::Number(i),
                &config.max_root_size,
                config.min_bytes_per_second,
                None,
            )?;
            if !tuf.update_root(&signed)? {
                error!("{}", err_msg);
                return Err(Error::Programming(err_msg.into()));
            }
        }

        if !tuf.update_root(&latest_root)? {
            error!("{}", err_msg);
            return Err(Error::Programming(err_msg.into()));
        }
        Ok(true)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_timestamp<V, U>(tuf: &mut Tuf<D>, repo: &mut V, config: &Config<U>) -> Result<bool>
    where
        V: Repository<D>,
        U: PathTranslator,
    {
        let ts = repo.fetch_metadata(
            &MetadataPath::from_role(&Role::Timestamp),
            &MetadataVersion::None,
            &config.max_timestamp_size,
            config.min_bytes_per_second,
            None,
        )?;
        tuf.update_timestamp(&ts)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_snapshot<V, U>(tuf: &mut Tuf<D>, repo: &mut V, config: &Config<U>) -> Result<bool>
    where
        V: Repository<D>,
        U: PathTranslator,
    {
        let snapshot_description = match tuf.timestamp() {
            Some(ts) => Ok(ts.snapshot()),
            None => Err(Error::MissingMetadata(Role::Timestamp)),
        }?.clone();

        if snapshot_description.version() <= tuf.snapshot().map(|s| s.version()).unwrap_or(0) {
            return Ok(false);
        }

        let (alg, value) = crypto::hash_preference(snapshot_description.hashes())?;

        let version = if tuf.root().consistent_snapshot() {
            MetadataVersion::Number(snapshot_description.version())
        } else {
            MetadataVersion::None
        };

        let snap = repo.fetch_metadata(
            &MetadataPath::from_role(&Role::Snapshot),
            &version,
            &Some(snapshot_description.size()),
            config.min_bytes_per_second,
            Some((alg, value.clone())),
        )?;
        tuf.update_snapshot(&snap)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_targets<V, U>(tuf: &mut Tuf<D>, repo: &mut V, config: &Config<U>) -> Result<bool>
    where
        V: Repository<D>,
        U: PathTranslator,
    {
        let targets_description = match tuf.snapshot() {
            Some(sn) => match sn.meta().get(&MetadataPath::from_role(&Role::Targets)) {
                Some(d) => Ok(d),
                None => Err(Error::VerificationFailure(
                    "Snapshot metadata did not contain a description of the \
                     current targets metadata."
                        .into(),
                )),
            },
            None => Err(Error::MissingMetadata(Role::Snapshot)),
        }?.clone();

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
            &MetadataPath::from_role(&Role::Targets),
            &version,
            &Some(targets_description.size()),
            config.min_bytes_per_second,
            Some((alg, value.clone())),
        )?;
        tuf.update_targets(&targets)
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
        let mut read = self._fetch_target(&target)?;
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
        let virt = self.config.path_translator.real_to_virtual(target)?;

        let snapshot = self.tuf
            .snapshot()
            .ok_or_else(|| Error::MissingMetadata(Role::Snapshot))?
            .clone();
        let (_, target_description) =
            self.lookup_target_description(false, 0, &virt, &snapshot, None);
        let target_description = target_description?;

        self.remote.fetch_target(
            target,
            &target_description,
            self.config.min_bytes_per_second,
        )
    }

    fn lookup_target_description(
        &mut self,
        default_terminate: bool,
        current_depth: u32,
        target: &VirtualTargetPath,
        snapshot: &SnapshotMetadata,
        targets: Option<&TargetsMetadata>,
    ) -> (bool, Result<TargetDescription>) {
        if current_depth > self.config.max_delegation_depth {
            warn!(
                "Walking the delegation graph would have exceeded the configured max depth: {}",
                self.config.max_delegation_depth
            );
            return (default_terminate, Err(Error::NotFound));
        }

        // these clones are dumb, but we need immutable values and not references for update
        // tuf in the loop below
        let targets = match targets {
            Some(t) => t.clone(),
            None => match self.tuf.targets() {
                Some(t) => t.clone(),
                None => {
                    return (
                        default_terminate,
                        Err(Error::MissingMetadata(Role::Targets)),
                    )
                }
            },
        };

        if let Some(t) = targets.targets().get(target) {
            return (default_terminate, Ok(t.clone()));
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

            let version = if self.tuf.root().consistent_snapshot() {
                MetadataVersion::Hash(value.clone())
            } else {
                MetadataVersion::None
            };

            let signed_meta = match self.local
                .fetch_metadata::<TargetsMetadata>(
                    delegation.role(),
                    &MetadataVersion::None,
                    &Some(role_meta.size()),
                    self.config.min_bytes_per_second(),
                    Some((alg, value.clone())),
                )
                .or_else(|_| {
                    self.remote.fetch_metadata::<TargetsMetadata>(
                        delegation.role(),
                        &version,
                        &Some(role_meta.size()),
                        self.config.min_bytes_per_second(),
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

            match self.tuf.update_delegation(delegation.role(), &signed_meta) {
                Ok(_) => {
                    match self.local.store_metadata(
                        delegation.role(),
                        &MetadataVersion::None,
                        &signed_meta,
                    ) {
                        Ok(_) => (),
                        Err(e) => warn!(
                            "Error storing metadata {:?} locally: {:?}",
                            delegation.role(),
                            e
                        ),
                    }

                    let meta = self.tuf
                        .delegations()
                        .get(delegation.role())
                        .unwrap()
                        .clone();
                    let (term, res) = self.lookup_target_description(
                        delegation.terminating(),
                        current_depth + 1,
                        target,
                        snapshot,
                        Some(&meta),
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
}

/// Configuration for a TUF `Client`.
///
/// # Defaults
///
/// The following values are considered reasonably safe defaults, however these values may change
/// as this crate moves out of beta. If you are concered about them changing, you should use the
/// `ConfigBuilder` and set your own values.
///
/// ```
/// # use tuf::client::{Config, DefaultTranslator};
/// let config = Config::default();
/// assert_eq!(config.max_root_size(), &Some(1024 * 1024));
/// assert_eq!(config.max_timestamp_size(), &Some(32 * 1024));
/// assert_eq!(config.min_bytes_per_second(), 4096);
/// assert_eq!(config.max_delegation_depth(), 8);
/// let _: &DefaultTranslator = config.path_translator();
/// ```
#[derive(Debug)]
pub struct Config<T>
where
    T: PathTranslator,
{
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
    min_bytes_per_second: u32,
    max_delegation_depth: u32,
    path_translator: T,
}

impl Config<DefaultTranslator> {
    /// Initialize a `ConfigBuilder` with the default values.
    pub fn build() -> ConfigBuilder<DefaultTranslator> {
        ConfigBuilder::default()
    }
}

impl<T> Config<T>
where
    T: PathTranslator,
{
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

    /// The `PathTranslator`.
    pub fn path_translator(&self) -> &T {
        &self.path_translator
    }
}

impl Default for Config<DefaultTranslator> {
    fn default() -> Self {
        Config {
            max_root_size: Some(1024 * 1024),
            max_timestamp_size: Some(32 * 1024),
            min_bytes_per_second: 4096,
            max_delegation_depth: 8,
            path_translator: DefaultTranslator::new(),
        }
    }
}

/// Helper for building and validating a TUF client `Config`.
#[derive(Debug, PartialEq)]
pub struct ConfigBuilder<T>
where
    T: PathTranslator,
{
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
    min_bytes_per_second: u32,
    max_delegation_depth: u32,
    path_translator: T,
}

impl<T> ConfigBuilder<T>
where
    T: PathTranslator,
{
    /// Validate this builder return a `Config` if validation succeeds.
    pub fn finish(self) -> Result<Config<T>> {
        Ok(Config {
            max_root_size: self.max_root_size,
            max_timestamp_size: self.max_timestamp_size,
            min_bytes_per_second: self.min_bytes_per_second,
            max_delegation_depth: self.max_delegation_depth,
            path_translator: self.path_translator,
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

    /// Set the `PathTranslator`.
    pub fn path_translator<TT>(self, path_translator: TT) -> ConfigBuilder<TT>
    where
        TT: PathTranslator,
    {
        ConfigBuilder {
            max_root_size: self.max_root_size,
            max_timestamp_size: self.max_timestamp_size,
            min_bytes_per_second: self.min_bytes_per_second,
            max_delegation_depth: self.max_delegation_depth,
            path_translator,
        }
    }
}

impl Default for ConfigBuilder<DefaultTranslator> {
    fn default() -> ConfigBuilder<DefaultTranslator> {
        let cfg = Config::default();
        ConfigBuilder {
            max_root_size: cfg.max_root_size,
            max_timestamp_size: cfg.max_timestamp_size,
            min_bytes_per_second: cfg.min_bytes_per_second,
            max_delegation_depth: cfg.max_delegation_depth,
            path_translator: cfg.path_translator,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use crypto::{PrivateKey, SignatureScheme};
    use interchange::Json;
    use metadata::{MetadataPath, MetadataVersion, RoleDefinition, RootMetadata, SignedMetadata};
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
            keys.iter()
                .map(|b| PrivateKey::from_pkcs8(b, SignatureScheme::Ed25519).unwrap())
                .collect()
        };
    }

    #[test]
    fn root_chain_update() {
        let repo = EphemeralRepository::new();
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
        let root: SignedMetadata<Json, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[0]).unwrap();

        repo.store_metadata(
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::Number(1),
            &root,
        ).unwrap();

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
        let mut root: SignedMetadata<Json, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[1]).unwrap();

        root.add_signature(&KEYS[0]).unwrap();

        repo.store_metadata(
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
        let mut root: SignedMetadata<Json, RootMetadata> =
            SignedMetadata::new(&root, &KEYS[2]).unwrap();

        root.add_signature(&KEYS[1]).unwrap();

        repo.store_metadata(
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::Number(3),
            &root,
        ).unwrap();
        repo.store_metadata(
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::None,
            &root,
        ).unwrap();

        let mut client = Client::new(
            Config::build().finish().unwrap(),
            repo,
            EphemeralRepository::new(),
        ).unwrap();
        assert_eq!(client.update_local(), Ok(true));
        assert_eq!(client.tuf.root().version(), 3);
    }
}
