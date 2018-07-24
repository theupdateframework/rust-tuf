//! Clients for high level interactions with TUF repositories.
//!
//! # Example
//!
//! ```no_run
//! extern crate futures;
//! extern crate futures_fs;
//! extern crate hyper;
//! extern crate tuf;
//! extern crate url;
//!
//! use futures::Future;
//! use hyper::client::Client as HttpClient;
//! use std::path::PathBuf;
//! use tuf::Tuf;
//! use tuf::crypto::KeyId;
//! use tuf::client::{Client, Config};
//! use tuf::metadata::{RootMetadata, SignedMetadata, Role, MetadataPath,
//!     MetadataVersion};
//! use tuf::interchange::Json;
//! use tuf::repository::{Repository, FileSystemRepository, HttpRepository};
//! use url::Url;
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
//!     let pool = futures_fs::FsPool::new(1);
//!     let local = FileSystemRepository::<Json>::new(pool, PathBuf::from("~/.rustup"))
//!         .unwrap();
//!
//!     let remote = HttpRepository::new(
//!         Url::parse("https://static.rust-lang.org/").unwrap(),
//!         HttpClient::new(),
//!         Some("rustup/1.4.0".into()),
//!         None);
//!
//!     let mut client = Client::with_root_pinned(
//!         key_ids,
//!         Config::default(),
//!         local,
//!         remote,
//!     ).wait().unwrap();
//!     let _ = client.update_local().wait().unwrap();
//!     let _ = client.update_remote().wait().unwrap();
//! }
//! ```

use std::io::Write;
use std::iter::Iterator;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use crypto::{self, KeyId};
use error::Error;
use futures::future::{Either, Loop, loop_fn};
use futures::{future, Future, Stream};
use interchange::DataInterchange;
use metadata::{
    MetadataPath, MetadataVersion, Role, RootMetadata, SnapshotMetadata, TargetDescription,
    TargetPath, TargetsMetadata, VirtualTargetPath,
};
use repository::Repository;
use tuf::Tuf;
use util::{future_ok, future_err};
use {TufFuture, TufStream, Result};

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
    D: DataInterchange + 'static,
    L: Repository<D> + 'static,
    R: Repository<D> + 'static,
    T: PathTranslator + 'static,
{
    tuf: Arc<Mutex<Tuf<D>>>,
    config: Arc<Config<T>>,
    local: Arc<L>,
    remote: Arc<R>,
}

impl<D, L, R, T> Client<D, L, R, T>
where
    D: DataInterchange + 'static,
    L: Repository<D>  + 'static,
    R: Repository<D> + 'static,
    T: PathTranslator + 'static,
{
    /// Create a new TUF client. It will attempt to load initial root metadata from the local repo
    /// and return an error if it cannot do so.
    ///
    /// **WARNING**: This method offers weaker security guarantees than the related method
    /// `with_root_pinned`.
    pub fn new(config: Config<T>, local: L, remote: R) -> TufFuture<Self> {
        let local = Arc::new(local);
        let remote = Arc::new(remote);

        let max_root_size = config.max_root_size;
        let min_bytes_per_second = config.min_bytes_per_second;

        let client = local.fetch_metadata(
                &MetadataPath::from_role(&Role::Root),
                &MetadataVersion::Number(1),
                max_root_size,
                min_bytes_per_second,
                None,
            )
            .and_then(move |root| {
                let tuf = Tuf::from_root(&root)?;

                Ok(Client {
                    tuf: Arc::new(Mutex::new(tuf)),
                    config: Arc::new(config),
                    local,
                    remote,
                })
            });

        Box::new(client)
    }

    /// Create a new TUF client. It will attempt to load initial root metadata the local and remote
    /// repositories using the provided key IDs to pin the verification.
    ///
    /// This is the preferred method of creating a client.
    pub fn with_root_pinned<I>(
        trusted_root_keys: I,
        config: Config<T>,
        local: L,
        remote: R,
    ) -> TufFuture<Self>
    where
        I: IntoIterator<Item = KeyId> + 'static,
        T: PathTranslator,
    {
        let local = Arc::new(local);
        let remote = Arc::new(remote);

        let remote_ = remote.clone();
        let max_root_size = config.max_root_size;
        let min_bytes_per_second = config.min_bytes_per_second;

        let client = local
            .fetch_metadata(
                &MetadataPath::from_role(&Role::Root),
                &MetadataVersion::Number(1),
                max_root_size,
                min_bytes_per_second,
                None,
            )
            .or_else(move |_| {
                remote_.fetch_metadata(
                    &MetadataPath::from_role(&Role::Root),
                    &MetadataVersion::Number(1),
                    max_root_size,
                    min_bytes_per_second,
                    None,
                )
            })
            .and_then(move |root| {
                let tuf = Tuf::from_root_pinned(root, trusted_root_keys)?;

                Ok(Client {
                    tuf: Arc::new(Mutex::new(tuf)),
                    config: Arc::new(config),
                    local,
                    remote,
                })
            });

        Box::new(client)
    }

    /// Update TUF metadata from the local repository.
    ///
    /// Returns `true` if an update occurred and `false` otherwise.
    pub fn update_local(&mut self) -> TufFuture<bool> {
        let tuf1 = self.tuf.clone();
        let tuf2 = self.tuf.clone();
        let tuf3 = self.tuf.clone();
        let tuf4 = self.tuf.clone();

        let config1 = self.config.clone();
        let config2 = self.config.clone();
        let config3 = self.config.clone();
        let config4 = self.config.clone();

        let local1 = self.local.clone();
        let local2 = self.local.clone();
        let local3 = self.local.clone();
        let local4 = self.local.clone();

        Box::new(
            Self::update_root(tuf1, local1, config1)
                .and_then(move |r| {
                    Self::update_timestamp(tuf2, local2, config2)
                        .or_else(|e| {
                            warn!(
                                "Error updating root metadata from local sources: {:?}",
                                e
                            );
                            Ok(false)
                        })
                        .and_then(move |ts| {
                            Self::update_snapshot(tuf3, local3, config3)
                                .or_else(|e| {
                                    warn!(
                                        "Error updating snapshot metadata from local sources: {:?}",
                                        e
                                    );
                                    Ok(false)
                                })
                                .and_then(move |sn| {
                                    Self::update_targets(tuf4, local4, config4)
                                        .or_else(|e| {
                                            warn!(
                                                "Error updating targets metadata from local sources: {:?}",
                                                e
                                            );
                                            Ok(false)
                                        })
                                        .and_then(move |ta| {
                                            Ok(r || ts || sn || ta)
                                        })
                                })
                        })
                })
        )
    }

    /// Update TUF metadata from the remote repository.
    ///
    /// Returns `true` if an update occurred and `false` otherwise.
    pub fn update_remote(&mut self) -> TufFuture<bool> {
        let tuf1 = self.tuf.clone();
        let tuf2 = self.tuf.clone();
        let tuf3 = self.tuf.clone();
        let tuf4 = self.tuf.clone();

        let config1 = self.config.clone();
        let config2 = self.config.clone();
        let config3 = self.config.clone();
        let config4 = self.config.clone();

        let remote1 = self.remote.clone();
        let remote2 = self.remote.clone();
        let remote3 = self.remote.clone();
        let remote4 = self.remote.clone();

        Box::new(
            Self::update_root(tuf1, remote1, config1)
                .and_then(move |r| {
                    Self::update_timestamp(tuf2, remote2, config2)
                        .and_then(move |ts| {
                            Self::update_snapshot(tuf3, remote3, config3)
                                .and_then(move |sn| {
                                    Self::update_targets(tuf4, remote4, config4)
                                        .and_then(move |ta| {
                                            Ok(r || ts || sn || ta)
                                        })
                                })
                        })
                })
        )
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_root<V, U>(tuf: Arc<Mutex<Tuf<D>>>, repo: Arc<V>, config: Arc<Config<U>>) -> TufFuture<bool>
    where
        V: Repository<D> + 'static,
        U: PathTranslator,
    {
        let err_msg = "TUF claimed no update occurred when one should have. \
                       This is a programming error. Please report this as a bug.";

        //let tuf = self.tuf.clone();
        let max_root_size = config.max_root_size;
        let min_bytes_per_second = config.min_bytes_per_second;

        let updated =
            repo.fetch_metadata(
                &MetadataPath::from_role(&Role::Root),
                &MetadataVersion::None,
                max_root_size,
                min_bytes_per_second,
                None,
            )
            .and_then(move |latest_root| {
                let latest_version =
                    D::deserialize::<RootMetadata>(latest_root.signed())?.version();

                let root_version = {
                    let tuf = tuf.lock().expect("poisoned lock");
                    tuf.root().version()
                };

                if latest_version < root_version {
                    return Err(Error::VerificationFailure(format!(
                        "Latest root version is lower than current root version: {} < {}",
                        latest_version, root_version,
                    )));
                } else if latest_version == root_version {
                    return Ok(Either::A(future::ok(false)));
                }

                let mut updated_roots = Vec::new();
                for i in (root_version + 1)..latest_version {
                    let tuf = tuf.clone();

                    updated_roots.push(
                        repo
                            .fetch_metadata(
                                &MetadataPath::from_role(&Role::Root),
                                &MetadataVersion::Number(i),
                                max_root_size,
                                min_bytes_per_second,
                                None,
                            )
                            .map(move |signed| {
                                let mut tuf = tuf.lock().expect("poisoned lock");

                                if !tuf.update_root(&signed)? {
                                    error!("{}", err_msg);
                                    return Err(Error::Programming(err_msg.into()));
                                }

                                Ok(())
                            }),
                    );
                }

                Ok(Either::B(future::join_all(updated_roots).and_then(
                    move |_| {
                        let mut tuf = tuf.lock().expect("poisoned lock");

                        if !tuf.update_root(&latest_root)? {
                            error!("{}", err_msg);
                            return Err(Error::Programming(err_msg.into()));
                        }

                        Ok(true)
                    }
                )))
            })
            .flatten();

        Box::new(updated)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_timestamp<V, U>(tuf: Arc<Mutex<Tuf<D>>>, repo: Arc<V>, config: Arc<Config<U>>) -> TufFuture<bool>
    where
        V: Repository<D>,
        U: PathTranslator,
    {
        let ts = repo
            .fetch_metadata(
                &MetadataPath::from_role(&Role::Timestamp),
                &MetadataVersion::None,
                config.max_timestamp_size,
                config.min_bytes_per_second,
                None,
            )
            .and_then(move |ts| {
                let mut tuf = tuf.lock().expect("poisoned lock");
                tuf.update_timestamp(&ts)
            });

        Box::new(ts)
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_snapshot<V, U>(tuf: Arc<Mutex<Tuf<D>>>, repo: Arc<V>, config: Arc<Config<U>>) -> TufFuture<bool>
    where
        V: Repository<D>,
        U: PathTranslator,
    {
        let snap = {
            let tuf = tuf.lock().expect("poisoned lock");

            let snapshot_description = match tuf.timestamp() {
                Some(ts) => ts.snapshot().clone(),
                None => {
                    return future_err(Error::MissingMetadata(Role::Timestamp));
                }
            };

            let (alg, value) = try_future!(
                crypto::hash_preference(snapshot_description.hashes())
            );

            if snapshot_description.version() <= tuf.snapshot().map(|s| s.version()).unwrap_or(0) {
                return future_ok(false);
            }

            let version = if tuf.root().consistent_snapshot() {
                MetadataVersion::Number(snapshot_description.version())
            } else {
                MetadataVersion::None
            };

            repo.fetch_metadata(
                &MetadataPath::from_role(&Role::Snapshot),
                &version,
                Some(snapshot_description.size()),
                config.min_bytes_per_second,
                Some((alg, value.clone())),
            )
        };

        Box::new(
            snap.and_then(move |snap| {
                let mut tuf = tuf.lock().unwrap();
                tuf.update_snapshot(&snap)
            })
        )
    }

    /// Returns `true` if an update occurred and `false` otherwise.
    fn update_targets<V, U>(tuf: Arc<Mutex<Tuf<D>>>, repo: Arc<V>, config: Arc<Config<U>>) -> TufFuture<bool>
    where
        V: Repository<D>,
        U: PathTranslator,
    {
        let targets = {
            let tuf = tuf.lock().expect("poisoned lock");

            let targets_description = match tuf.snapshot() {
                Some(sn) => match sn.meta().get(&MetadataPath::from_role(&Role::Targets)) {
                    Some(d) => d,
                    None => {
                        return Box::new(future::err(Error::VerificationFailure(
                            "Snapshot metadata did not contain a description of the \
                             current targets metadata."
                                .into(),
                        )));
                    }
                },
                None => {
                    return Box::new(future::err(Error::MissingMetadata(Role::Snapshot)));
                }
            };

            if targets_description.version() <= tuf.targets().map(|t| t.version()).unwrap_or(0) {
                return Box::new(future::ok(false));
            }

            let (alg, value) = try_future!(crypto::hash_preference(targets_description.hashes()));

            let version = if tuf.root().consistent_snapshot() {
                MetadataVersion::Hash(value.clone())
            } else {
                MetadataVersion::None
            };

            repo.fetch_metadata(
                &MetadataPath::from_role(&Role::Targets),
                &version,
                Some(targets_description.size()),
                config.min_bytes_per_second,
                Some((alg, value.clone())),
            )
        };

        Box::new(
            targets.and_then(move |targets| {
                let mut tuf = tuf.lock().unwrap();
                tuf.update_targets(&targets)
            })
        )
    }

    /// Fetch a target from the remote repo and write it to the local repo.
    pub fn fetch_target(&mut self, target: &TargetPath) -> TufFuture<()> {
        let stream = self.fetch_target_stream(target);
        self.local.store_target(stream, target)
    }

    /// Fetch a target from the remote repo and write it to the provided writer.
    pub fn fetch_target_to_writer<W: Write + 'static>(
        &mut self,
        target: &TargetPath,
        mut write: W,
    ) -> TufFuture<()> {
        Box::new(
            self.fetch_target_stream(&target)
                .for_each(move |bytes| {
                    write.write_all(&bytes)?;
                    Ok(())
                })
        )
    }

    // TODO this should check the local repo first
    fn fetch_target_stream(&mut self, target: &TargetPath) -> TufStream<Bytes> {
        let virt = try_stream!(self.config.path_translator.real_to_virtual(target));

        let snapshot = {
            let tuf = self.tuf.lock().unwrap();
            try_stream!(tuf.snapshot().ok_or_else(|| Error::MissingMetadata(Role::Snapshot)))
                .clone()
        };

        let target = target.clone();
        let remote = self.remote.clone();
        let min_bytes_per_second = self.config.min_bytes_per_second;

        Box::new(
            Self::lookup_target_description(
                self.tuf.clone(),
                self.config.max_delegation_depth,
                min_bytes_per_second,
                false,
                0,
                Arc::new(virt),
                snapshot,
                None,
                self.local.clone(),
                self.remote.clone(),
            )
                .map(move |target_description| {
                    remote.fetch_target(
                        &target,
                        &target_description,
                        min_bytes_per_second,
                    )
                })
                .map_err(|(_, err)| err)
                .flatten_stream()
        )
    }

    fn lookup_target_description<D_, L_, R_>(
        tuf: Arc<Mutex<Tuf<D_>>>,
        max_delegation_depth: u32,
        min_bytes_per_second: u32,
        default_terminate: bool,
        current_depth: u32,
        target: Arc<VirtualTargetPath>,
        snapshot: Arc<SnapshotMetadata>,
        targets: Option<Arc<TargetsMetadata>>,
        local: Arc<L_>,
        remote: Arc<R_>,
    ) -> Box<Future<Item=TargetDescription, Error=(bool, Error)>>
    where
        D_: DataInterchange + 'static,
        L_: Repository<D_> + 'static,
        R_: Repository<D_> + 'static,
    {
        if current_depth > max_delegation_depth {
            warn!(
                "Walking the delegation graph would have exceeded the configured max depth: {}",
                max_delegation_depth
            );
            return future_err((default_terminate, Error::NotFound));
        }

        let delegations = {
            let tuf = tuf.lock().expect("poisoned lock");

            let targets = if let Some(targets) = targets {
                targets.clone()
            } else if let Some(targets) = tuf.targets() {
                targets.clone()
            } else {
                return future_err((default_terminate, Error::MissingMetadata(Role::Targets)));
            };

            if let Some(target) = targets.targets().get(&target) {
                return future_ok(target.clone());
            }

            if let Some(delegations) = targets.delegations() {
                // this clone is dumb, but we need immutable values and not references for update
                // tuf in the loop below
                delegations.roles().clone().into_iter()
            } else {
                return future_err((default_terminate, Error::NotFound));
            }
        };

        Box::new(
            loop_fn(delegations, move |mut delegations| {
                let snapshot = snapshot.clone();

                let delegation = if let Some(delegation) = delegations.next() {
                    delegation
                } else {
                    return future_err((default_terminate, Error::NotFound));
                };

                if !delegation.paths().iter().any(|p| target.is_child(p)) {
                    if delegation.terminating() {
                        return future_err((true, Error::NotFound));
                    } else {
                        return future_ok(Loop::Continue(delegations));
                    }
                }

                let role_meta = if let Some(m) = snapshot.meta().get(delegation.role()) {
                    m
                } else {
                    if delegation.terminating() {
                        return future_err((true, Error::NotFound));
                    } else {
                        return future_ok(Loop::Continue(delegations));
                    }
                };

                let (alg, value) = match crypto::hash_preference(role_meta.hashes()) {
                    Ok((alg, value)) => (alg, value.clone()),
                    Err(e) => {
                        return future_err((delegation.terminating(), e));
                    }
                };

                let version = {
                    let tuf = tuf.lock().unwrap();

                    if tuf.root().consistent_snapshot() {
                        MetadataVersion::Hash(value.clone())
                    } else {
                        MetadataVersion::None
                    }
                };

                let tuf = tuf.clone();
                let target = target.clone();
                let snapshot = snapshot.clone();
                let local = local.clone();
                let remote1 = remote.clone();
                let remote2 = remote.clone();
                let delegation = Arc::new(delegation);
                let delegation1 = delegation.clone();
                let role_meta_size = role_meta.size();
                let value1 = value.clone();

                Box::new(
                    local
                        .fetch_metadata(
                            delegation.role(),
                            &MetadataVersion::None,
                            Some(role_meta_size),
                            min_bytes_per_second,
                            Some((alg, value)),
                        )
                        .or_else(move |_| {
                            remote1.fetch_metadata(
                                delegation.role(),
                                &version,
                                Some(role_meta_size),
                                min_bytes_per_second,
                                Some((alg, value1)),
                            )
                        })
                        .then(move |result| {
                            let signed_meta = match result {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!("Failed to fetch metadata {:?}: {:?}", delegation1.role(), e);
                                    if delegation1.terminating() {
                                        return future_err((true, e));
                                    } else {
                                        return future_ok(Loop::Continue(delegations));
                                    }
                                }
                            };

                            let result = {
                                let mut tuf = tuf.lock().expect("poisoned lock");
                                tuf.update_delegation(delegation1.role(), &signed_meta)
                            };

                            if let Err(err) = result {
                                if delegation1.terminating() {
                                    return future_err((true, err));
                                } else {
                                    return future_ok(Loop::Continue(delegations));
                                }
                            }

                            Box::new(
                                local
                                    .store_metadata(
                                        delegation1.role(),
                                        &MetadataVersion::None,
                                        &signed_meta,
                                    )
                                    .then(move |result| {
                                        if let Err(err) = result {
                                            warn!(
                                                "Error storing metadata {:?} locally: {:?}",
                                                delegation1.role(),
                                                err
                                            );
                                        }

                                        let meta = {
                                            let tuf = tuf.lock().unwrap();
                                            tuf.get_delegation(delegation1.role()).unwrap()
                                        };

                                        Self::lookup_target_description::<D_, L_, R_>(
                                            tuf,
                                            max_delegation_depth,
                                            min_bytes_per_second,
                                            delegation1.terminating(),
                                            current_depth + 1,
                                            target,
                                            snapshot,
                                            Some(meta),
                                            local,
                                            remote2,
                                        ).then(|result| {
                                            match result {
                                                Err((true, err)) => {
                                                    Err((true, err))
                                                }
                                                Err((false, err)) => {
                                                    warn!(
                                                        "Error looking up target description: {:?}",
                                                        err
                                                    );
                                                    Ok(Loop::Continue(delegations))
                                                }
                                                _ => {
                                                    Ok(Loop::Continue(delegations))
                                                }
                                            }
                                        })
                                    })
                            )
                        })
                )
            })
                .and_then(move |loop_result: Loop<_, (bool, Error)>| {
                    match loop_result {
                        Loop::Break(result) => Ok(result),
                        Loop::Continue(_) => Err((default_terminate, Error::NotFound)),
                    }
                })
        )
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
        ).wait().unwrap();

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
        ).wait().unwrap();

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
        ).wait().unwrap();
        repo.store_metadata(
            &MetadataPath::from_role(&Role::Root),
            &MetadataVersion::None,
            &root,
        ).wait().unwrap();

        let mut client = Client::new(
            Config::build().finish().unwrap(),
            repo,
            EphemeralRepository::new(),
        ).wait().unwrap();
        assert_eq!(client.update_local().wait(), Ok(true));
        assert_eq!(client.tuf.lock().unwrap().root().version(), 3);
    }
}
