//! Structs and functions for interacting with TUF repositories.

use chrono::UTC;
use json;
use hyper::Url as HyperUrl;
use hyper::client::Client;
use ring::digest;
use ring::digest::{SHA256, SHA512};
use std::collections::{HashMap, HashSet};
use std::collections::vec_deque::VecDeque;
use std::fs::{self, File, DirBuilder};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::{PathBuf, Path};
use url::Url;
use uuid::Uuid;
use walkdir::WalkDir;

use cjson;
use error::Error;
use http;
use metadata::{Role, RoleType, Root, Targets, Timestamp, Snapshot, Metadata, SignedMetadata,
               RootMetadata, TargetsMetadata, TimestampMetadata, SnapshotMetadata, HashType,
               HashValue, KeyId, Key, DelegatedRole};
use util::{self, TempFile};

/// A remote TUF repository.
#[derive(Debug)]
pub enum RemoteRepo {
    /// An untrusted repository on the same file sytem. Primarily used for testing.
    File(PathBuf),
    /// A repository reachable via HTTP/S.
    Http(Url),
}

impl RemoteRepo {
    fn as_fetch(&self) -> FetchType {
        match self {
            &RemoteRepo::File(ref path) => FetchType::File(path.clone()),
            &RemoteRepo::Http(ref url) => FetchType::Http(url.clone()),
        }
    }
}


/// Interface for interacting with TUF repositories.
#[derive(Debug)]
pub struct Tuf {
    remote: RemoteRepo,
    local_path: PathBuf,
    http_client: Client,
    root: RootMetadata,
    targets: Option<TargetsMetadata>,
    timestamp: Option<TimestampMetadata>,
    snapshot: Option<SnapshotMetadata>,
    delegations: HashMap<String, DelegatedRoleContainer>,
}

impl Tuf {
    /// Create a `Tuf` struct from an existing repo with the initial root keys pinned.
    pub fn from_root_keys(root_keys: Vec<Key>, config: Config) -> Result<Self, Error> {
        if config.init {
            Self::initialize(&config.local_path)?;
        }

        let root = {
            let fetch_type = &FetchType::Cache(config.local_path.clone());

            match Self::read_root_with_keys(fetch_type, &config.http_client, &root_keys) {
                Ok(modified_root) => {
                    Self::get_metadata::<Root, RootMetadata, File>(fetch_type,
                                                                   &config.http_client,
                                                                   &Role::Root,
                                                                   Some(1),
                                                                   true,
                                                                   modified_root.root.threshold,
                                                                   &modified_root.root.key_ids,
                                                                   &modified_root.keys,
                                                                   None,
                                                                   None,
                                                                   &mut None)?
                }
                Err(e) => {
                    debug!("Failed to read root locally: {:?}", e);
                    let fetch_type = &config.remote.as_fetch();
                    let modified_root =
                        Self::read_root_with_keys(fetch_type, &config.http_client, &root_keys)?;
                    Self::get_metadata::<Root, RootMetadata, File>(fetch_type,
                                                                   &config.http_client,
                                                                   &Role::Root,
                                                                   Some(1),
                                                                   true,
                                                                   modified_root.root.threshold,
                                                                   &modified_root.root.key_ids,
                                                                   &modified_root.keys,
                                                                   None,
                                                                   None,
                                                                   &mut None)?
                }
            }
        };

        let mut tuf = Tuf {
            remote: config.remote,
            local_path: config.local_path,
            http_client: config.http_client,
            root: root,
            targets: None,
            timestamp: None,
            snapshot: None,
            delegations: HashMap::new(),
        };

        tuf.update()?;
        Ok(tuf)
    }

    /// Create a `Tuf` struct from a new repo. Must contain the `root.json`. The root is trusted
    /// with only verification on consistency, not authenticity.
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.init {
            Self::initialize(&config.local_path)?;
        }

        let root = {
            let fetch_type = &FetchType::Cache(config.local_path.clone());
            let (_, root) =
                Self::unverified_read_root(fetch_type, &config.http_client, None)?;

            Self::get_metadata::<Root, RootMetadata, File>(fetch_type,
                                                           &config.http_client,
                                                           &Role::Root,
                                                           None,
                                                           true,
                                                           root.root.threshold,
                                                           &root.root.key_ids,
                                                           &root.keys,
                                                           None,
                                                           None,
                                                           &mut None)?
        };

        let mut tuf = Tuf {
            remote: config.remote,
            local_path: config.local_path,
            http_client: config.http_client,
            root: root,
            targets: None,
            timestamp: None,
            snapshot: None,
            delegations: HashMap::new(),
        };
        tuf.update()?;

        Ok(tuf)
    }

    /// Create and verify the necessary directory structure for a TUF repo.
    pub fn initialize(local_path: &PathBuf) -> Result<(), Error> {
        info!("Initializing local storage: {}",
              local_path.to_string_lossy());

        for dir in vec![PathBuf::from("metadata"),
                        PathBuf::from("targets"),
                        PathBuf::from("temp")]
            .iter() {
            let path = local_path.as_path().join(dir);
            debug!("Creating path: {}", path.to_string_lossy());
            DirBuilder::new().recursive(true).create(path)?
            // TODO error if path is not fully owned by the current user
        }

        Ok(())
    }

    // TODO clean function that cleans up local_path for old targets, old dirs, etc

    fn temp_file(&self) -> Result<TempFile, Error> {
        Ok(TempFile::new(self.local_path.join("temp"))?)
    }

    /// Update the metadata from local and remote sources.
    pub fn update(&mut self) -> Result<(), Error> {
        info!("Updating metdata");
        match self.update_local() {
            Ok(()) => (),
            Err(e) => warn!("Error updating metadata from local sources: {:?}", e),
        };
        self.update_remote()?;
        info!("Successfully updated metadata");
        Ok(())
    }

    fn update_remote(&mut self) -> Result<(), Error> {
        debug!("Updating metadata from remote sources");
        let fetch_type = &self.remote.as_fetch();
        self.update_root(fetch_type)?;

        if self.update_timestamp(fetch_type)? {
            let old_snapshot = self.update_snapshot(fetch_type)?;
            self.update_targets(fetch_type)?;
            self.update_delegations(old_snapshot, fetch_type)
        } else {
            Ok(())
        }
    }

    fn update_local(&mut self) -> Result<(), Error> {
        debug!("Updating metadata from local sources");
        let fetch_type = &FetchType::Cache(self.local_path.clone());

        self.update_root(fetch_type)?;

        if self.update_timestamp(fetch_type)? {
            let old_snapshot = self.update_snapshot(fetch_type)?;
            self.update_targets(fetch_type)?;
            self.update_delegations(old_snapshot, fetch_type)
        } else {
            Ok(())
        }
    }

    fn update_root(&mut self, fetch_type: &FetchType) -> Result<(), Error> {
        debug!("Updating root metadata");

        let (_, temp_root) =
            Self::unverified_read_root(fetch_type, &self.http_client, Some(self.local_path.as_path()))?;

        // handle the edge case where we never enter the update look
        // AND the first piece of metadata is expired
        if temp_root.version == 1 && self.root.expires() <= &UTC::now() {
            return Err(Error::ExpiredMetadata(Role::Root));
        }

        // TODO reuse temp root as last one
        for i in (self.root.version + 1)..(temp_root.version + 1) {
            let mut temp_file = if !fetch_type.is_cache() {
                Some(self.temp_file()?)
            } else {
                None
            };

            let root = Self::get_metadata::<Root, RootMetadata, TempFile>(fetch_type,
                                                                      &self.http_client,
                                                                      &Role::Root,
                                                                      Some(i),
                                                                      true,
                                                                      self.root.root.threshold,
                                                                      &self.root.root.key_ids,
                                                                      &self.root.keys,
                                                                      None,
                                                                      None,
                                                                      &mut temp_file)?;

            // verify root again against itself (for cross signing)
            // TODO this is not the most efficient way to do it, but it works
            let root_again =
                Self::get_metadata::<Root, RootMetadata, File>(fetch_type,
                                                               &self.http_client,
                                                               &Role::Root,
                                                               Some(i),
                                                               false,
                                                               root.root.threshold,
                                                               &root.root.key_ids,
                                                               &root.keys,
                                                               None,
                                                               None,
                                                               &mut None::<File>)?;
            if root != root_again {
                // TODO better error message
                return Err(Error::Generic(format!("Cross singning of root version {} failed", i)));
            }

            info!("Rotated to root metadata version {}", i);
            self.root = root;

            match temp_file {
                Some(temp_file) => {
                    temp_file.persist(&self.local_path
                                           .join("metadata")
                                           .join(format!("{}.root.json", i)))?
                }
                None => (),
            };

            self.purge_metadata()?;
        }

        Ok(())
    }

    fn update_timestamp(&mut self, fetch_type: &FetchType) -> Result<bool, Error> {
        debug!("Updating timestamp metadata");

        let mut temp_file = if !fetch_type.is_cache() {
            Some(self.temp_file()?)
        } else {
            None
        };

        let timestamp =
            Self::get_metadata::<Timestamp, TimestampMetadata, TempFile>(fetch_type,
                                                                     &self.http_client,
                                                                     &Role::Timestamp,
                                                                     None,
                                                                     false,
                                                                     self.root.timestamp.threshold,
                                                                     &self.root.timestamp.key_ids,
                                                                     &self.root.keys,
                                                                     None,
                                                                     None,
                                                                     &mut temp_file)?;

        match self.timestamp {
            Some(ref t) if t.version > timestamp.version => {
                return Err(Error::VersionDecrease(Role::Timestamp));
            }
            Some(ref t) if t.version == timestamp.version => return Ok(false),
            _ => self.timestamp = Some(timestamp),
        }

        if let Some(ref timestamp) = self.timestamp {
            if let Some(ref timestamp_meta) = timestamp.meta.get("snapshot.json") {
                if timestamp_meta.version > timestamp.version {
                    info!("Timestamp metadata is up to date");
                    return Ok(false);
                }
            }
        }

        match temp_file {
            Some(temp_file) => {
                let current_path = self.local_path
                    .join("metadata")
                    .join("timestamp.json");

                if current_path.exists() {
                    fs::remove_file(&current_path)?;
                };

                temp_file.persist(&current_path)?
            }
            None => (),
        };

        Ok(true)
    }

    fn update_snapshot(&mut self, fetch_type: &FetchType) -> Result<Option<SnapshotMetadata>, Error> {
        debug!("Updating snapshot metadata");

        let meta = match self.timestamp {
            Some(ref timestamp) => {
                match timestamp.meta.get("snapshot.json") {
                    Some(meta) => meta,
                    None => {
                        return Err(Error::VerificationFailure("Missing snapshot.json in \
                                                               timestamp.json"
                            .to_string()))
                    }
                }
            }
            None => return Err(Error::MissingMetadata(Role::Timestamp)),
        };

        let (hash_alg, expected_hash): (&HashType, &HashValue) = HashType::preferences().iter()
            .fold(None, |res, pref| {
                res.or_else(|| if let Some(hash) = meta.hashes.get(&pref) {
                    Some((pref, hash))
                } else {
                    None
                })
            })
            .ok_or_else(|| Error::NoSupportedHashAlgorithms)?;

        let mut temp_file = if !fetch_type.is_cache() {
            Some(self.temp_file()?)
        } else {
            None
        };

        let snapshot = Self::get_metadata::<Snapshot,
                                               SnapshotMetadata,
                                               TempFile>(fetch_type,
                                                     &self.http_client,
                                                     &Role::Snapshot,
                                                     None,
                                                     false,
                                                     self.root.snapshot.threshold,
                                                     &self.root.snapshot.key_ids,
                                                     &self.root.keys,
                                                     Some(meta.length),
                                                     Some((&hash_alg, &expected_hash.0)),
                                                     &mut temp_file)?;
        // TODO ? check downloaded version matches what was in the timestamp.json

        let old_snapshot = match self.snapshot {
            Some(ref s) if s.version > snapshot.version => {
                return Err(Error::VersionDecrease(Role::Snapshot));
            }
            _ => {
                let old_snapshot = self.snapshot.take();
                self.snapshot = Some(snapshot);
                old_snapshot
            },
        };

        match temp_file {
            Some(temp_file) => {
                let current_path = self.local_path
                    .join("metadata")
                    .join("snapshot.json");

                if current_path.exists() {
                    fs::remove_file(&current_path)?;
                };

                temp_file.persist(&current_path)?
            }
            None => (),
        };

        Ok(old_snapshot)
    }

    fn update_targets(&mut self, fetch_type: &FetchType) -> Result<(), Error> {
        debug!("Updating targets metadata");

        let meta = match self.snapshot {
            Some(ref snapshot) => {
                match snapshot.meta.get("targets.json") {
                    Some(meta) => meta,
                    None => {
                        return Err(Error::VerificationFailure("Missing targets.json in \
                                                               snapshot.json"
                            .to_string()))
                    }
                }
            }
            None => return Err(Error::MissingMetadata(Role::Snapshot)),
        };

        let hash_data = match meta.hashes {
            Some(ref hashes) => {
                Some(HashType::preferences().iter()
                    .fold(None, |res, pref| {
                        res.or_else(|| if let Some(hash) = hashes.get(&pref) {
                            Some((pref, hash))
                        } else {
                            None
                        })
                    })
                    .ok_or_else(|| Error::NoSupportedHashAlgorithms)?)
            }
            None => None,
        };

        let hash_data = hash_data.map(|(t, v)| (t, v.0.as_slice()));

        let mut temp_file = if !fetch_type.is_cache() {
            Some(self.temp_file()?)
        } else {
            None
        };

        let targets = Self::get_metadata::<Targets, TargetsMetadata, TempFile>(fetch_type,
                                                                           &self.http_client,
                                                                           &Role::Targets,
                                                                           None,
                                                                           false,
                                                                           self.root.targets.threshold,
                                                                           &self.root.targets.key_ids,
                                                                           &self.root.keys,
                                                                           meta.length,
                                                                           hash_data,
                                                                           &mut temp_file)?;

        // TODO ? check downloaded version matches what was in the snapshot.json

        match self.targets {
            Some(ref t) if t.version > targets.version => {
                return Err(Error::VersionDecrease(Role::Targets));
            }
            Some(ref t) if t.version == targets.version => return Ok(()),
            _ => self.targets = Some(targets),
        }

        match temp_file {
            Some(temp_file) => {
                let current_path = self.local_path
                    .join("metadata")
                    .join("targets.json");

                if current_path.exists() {
                    fs::remove_file(&current_path)?;
                };

                temp_file.persist(&current_path)?
            }
            None => (),
        };

        Ok(())
    }

    // TODO omg so much cloning had to happen just to make the work
    // come back later and clean this up once all the features are stable
    fn update_delegations(&mut self, old_snapshot: Option<SnapshotMetadata>, fetch_type: &FetchType) -> Result<(), Error> {
        let snapshot = match self.snapshot.clone() {
            Some(s) => s,
            None => return Err(Error::MissingMetadata(Role::Snapshot)),
        };

        match old_snapshot {
            Some(ref old_snapshot) => {
                for old in old_snapshot.meta.keys().collect::<HashSet<&String>>()
                                       .difference(&snapshot.meta.keys().collect::<HashSet<&String>>()) {
                    debug!("Purging no longer trusted delegation {}", old);
                    match self.delegations.remove(*old) {
                        Some(old) => self.try_remove_meta(&old.role_definition.name),
                        None => (),
                    }
                }
            }
            None => (),
        }

        let targets = match &self.targets {
            &Some(ref t) => t,
            &None => return Err(Error::MissingMetadata(Role::Targets)),
        };

        let delegations = match &targets.delegations {
            &Some(ref d) => d,
            &None => return Ok(()),
        };

        // set these up to do a breadth first traversal of the delegation graph
        let mut visited = HashSet::new();
        let mut to_visit: VecDeque<(Option<String>, DelegatedRole)> = VecDeque::new();
        
        for role in delegations.roles.iter() {
            to_visit.push_back((None, role.clone()));
        }

        // Mr. La Forge, engage.
        while let Some((parent, role)) = to_visit.pop_front() {
            if visited.contains(&role.name) {
                continue
            };
            visited.insert(role.name.clone());

            let result = match (self.delegations.get(&role.name), snapshot.meta.get(&format!("{}.json", role.name))) {
                (None, None) => continue,
                (Some(_), None) => continue,
                (Some(container), Some(meta)) if container.targets.version == meta.version => {
                    warn!("Delegation {} is up to date with what snapshot metadata reports",
                           container.role_definition.name);
                    continue
                }
                (Some(container), Some(meta)) if container.targets.version > meta.version => {
                    warn!("Delegation {} is ahead of what snapshot metadata reports. {} vs. {}",
                          container.role_definition.name, container.targets.version, meta.version);
                    continue
                }
                (_, Some(meta)) => {
                    let parent_container = match parent {
                        Some(p) => match &self.delegations.get(&p) {
                            &Some(p) => Some(p),
                            &None => continue,
                        },
                        None => None
                    };

                    let hash_data = match meta.hashes {
                        Some(ref hashes) => {
                            match HashType::preferences().iter()
                                .fold(None, |res, pref| {
                                    res.or_else(|| if let Some(hash) = hashes.get(&pref) {
                                        Some((pref, hash))
                                    } else {
                                        None
                                    })
                                }) {
                                    Some(pair) => Some(pair.clone()),
                                    None => {
                                        warn!("No suitable hash algorithms. Refusing to trust metadata.");
                                        continue
                                    }
                                }
                        },
                        None => None,
                    };

                    let mut temp_file = if !fetch_type.is_cache() {
                        match self.temp_file() {
                            Ok(t) => Some(t),
                            Err(e) => {
                                warn!("Failed to create temp file for delegation: {:?}", e);
                                continue
                            }
                        }
                    } else {
                        None
                    };

                    let (threshold, key_ids, available_keys) = match &parent_container {
                        &Some(parent) => {
                            (parent.role_definition.threshold,
                             &parent.role_definition.key_ids,
                             parent.targets.delegations.clone().map(|d| d.keys).unwrap_or_else(|| HashMap::new()))
                        }
                        &None => {
                            match delegations.roles.iter().filter(|d| d.name == role.name).next() {
                                Some(role_def) => (role_def.threshold, &role_def.key_ids, delegations.keys.clone()),
                                None => continue,
                            }
                        }
                    };

                    match Tuf::get_metadata::<Targets,
                                              TargetsMetadata,
                                              TempFile>(&self.remote.as_fetch(),
                                                        &self.http_client,
                                                        &Role::TargetsDelegation(role.name.clone()),
                                                        None,
                                                        false,
                                                        threshold,
                                                        key_ids,
                                                        &available_keys,
                                                        meta.length,
                                                        hash_data.map(|(a, h)| (a, &*h.0)),
                                                        &mut temp_file) {
                        Ok(meta) => {
                            let container = match parent_container {
                                Some(p) => p.clone(),
                                None => match &delegations.roles.iter()
                                    .filter(|d| d.name == role.name)
                                    .next()
                                    .cloned()
                                    .map(|ref p| {
                                        DelegatedRoleContainer {
                                            parent: Some(role.name.clone()),
                                            targets: meta,
                                            role_definition: p.clone(),
                                        }
                                    }) {
                                        &Some(ref c) => c,
                                        &None => continue
                                    }
                            };

                            match meta.delegations {
                                Some(delegations) => for r in delegations.roles.iter() {
                                    to_visit.push_back((Some(role.name.clone()), r.clone()));
                                },
                                None => (),
                            };

                            (role.name, container)
                        }
                        Err(e) => {
                            warn!("Failed to get metadata for role {}: {:?}", role.name, e);
                            continue
                        }
                    }
                }
            };

            self.delegations.insert(result.0, result.1.clone());
        }
        
        Ok(())
    }

    fn get_metadata<R: RoleType, M: Metadata<R>, W: Write>(fetch_type: &FetchType,
                                                           http_client: &Client,
                                                           role: &Role,
                                                           metadata_version: Option<i32>,
                                                           allow_expired: bool,
                                                           threshold: i32,
                                                           trusted_ids: &[KeyId],
                                                           available_keys: &HashMap<KeyId, Key>,
                                                           size: Option<i64>,
                                                           hash_data: Option<(&HashType,
                                                                              &[u8])>,
                                                           mut out: &mut Option<W>)
                                                           -> Result<M, Error> {

        debug!("Loading metadata from {:?}", fetch_type);
        let metadata_version_str = metadata_version.map(|x| format!("{}.", x))
            .unwrap_or_else(|| "".to_string());

        let buf: Vec<u8> = match fetch_type {
            &FetchType::Cache(ref local_path) => {
                let path = local_path.join("metadata")
                    .join(format!("{}{}.json", metadata_version_str, role));
                info!("Reading metadata from local path: {:?}", path);

                let mut file = File::open(&path).map_err(|e| Error::from_io(e, &path))?;
                let mut buf = Vec::new();

                match (size, hash_data) {
                    (None, None) => file.read_to_end(&mut buf).map(|_| ())?,
                    _ => match Self::read_and_verify(&mut file, &mut Some(&mut buf), size, hash_data) {
                        Ok(()) => (),
                        Err(e) => {
                            debug!("Removing file because it failed to validate: {:?}", path);
                            match fs::remove_file(&path) {
                                Ok(()) => (),
                                Err(e) => warn!("Failed to remove file {:?} after failed validation: {:?}",
                                                path, e),
                            }
                            return Err(e)
                        }
                    },
                };

                buf
            }
            &FetchType::File(ref path) => {
                let path = path.join(format!("{}{}.json", metadata_version_str, role));
                info!("Reading metadata from path: {:?}", path);

                let mut file = File::open(path.clone()).map_err(|e| Error::from_io(e, &path))?;
                let mut buf = Vec::new();

                match (size, hash_data) {
                    (None, None) => file.read_to_end(&mut buf).map(|_| ())?,
                    _ => Self::read_and_verify(&mut file, &mut Some(&mut buf), size, hash_data)?,
                };

                buf
            }
            &FetchType::Http(ref url) => {
                let mut url = url.clone();
                {
                    url.path_segments_mut()
                        .map_err(|_| Error::Generic("URL path could not be mutated".to_string()))?
                        .push(&format!("{}{}.json", metadata_version_str, role));
                }
                let mut resp = http::get(http_client, &url)?;
                let mut buf = Vec::new();

                match (size, hash_data) {
                    (None, None) => resp.read_to_end(&mut buf).map(|_| ())?,
                    _ => Self::read_and_verify(&mut resp, &mut Some(&mut buf), size, hash_data)?,
                };

                buf
            }
        };

        let signed: SignedMetadata<R> = json::from_slice(&buf)?;
        // TODO clone
        Self::verify_meta::<R>(signed.clone(), role, threshold, trusted_ids, available_keys)?;
        let meta: M = json::from_value(signed.signed)?;

        if !allow_expired && meta.expires() <= &UTC::now() {
            return Err(Error::ExpiredMetadata(role.clone()));
        }

        match out {
            &mut Some(ref mut out) => out.write_all(&buf)?,
            &mut None => (),
        };

        Ok(meta)
    }

    fn unverified_read_root(fetch_type: &FetchType,
                            http_client: &Client,
                            local_path: Option<&Path>)
                            -> Result<(Option<TempFile>, RootMetadata), Error> {
        let (temp_file, buf): (Option<TempFile>, Vec<u8>) = match fetch_type {
            &FetchType::Cache(ref local_path) => {
                let path = local_path.join("metadata")
                    .join("root.json");
                let mut file = File::open(path.clone()).map_err(|e| Error::from_io(e, &path))?;
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).map(|_| ())?;
                (None, buf)
            }
            &FetchType::File(ref path) => {
                let local_path = local_path.ok_or_else(|| {
                    let msg = "Programming error. No local path supplied for remote file read";
                    error!("{}", msg);
                    Error::Generic(msg.to_string())
                })?;
                let dest_path = local_path.join("temp")
                    .join(Uuid::new_v4().hyphenated().to_string());

                let src_path = path.join("root.json");
                fs::copy(src_path, dest_path.clone())?;

                let mut temp_file = TempFile::from_existing(dest_path)
                    .map_err(|e| Error::from_io(e, &path))?;
                let mut buf = Vec::new();
                temp_file.read_to_end(&mut buf).map(|_| ())?;
                temp_file.seek(SeekFrom::Start(0))
                    .map_err(|e| Error::from_io(e, &path))?;

                (Some(temp_file), buf)
            }
            &FetchType::Http(ref url) => {
                let local_path = local_path.ok_or_else(|| {
                    let msg = "Programming error. No local path supplied for remote HTTP read";
                    error!("{}", msg);
                    Error::Generic(msg.to_string())
                })?;

                let mut temp_file = TempFile::new(local_path.to_path_buf())?;

                let mut url = url.clone();
                {
                    url.path_segments_mut()
                        .map_err(|_| Error::Generic("URL path could not be mutated".to_string()))?
                        .push("root.json");
                }
                let mut resp = http::get(http_client, &url)?;
                let mut buf = Vec::new();
                resp.read_to_end(&mut buf).map(|_| ())?;

                temp_file.write_all(&buf).map(|_| ())?;
                temp_file.seek(SeekFrom::Start(0))?;

                (Some(temp_file), buf)
            }
        };

        let signed: SignedMetadata<Root> = json::from_slice(&buf)?;
        let root_str = signed.signed.to_string();
        Ok((temp_file, json::from_str(&root_str)?))
    }

    /// Read the root.json metadata and replace keys for the root role with the keys that are given
    /// as arguments to this function. This initial read is unverified in any way.
    fn read_root_with_keys(fetch_type: &FetchType,
                           http_client: &Client,
                           root_keys: &[Key])
                           -> Result<RootMetadata, Error> {
        let buf: Vec<u8> = match fetch_type {
            &FetchType::Cache(ref local_path) => {
                let path = local_path.join("metadata")
                    .join("1.root.json");

                debug!("Reading root.json from path: {:?}", path);

                let mut file = File::open(path.clone()).map_err(|e| Error::from_io(e, &path))?;
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).map(|_| ())?;
                buf
            }
            &FetchType::File(ref path) => {
                let path = path.join("1.root.json");
                let mut file = File::open(path.clone()).map_err(|e| Error::from_io(e, &path))?;
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).map(|_| ())?;
                buf
            }
            &FetchType::Http(ref url) => {
                let mut url = url.clone();
                {
                    url.path_segments_mut()
                        .map_err(|_| Error::Generic("URL path could not be mutated".to_string()))?
                        .push("1.root.json");
                }
                let mut resp = http::get(http_client, &url)?;
                let mut buf = Vec::new();
                resp.read_to_end(&mut buf).map(|_| ())?;
                buf
            }
        };

        // TODO once serialize is implemented for all the types, don't use this
        // json manipulation mess here
        let mut signed = json::from_slice::<SignedMetadata<Root>>(&buf)?;
        if let json::Value::Object(ref mut object) = signed.signed {
            if let Some(&mut json::Value::Object(ref mut roles)) = object.get_mut("roles") {
                if let Some(&mut json::Value::Object(ref mut root)) = roles.get_mut("root") {
                    if let Some(&mut json::Value::Array(ref mut key_ids)) = root.get_mut("keyids") {
                        key_ids.clear();
                        key_ids.extend(root_keys.iter()
                            .map(|k| json::Value::String(k.value.key_id().0)));
                    }
                }
            }
        }

        Ok(json::from_value(signed.signed)?)
    }

    fn verify_meta<R: RoleType>(signed: SignedMetadata<R>,
                                role: &Role,
                                threshold: i32,
                                trusted_ids: &[KeyId],
                                available_keys: &HashMap<KeyId, Key>)
                                -> Result<(), Error> {
        let bytes =
            cjson::canonicalize(&signed.signed).map_err(|err| Error::CanonicalJsonError(err))?;

        let unique_count = signed.signatures
            .iter()
            .map(|s| &s.key_id)
            .collect::<HashSet<&KeyId>>()
            .len();

        if signed.signatures.len() != unique_count {
            return Err(Error::NonUniqueSignatures(role.clone()));
        }

        let keys = trusted_ids.iter()
            .map(|id| (id, available_keys.get(id)))
            .fold(HashMap::new(), |mut m, (id, k)| {
                if let Some(key) = k {
                    m.insert(id, key);
                } else {
                    debug!("unknown key id: {:?}", id);
                }
                m
            });

        if threshold <= 0 {
            return Err(Error::VerificationFailure("Threshold not >= 1".into()));
        }

        let mut valid_sigs = 0;
        for sig in signed.signatures.iter() {
            if let Some(key) = keys.get(&sig.key_id) {
                debug!("Verifying role {:?} with key ID {:?}",
                       role,
                       sig.key_id);

                match key.verify(&sig.method, &bytes, &sig.sig) {
                    Ok(()) => {
                        debug!("Good signature from key ID {:?}", sig.key_id);
                        valid_sigs += 1;
                    }
                    Err(e) => warn!("Failed to verify with key ID {:?}: {:?}", &sig.key_id, e),
                }
                if valid_sigs == threshold {
                    return Ok(());
                }
            }
        }

        info!("Threshold not met: {}/{}", valid_sigs, threshold);
        return Err(Error::UnmetThreshold(role.clone()));
    }

    /// Reads a target from local storage or fetches it from a remote repository. Verifies the
    /// target. Fails if the target is missing, or if the metadata chain that leads to it cannot
    /// be verified.
    // TODO ? stronger input type
    pub fn fetch_target(&self, target: &str) -> Result<PathBuf, Error> {
        let metadata_chain = match self.targets {
            Some(ref targets) => TargetPathIterator::new(&self, targets.clone(), target),
            None => return Err(Error::MissingMetadata(Role::Targets)),
        };
        for ref targets_meta in metadata_chain {
            let target_meta = match targets_meta.targets.get(target) {
                Some(meta) => meta,
                None => continue,
            };

            let (hash_alg, expected_hash): (&HashType, HashValue) = HashType::preferences().iter()
                .fold(None, |res, pref| {
                    res.or_else(|| if let Some(hash) = target_meta.hashes.get(&pref) {
                        Some((pref, hash.clone()))
                    } else {
                        None
                    })
                })
                .ok_or_else(|| Error::NoSupportedHashAlgorithms)?;

            // TODO correctly split path
            let path = self.local_path.join("targets").join(util::url_path_to_os_path(target)?);
            info!("reading target from local path: {:?}", path);

            if path.exists() {
                let mut file = File::open(path.clone()).map_err(|e| Error::from_io(e, &path))?;
                Self::read_and_verify(&mut file,
                                      &mut None::<&mut File>,
                                      Some(target_meta.length),
                                      Some((&hash_alg, &expected_hash.0)))?;
                let _ = file.seek(SeekFrom::Start(0))?;
                return Ok(path);
            } else {
                let mut temp_file = self.temp_file()?;

                match self.remote {
                    RemoteRepo::File(ref path) => {
                        let mut path = path.clone();
                        path.extend(util::url_path_to_path_components(target)?);
                        let mut file = File::open(path.clone()).map_err(|e| Error::from_io(e, &path))?;

                        match Self::read_and_verify(&mut file,
                                                    &mut Some(temp_file.file_mut()?),
                                                    Some(target_meta.length),
                                                    Some((&hash_alg, &expected_hash.0))) {
                            Ok(()) => {
                                let mut storage_path = self.local_path.join("targets");
                                storage_path.extend(util::url_path_to_path_components(target)?);

                                {
                                    let parent = storage_path.parent()
                                        .ok_or_else(|| Error::Generic("Path had no parent".to_string()))?;

                                    DirBuilder::new()
                                        .recursive(true)
                                        .create(parent)?;
                                }

                                temp_file.persist(&storage_path)?;
                                return Ok(storage_path)
                            }
                            Err(e) => warn!("Error verifying target: {:?}", e),
                        }
                    }
                    RemoteRepo::Http(ref url) => {
                        let mut url = url.clone();
                        {
                            url.path_segments_mut()
                                .map_err(|_| Error::Generic("URL path could not be mutated".to_string()))?
                                .extend(util::url_path_to_path_components(&target)?);
                        }
                        let url = util::url_to_hyper_url(&url)?;
                        let mut resp = http::get(&self.http_client, &url)?;

                        match Self::read_and_verify(&mut resp,
                                                    &mut Some(temp_file.file_mut()?),
                                                    Some(target_meta.length),
                                                    Some((&hash_alg, &expected_hash.0))) {
                            Ok(()) => {
                                // TODO this isn't windows friendly
                                let mut storage_path = self.local_path.join("targets");
                                storage_path.extend(util::url_path_to_path_components(target)?);

                                {
                                    let parent = storage_path.parent()
                                        .ok_or_else(|| Error::Generic("Path had no parent".to_string()))?;

                                    DirBuilder::new()
                                        .recursive(true)
                                        .create(parent)?;
                                }

                                temp_file.persist(&storage_path)?;

                                return Ok(storage_path)
                            }
                            Err(e) => warn!("Error verifying target: {:?}", e),
                        }
                    }
                }
            }
        };

        Err(Error::UnavailableTarget)
    }

    fn read_and_verify<R: Read, W: Write>(input: &mut R,
                                          output: &mut Option<W>,
                                          size: Option<i64>,
                                          hash_data: Option<(&HashType, &[u8])>)
                                          -> Result<(), Error> {
        let mut context = match hash_data {
            Some((&HashType::Sha512, _)) => Some(digest::Context::new(&SHA512)),
            Some((&HashType::Sha256, _)) => Some(digest::Context::new(&SHA256)),
            Some((&HashType::Unsupported(_), _)) => return Err(Error::NoSupportedHashAlgorithms),
            _ => None,
        };

        let mut buf = [0; 1024];
        let mut bytes_left = size;

        loop {
            match input.read(&mut buf) {
                Ok(read_bytes) => {
                    if read_bytes == 0 {
                        break;
                    }

                    match output {
                        &mut Some(ref mut output) => output.write_all(&buf[0..read_bytes])?,
                        &mut None => (),
                    };

                    match context {
                        Some(ref mut c) => c.update(&buf[0..read_bytes]),
                        None => (),
                    };

                    match bytes_left {
                        Some(ref mut bytes_left) => {
                            *bytes_left -= read_bytes as i64;
                            if *bytes_left == 0 {
                                break;
                            } else if *bytes_left < 0 {
                                return Err(Error::UnavailableTarget);
                            }
                        }
                        None => (),
                    };
                }
                e @ Err(_) => e.map(|_| ())?,
            }
        }

        let generated_hash = context.map(|c| c.finish());

        match (generated_hash, hash_data) {
            (Some(generated_hash), Some((_, expected_hash))) if generated_hash.as_ref() !=
                                                                expected_hash => {
                Err(Error::UnavailableTarget)
            }
            // this should never happen, so err if it does for safety
            (Some(_), None) => {
                let msg = "Hash calculated when no expected hash supplied";
                error!("Programming error. Please report this as a bug: {}", msg);
                Err(Error::VerificationFailure(msg.to_string()))
            }
            // this should never happen, so err if it does for safety
            (None, Some(_)) => {
                let msg = "No hash calculated when expected hash supplied";
                error!("Programming error. Please report this as a bug: {}", msg);
                Err(Error::VerificationFailure(msg.to_string()))
            }
            (Some(_), Some(_)) |
            (None, None) => Ok(()),
        }
    }

    // TODO write integration tests for this
    fn purge_metadata(&mut self) -> Result<(), Error> {
        info!("Purging old metadata");

        self.snapshot = None;
        self.targets = None;
        self.timestamp = None;
        self.delegations.clear();

        let current_path = self.local_path.join("metadata");
    
        for entry in WalkDir::new(&current_path).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue
            }

            if !entry.path().to_string_lossy().ends_with("root.json") {
                debug!("Removing file {:?}", entry.path());
                fs::remove_file(entry.path())?;
            }
        }

        for entry in WalkDir::new(&current_path).min_depth(1).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_dir() {
                match fs::remove_dir(entry.path()) {
                    Ok(()) => (),
                    Err(e) => info!("Failed to remove dir {:?}: {:?}", entry.path(), e),
                };
            }
        }

        Ok(())
    }

    fn try_remove_meta(&self, meta_url_path: &str) {
        match util::url_path_to_path_components(meta_url_path) {
            Ok(path) => {
                let mut full_path = self.local_path.join("metadata");
                full_path.extend(path);

                if !full_path.exists() {
                    debug!("Path {:?} does not exist, so not removing", full_path);
                }

                match fs::remove_file(full_path.clone()) {
                    Ok(()) => (),
                    Err(e) => warn!("Failed to remove meta path {:?}: {:?}",
                                    full_path, e),
                }
            }
            Err(e) => warn!("Could not turn URL path {:?} into an FS path: {:?}",
                            meta_url_path, e),
        }
    }
}


/// The configuration used to initialize a `Tuf` struct.
pub struct Config {
    remote: RemoteRepo,
    local_path: PathBuf,
    http_client: Client,
    init: bool,
}

impl Config {
    /// Create a new builder with the default configurations where applicable.
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}


/// Helper that constructs `Config`s and verifies the options.
pub struct ConfigBuilder {
    remote: Option<RemoteRepo>,
    local_path: Option<PathBuf>,
    http_client: Option<Client>,
    init: bool,
}

impl ConfigBuilder {
    /// Create a new builder with the default configurations where applicable.
    pub fn new() -> Self {
        ConfigBuilder {
            remote: None,
            local_path: None,
            http_client: None,
            init: true,
        }
    }

    /// The remote TUF repo.
    pub fn remote(mut self, remote: RemoteRepo) -> Self {
        self.remote = Some(remote);
        self
    }

    /// The local path for metadata and target storage.
    pub fn local_path(mut self, local_path: PathBuf) -> Self {
        self.local_path = Some(local_path);
        self
    }

    /// The `hyper::client::Client` to use. Default: `Client::new()`.
    pub fn http_client(mut self, client: Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Where or not to initialize the local directory structures.
    pub fn init(mut self, init: bool) -> Self {
        self.init = init;
        self
    }

    /// Verify the configuration.
    pub fn finish(self) -> Result<Config, Error> {
        let remote = self.remote
            .ok_or_else(|| Error::InvalidConfig("Remote repository was not set".to_string()))?;

        let local_path = self.local_path
            .ok_or_else(|| Error::InvalidConfig("Local path was not set".to_string()))?;

        Ok(Config {
            remote: remote,
            local_path: local_path,
            http_client: self.http_client.unwrap_or_else(|| Client::new()),
            init: self.init,
        })
    }
}


#[derive(Debug)]
enum FetchType {
    Cache(PathBuf),
    File(PathBuf),
    Http(HyperUrl),
}

impl FetchType {
    fn is_cache(&self) -> bool {
        match self {
            &FetchType::Cache(_) => true,
            _ => false,
        }
    }
}


struct TargetPathIterator<'a> {
    tuf: &'a Tuf,
    targets: TargetsMetadata,
    target: &'a str,
    terminate: bool,
    targets_checked: bool,
    roles_index: usize,
    sub_iter: Option<Box<TargetPathIterator<'a>>>,
}

impl<'a> TargetPathIterator<'a> {
    fn new(tuf: &'a Tuf, targets: TargetsMetadata, target: &'a str) -> Self {
        TargetPathIterator {
            tuf: tuf,
            targets: targets,
            target: target,
            terminate: false,
            targets_checked: false,
            roles_index: 0,
            sub_iter: None,
        }
    }
}

impl<'a> Iterator for TargetPathIterator<'a> {
    type Item = TargetsMetadata;

    fn next(&mut self) -> Option<Self::Item> {
        if self.terminate {
            return None
        }

        match self.targets.targets.get(self.target) {
            Some(_) if !self.targets_checked => {
                self.targets_checked = true;
                Some(self.targets.clone())
            },
            _ => {
                match self.targets.delegations {
                    Some(ref delegations) => {
                        for delegation in delegations.roles.iter().skip(self.roles_index) {
                            if delegation.terminating {
                                self.terminate = true;
                            }

                            self.roles_index += 1;

                            let meta = match self.tuf.delegations.get(&delegation.name) {
                                Some(container) => container.targets.clone(),
                                None => continue,
                            };

                            if delegation.could_have_target(&self.target) {
                                let mut iter = TargetPathIterator::new(&self.tuf,
                                                                       meta,
                                                                       self.target);
                                let res = iter.next();
                                if delegation.terminating && res.is_none() {
                                    return None
                                } else if res.is_some() {
                                    self.sub_iter = Some(Box::new(iter));
                                    return res
                                } else {
                                    continue
                                }
                            } else {
                                continue
                            }
                        }
                        return None
                    },
                    None => return None,
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct DelegatedRoleContainer {
    role_definition: DelegatedRole,
    targets: TargetsMetadata,
    parent: Option<String>,
}
