use chrono::UTC;
use json;
use hyper::client::Client;
use ring::digest;
use ring::digest::{SHA256, SHA512};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, DirBuilder};
use std::io::{Read, Write};
use std::path::PathBuf;
use url::Url;
use uuid::Uuid;

use cjson;
use error::Error;
use metadata::{Role, RoleType, Root, Targets, Timestamp, Snapshot, Metadata, SignedMetadata,
               RootMetadata, TargetsMetadata, TimestampMetadata, SnapshotMetadata, HashType,
               HashValue, KeyId, Key};
use util;


/// Interface for interacting with TUF repositories.
#[derive(Debug)]
pub struct Tuf {
    url: Url,
    local_path: PathBuf,
    http_client: Client,
    root: RootMetadata,
    targets: Option<TargetsMetadata>,
    timestamp: Option<TimestampMetadata>,
    snapshot: Option<SnapshotMetadata>,
}

impl Tuf {
    /// Create a `Tuf` struct from an existing repo with the initial root keys pinned. This also
    /// calls `initialize` to ensure the needed paths exist.
    pub fn from_root_keys(root_keys: Vec<Key>, config: Config) -> Result<Self, Error> {
        Self::initialize(&config.local_path)?;

        let url = util::path_to_url(config.local_path.as_path())
            .map_err(|e| Error::Generic(format!("{:?}", e)))?;

        // TODO have this try local then try from the URL since things might not be initialized
        let root = {
            let modified_root = Self::read_root_with_keys(&config.http_client, &url, &root_keys)?;
            // pass it back through the main path to ensure consistency
            Self::get_meta_num::<Root, RootMetadata, File>(&config.http_client,
                                                           &url,
                                                           1,
                                                           &modified_root,
                                                           &mut None)?
        };

        let mut tuf = Tuf {
            url: config.url,
            local_path: config.local_path,
            http_client: config.http_client,
            root: root,
            targets: None,
            timestamp: None,
            snapshot: None,
        };

        tuf.update()?;
        Ok(tuf)
    }

    /// Create a `Tuf` struct from a new repo. Must contain the `root.json`. The root is trusted
    /// with only verification on consistency, not authenticity. This call also calls `initialize`
    /// to ensure the needed paths exist.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::initialize(&config.local_path)?;
        let url = util::path_to_url(config.local_path.as_path())
            .map_err(|e| Error::Generic(format!("{:?}", e)))?;

        let root = {
            let root = Self::unverified_read_root(&config.http_client, &url)?;
            Self::get_metadata::<Root, RootMetadata, File>(&config.http_client,
                                                           &url,
                                                           &root,
                                                           &mut None)?
        };

        let mut tuf = Tuf {
            url: config.url,
            local_path: config.local_path,
            http_client: config.http_client,
            root: root,
            targets: None,
            timestamp: None,
            snapshot: None,
        };
        tuf.update()?;

        Ok(tuf)
    }

    /// Create and verify the necessary directory structure for a TUF repo.
    pub fn initialize(local_path: &PathBuf) -> Result<(), Error> {
        info!("Initializing local storage: {}", local_path.to_string_lossy());

        for dir in vec![PathBuf::from("metadata").join("current"),
                        PathBuf::from("metadata").join("archive"),
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

    fn temp_file(&self) -> Result<(File, PathBuf), Error> {
        let uuid = Uuid::new_v4();
        let path = self.local_path.as_path().join("temp").join(uuid.hyphenated().to_string());
        Ok((File::create(path.clone())?, path.to_path_buf()))
    }

    /// Update the metadata from local and remote sources.
    pub fn update(&mut self) -> Result<(), Error> {
        info!("Updating metdata");
        self.update_local()?;
        self.update_remote()?;
        info!("Successfully updated metadata");
        Ok(())
    }

    fn update_remote(&mut self) -> Result<(), Error> {
        debug!("Updating metadata from remote sources");

        self.update_root(true)?;

        if self.update_timestamp(true)? && self.update_snapshot(true)? {
            self.update_targets(true)
        } else {
            Ok(())
        }
    }

    fn update_local(&mut self) -> Result<(), Error> {
        debug!("Updating metadata from local sources");

        self.update_root(false)?;

        if self.update_timestamp(false)? && self.update_snapshot(false)? {
            self.update_targets(false)
        } else {
            Ok(())
        }
    }

    fn update_root(&mut self, remote: bool) -> Result<(), Error> {
        let url = if remote {
            // TODO remove this clone
            self.url.clone()
        } else {
            util::path_to_url(self.local_path.as_path())
                .map_err(|e| Error::Generic(format!("{:?}", e)))?
        };

        let temp_root = Self::unverified_read_root(&self.http_client, &url)?;

        // TODO reuse temp root as last one
        for i in (self.root.version + 1)..(temp_root.version + 1) {
            let (mut out, out_path) = if remote {
                let (file, path) = self.temp_file()?;
                (Some(file), Some(path))
            } else {
                (None, None)
            };

            let root = match Self::get_meta_num::<Root, RootMetadata, File>(&self.http_client,
                                                                      &url,
                                                                      i,
                                                                      &self.root,
                                                                     &mut out) {
                Ok(root) => {
                    root
                }
                Err(e) => {
                    match out_path {
                        Some(out_path) => match fs::remove_file(out_path.clone()) {
                            Ok(_) => (),
                            Err(e) => error!("Error removing temp file {:?}: {}", out_path, e),
                        },
                        None => (),
                    }
                    return Err(e)
                }
            };

            info!("Rotated to root metadata version {}", i);
            self.root = root;

            match out_path {
                Some(out_path) => {
                    fs::rename(out_path,
                               self.local_path.join("metadata").join("archive").join(format!("{}.root.json", i)))?
                }
                None => (),
            };

            // set to None to untrust old metadata
            // TODO check that these resets are in line with the Mercury paper
            self.targets = None;
            self.timestamp = None;
            self.snapshot = None;
        }

        Ok(())
    }

    fn update_timestamp(&mut self, remote: bool) -> Result<bool, Error> {
        let (url, mut out, out_path) = if remote {
            // TODO remove this clone
            let (file, path) = self.temp_file()?;
            (self.url.clone(), Some(file), Some(path))
        } else {
            let url = util::path_to_url(self.local_path.as_path())
                .map_err(|e| Error::Generic(format!("{:?}", e)))?;
            (url, None, None)
        };

        let timestamp = Self::get_metadata::<Timestamp,
                                             TimestampMetadata,
                                             File>(&self.http_client, &url, &self.root, &mut out)?;
        match self.timestamp {
            Some(ref t) if t.version > timestamp.version => {
                match out_path {
                    Some(out_path) => fs::remove_file(out_path)?,
                    None => (),
                };

                return Err(Error::VersionDecrease(Role::Timestamp));
            }
            Some(ref t) if t.version == timestamp.version => return Ok(false),
            _ => self.timestamp = Some(timestamp),
        }

        if let Some(ref timestamp) = self.timestamp {
            if let Some(ref timestamp_meta) = timestamp.meta.get("snapshot.json") {
                if timestamp_meta.version > timestamp.version {
                    info!("Timestamp metadata is up to date");

                    match out_path {
                        Some(out_path) => {
                            match fs::remove_file(out_path.clone()) {
                                Ok(_) => (),
                                Err(e) => error!("Error removing temp file {:?}: {}", out_path, e),
                            }
                        },
                        None => (),
                    };

                    return Ok(false);
                }
            }
        }


        match out_path {
            Some(out_path) => {
                fs::rename(self.local_path.join("metadata").join("current").join("timestamp.json"),
                           self.local_path.join("metadata").join("archive").join("timestamp.json"))?;
                fs::rename(out_path,
                           self.local_path.join("metadata").join("current").join("timestamp.json"))?
            }
            None => (),
        };

        Ok(true)
    }

    fn update_snapshot(&mut self, remote: bool) -> Result<bool, Error> {
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

        let (url, mut out, out_path) = if remote {
            let (file, path) = self.temp_file()?;
            // TODO remove this clone
            (self.url.clone(), Some(file), Some(path))
        } else {
            let url = util::path_to_url(self.local_path.as_path())
                .map_err(|e| Error::Generic(format!("{:?}", e)))?;
            (url, None, None)
        };

        let snapshot = Self::get_meta_prefix::<Snapshot,
                                               SnapshotMetadata,
                                               File>(&self.http_client,
                                                     &url,
                                                     "",
                                                     &self.root,
                                                     Some(meta.length),
                                                     Some((&hash_alg, &expected_hash.0)),
                                                     &mut out)?;

        // TODO ? check downloaded version matches what was in the timestamp.json

        match self.snapshot {
            Some(ref s) if s.version > snapshot.version => {
                match out_path {
                    Some(out_path) => fs::remove_file(out_path)?,
                    None => (),
                };
                return Err(Error::VersionDecrease(Role::Snapshot));
            }
            Some(ref s) if s.version == snapshot.version => return Ok(false),
            _ => self.snapshot = Some(snapshot),
        }

        // TODO this needs to be extended once we do delegations
        if let Some(ref snapshot) = self.snapshot {
            if let Some(ref snapshot_meta) = snapshot.meta.get("targets.json") {
                if let Some(ref targets) = self.targets {
                    if snapshot_meta.version > targets.version {
                        info!("Snapshot metadata is up to date");

                        match out_path {
                            Some(out_path) => fs::remove_file(out_path)?,
                            None => (),
                        };
                        return Ok(false);
                    }
                }
            }
        }

        match out_path {
            Some(out_path) => {
                fs::rename(self.local_path.join("metadata").join("current").join("snapshot.json"),
                           self.local_path.join("metadata").join("archive").join("snapshot.json"))?;
                fs::rename(out_path,
                           self.local_path.join("metadata").join("current").join("snapshot.json"))?
            }
            None => (),
        };

        Ok(true)
    }

    fn update_targets(&mut self, remote: bool) -> Result<(), Error> {
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

        let (url, mut out, out_path) = if remote {
            let (file, path) = self.temp_file()?;
            (self.url.clone(), Some(file), Some(path))
        } else {
            let url = util::path_to_url(self.local_path.as_path())
                .map_err(|e| Error::Generic(format!("{:?}", e)))?;
            (url, None, None)
        };

        let targets = Self::get_meta_prefix::<Targets, TargetsMetadata, File>(&self.http_client,
                                                                              &url,
                                                                              "",
                                                                              &self.root,
                                                                              meta.length,
                                                                              hash_data,
                                                                              &mut out)?;

        // TODO ? check downloaded version matches what was in the snapshot.json

        match self.targets {
            Some(ref t) if t.version > targets.version => {
                match out_path {
                    Some(out_path) => fs::remove_file(out_path)?,
                    None => (),
                };

                return Err(Error::VersionDecrease(Role::Targets));
            }
            Some(ref t) if t.version == targets.version => return Ok(()),
            _ => self.targets = Some(targets),
        }

        match out_path {
            Some(out_path) => {
                fs::rename(self.local_path.join("metadata").join("current").join("targets.json"),
                           self.local_path.join("metadata").join("archive").join("targets.json"))?;
                fs::rename(out_path,
                           self.local_path.join("metadata").join("current").join("targets.json"))?
            }
            None => (),
        };

        Ok(())
    }

    fn get_metadata<R: RoleType, M: Metadata<R>, W: Write>(http_client: &Client,
                                                           url: &Url,
                                                           root: &RootMetadata,
                                                           mut out: &mut Option<W>)
                                                           -> Result<M, Error> {
        Self::get_meta_prefix(http_client, url, "", root, None, None, &mut out)
    }

    fn get_meta_num<R: RoleType, M: Metadata<R>, W: Write>(http_client: &Client,
                                                           url: &Url,
                                                           num: i32,
                                                           root: &RootMetadata,
                                                           mut out: &mut Option<W>)
                                                           -> Result<M, Error> {
        // TODO this should check that the metadata version == num
        Self::get_meta_prefix(http_client,
                              url,
                              &format!("{}.", num),
                              root,
                              None,
                              None,
                              &mut out)
    }

    fn get_meta_prefix<R: RoleType, M: Metadata<R>, W: Write>(http_client: &Client,
                                                              url: &Url,
                                                              prefix: &str,
                                                              root: &RootMetadata,
                                                              size: Option<i64>,
                                                              hash_data: Option<(&HashType,
                                                                                 &[u8])>,
                                                              mut out: &mut Option<W>)
                                                              -> Result<M, Error> {
        let buf: Vec<u8> = match url.scheme() {
            "file" => {
                let path = util::url_path_to_os_path(url.path())
                    ?
                    .join("metadata")
                    .join("current")
                    .join(format!("{}{}.json", prefix, R::role()));
                info!("Reading metadata from local path: {:?}", path);

                let mut file = File::open(path)?;
                let mut buf = Vec::new();

                match (size, hash_data) {
                    (None, None) => file.read_to_end(&mut buf).map(|_| ())?,
                    _ => Self::read_and_verify(&mut file, &mut Some(&mut buf), size, hash_data)?,
                };

                buf
            }
            "http" | "https" => {
                let url = util::url_to_hyper_url(url)?
                    .join(&format!("{}{}.json", prefix, R::role()))?;
                let mut resp = http_client.get(url).send()?;
                let mut buf = Vec::new();

                match (size, hash_data) {
                    (None, None) => resp.read_to_end(&mut buf).map(|_| ())?,
                    _ => Self::read_and_verify(&mut resp, &mut Some(&mut buf), size, hash_data)?,
                };

                buf
            }
            x => return Err(Error::Generic(format!("Unsupported URL scheme: {}", x))),
        };

        let signed = json::from_slice(&buf)?;
        let safe_bytes = Self::verify_meta::<R>(signed, root)?;
        let meta: M = json::from_slice(&safe_bytes)?;

        // TODO this will be a problem with updating root metadata and this function probably
        // needs an arg like `allow_expired`.
        if meta.expires() <= &UTC::now() {
            return Err(Error::ExpiredMetadata(R::role()));
        }

        match out {
            &mut Some(ref mut out) => out.write_all(&buf)?,
            &mut None => (),
        };

        Ok(meta)
    }

    fn unverified_read_root(http_client: &Client, url: &Url) -> Result<RootMetadata, Error> {
        let buf: Vec<u8> = match url.scheme() {
            "file" => {
                let path = util::url_path_to_os_path(url.path())
                    ?
                    .join("metadata")
                    .join("current")
                    .join("root.json");

                let mut file = File::open(path)?;
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).map(|_| ())?;
                buf
            }
            "http" | "https" => {
                let url = util::url_to_hyper_url(url)?.join("root.json")?;
                let mut resp = http_client.get(url).send()?;
                let mut buf = Vec::new();
                resp.read_to_end(&mut buf).map(|_| ())?;
                buf
            }
            x => return Err(Error::Generic(format!("Unsupported URL scheme: {}", x))),
        };

        let signed: SignedMetadata<Root> = json::from_slice(&buf)?;
        let root_str = signed.signed.to_string();
        Ok(json::from_str(&root_str)?)
    }

    /// Read the root.json metadata and replace keys for the root role with the keys that are given
    /// as arguments to this function. This initial read is unverified in any way.
    fn read_root_with_keys(http_client: &Client,
                           url: &Url,
                           root_keys: &[Key])
                           -> Result<RootMetadata, Error> {
        let buf: Vec<u8> = match url.scheme() {
            "file" => {
                let path = util::url_path_to_os_path(url.path())
                    ?
                    .join("metadata")
                    .join("current")
                    .join("1.root.json");

                let mut file = File::open(path)?;
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).map(|_| ())?;
                buf
            }
            "http" | "https" => {
                let url = util::url_to_hyper_url(url)?;
                let mut resp = http_client.get(url).send()?;
                let mut buf = Vec::new();
                resp.read_to_end(&mut buf).map(|_| ())?;
                buf
            }
            x => return Err(Error::Generic(format!("Unsupported URL scheme: {}", x))),
        };

        // TODO once serialize is implemented for all the types, don't use this
        // json manipulation mess here
        let mut signed = json::from_slice::<SignedMetadata<Root>>(&buf)?;
        if let json::Value::Object(ref mut object) = signed.signed {
            if let Some(&mut json::Value::Object(ref mut roles)) = object.get_mut("roles") {
                if let Some(&mut json::Value::Object(ref mut root)) = roles.get_mut("root") {
                    if let Some(&mut json::Value::Array(ref mut key_ids)) = root.get_mut("keyids") {
                        key_ids.clear();
                        key_ids.extend(root_keys.iter().map(|k| json!(k.value.key_id().0)));
                    }
                }
            }
        }

        Ok(json::from_value(signed.signed)?)
    }

    fn verify_meta<R: RoleType>(signed: SignedMetadata<R>,
                                root: &RootMetadata)
                                -> Result<Vec<u8>, Error> {
        let bytes =
            cjson::canonicalize(signed.signed).map_err(|err| Error::CanonicalJsonError(err))?;

        let role = root.role_definition::<R>();

        let unique_count = signed.signatures
            .iter()
            .map(|s| &s.key_id)
            .collect::<HashSet<&KeyId>>()
            .len();

        if signed.signatures.len() != unique_count {
            return Err(Error::NonUniqueSignatures);
        }

        let keys = role.key_ids
            .iter()
            .map(|id| (id, root.keys.get(id)))
            .fold(HashMap::new(), |mut m, (id, k)| {
                if let Some(key) = k {
                    m.insert(id, key);
                } else {
                    debug!("Unknown key ID: {:?}", id);
                }
                m
            });

        if role.threshold <= 0 {
            return Err(Error::VerificationFailure("Threshold not >= 1".into()));
        }

        let mut valid_sigs = 0;
        for sig in signed.signatures.iter() {
            if let Some(key) = keys.get(&sig.key_id) {
                debug!("Verifying role {:?} with key ID {:?}",
                       R::role(),
                       sig.key_id);

                match key.verify(&sig.method, &bytes, &sig.sig) {
                    Ok(()) => {
                        debug!("Good signature from key ID {:?}", sig.key_id);
                        valid_sigs += 1;
                    }
                    Err(e) => warn!("Failed to verify with key ID {:?}: {:?}", &sig.key_id, e),
                }
                if valid_sigs == role.threshold {
                    return Ok(bytes);
                }
            }
        }

        info!("Threshold not met: {}/{}", valid_sigs, role.threshold);
        return Err(Error::UnmetThreshold(R::role()));
    }

    /// Lists all targets that are currently available. If a target is missing, it means the
    /// metadata chain that leads to it cannot be verified, and the target is therefore untrusted.
    // TODO stronger return type
    pub fn list_targets(&self) -> Vec<String> {
        match self.targets {
            Some(ref targets) => {
                let mut res = targets.targets.keys().cloned().collect::<Vec<String>>();
                res.sort();
                res
            }
            None => Vec::new(),
        }
    }

    /// Verifies a given target. Fails if the target is missing, or if the metadata chain that
    /// leads to it cannot be verified.
    // TODO stronger input type
    pub fn verify_target(&self, target: &str) -> Result<(), Error> {
        let target_meta = match self.targets {
            Some(ref targets) => {
                targets.targets
                    .get(target)
                    .ok_or_else(|| Error::UnknownTarget)?
            }
            None => return Err(Error::MissingMetadata(Role::Targets)),
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

        // TODO pretty sure this join is wrong somehow
        let path = self.local_path.join(target);
        info!("Reading target from local path: {:?}", path);

        let mut file = File::open(path)?;

        Self::read_and_verify(&mut file,
                              &mut None::<&mut File>,
                              Some(target_meta.length),
                              Some((&hash_alg, &expected_hash.0)))
            .map(|_| ())
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
                                return Err(Error::OversizedTarget);
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
                Err(Error::TargetHashMismatch)
            }
            // this case should never happen, so err if it does for safety
            (Some(_), None) => {
                let msg = "Hash calculated when no expected hash supplied";
                error!("Programming error. Please report this as a bug: {}", msg);
                Err(Error::VerificationFailure(msg.to_string()))
            }
            // this case should never happen, so err if it does for safety
            (None, Some(_)) => {
                let msg = "No hash calculated when expected hash supplied";
                error!("Programming error. Please report this as a bug: {}", msg);
                Err(Error::VerificationFailure(msg.to_string()))
            }
            _ => Ok(()),
        }
    }
}


/// The configuration used to initialize a `Tuf` struct.
pub struct Config {
    url: Url,
    local_path: PathBuf,
    http_client: Client,
}

impl Config {
    /// Create a new builder with the defaul configurations where applicable.
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}


/// Helper that constructs `Config`s and verifies the options.
pub struct ConfigBuilder {
    url: Option<Url>,
    local_path: Option<PathBuf>,
    http_client: Option<Client>,
}

impl ConfigBuilder {
    /// Create a new builder with the defaul configurations where applicable.
    pub fn new() -> Self {
        ConfigBuilder {
            url: None,
            local_path: None,
            http_client: None,
        }
    }

    /// The remote URL of the TUF repo.
    pub fn url(mut self, url: Url) -> Self {
        self.url = Some(url);
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

    /// Verify the configuration.
    pub fn finish(self) -> Result<Config, Error> {
        // TODO verify url scheme is something we support
        let url = self.url
            .ok_or_else(|| Error::InvalidConfig("Repository URL was not set".to_string()))?;

        let local_path = self.local_path
            .ok_or_else(|| Error::InvalidConfig("Local path was not set".to_string()))?;

        Ok(Config {
            url: url,
            local_path: local_path,
            http_client: self.http_client.unwrap_or_else(|| Client::new()),
        })
    }
}
