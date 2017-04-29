use chrono::UTC;
use json;
use ring::digest;
use ring::digest::{SHA256, SHA512};
use std::collections::{HashMap, HashSet};
use std::fs::{File, DirBuilder};
use std::io::Read;
use std::path::{PathBuf, Path};
use url::Url;

use cjson;
use error::Error;
use metadata::{Role, RoleType, Root, Targets, Timestamp, Snapshot, Metadata, SignedMetadata,
               RootMetadata, TargetsMetadata, TimestampMetadata, SnapshotMetadata, HashType,
               HashValue, KeyId, Key};


/// Interface for interacting with TUF repositories.
#[derive(Debug)]
pub struct Tuf {
    url: Url,
    local_path: PathBuf,
    root: RootMetadata,
    targets: Option<TargetsMetadata>,
    timestamp: Option<TimestampMetadata>,
    snapshot: Option<SnapshotMetadata>,
}

impl Tuf {
    /// Create a `Tuf` struct from an existing repo with the initial root keys pinned.
    pub fn from_root_keys(root_keys: Vec<Key>, config: Config) -> Result<Self, Error> {
        // TODO have this try local then try from the URL since things might not be initialized
        let root = {
            let modified_root = Self::read_root_with_keys(&config.local_path, &root_keys)?;
            // pass it back through the main path to ensure consistency
            Self::load_meta_num::<Root, RootMetadata>(&config.local_path, 1, &modified_root)?
        };

        let mut tuf = Tuf {
            url: config.url,
            local_path: config.local_path,
            root: root,
            targets: None,
            timestamp: None,
            snapshot: None,
        };

        tuf.update_local()?;
        Ok(tuf)
    }

    /// Create a `Tuf` struct from a new repo. Must contain the `root.json`. The root is trusted
    /// with only verification on consistency, not authenticity. This call also calls `initialize`
    /// to ensure the needed paths exist.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::initialize(&config.local_path)?;

        let root = {
            let root = Self::unverified_read_root(&config.local_path)?;
            Self::load_metadata::<Root, RootMetadata>(&config.local_path, &root)?
        };

        let mut tuf = Tuf {
            url: config.url,
            local_path: config.local_path,
            root: root,
            targets: None,
            timestamp: None,
            snapshot: None,
        };
        tuf.update_local()?;

        Ok(tuf)
    }

    /// Create and verify the necessary directory structure for a TUF repo.
    pub fn initialize(local_path: &PathBuf) -> Result<(), Error> {
        for dir in vec!["metadata/latest", "metadata/archive", "targets"].iter() {
            DirBuilder::new().recursive(true)
                .create(local_path.as_path().join(dir))?

            // TODO error if path is not fully owned by the current user
        }

        Ok(())
    }

    fn update_local(&mut self) -> Result<(), Error> {
        self.update_root_local()?;

        if self.update_timestamp_local()? && self.update_snapshot_local()? {
            self.update_targets_local()
        } else {
            Ok(())
        }
    }

    fn update_root_local(&mut self) -> Result<(), Error> {
        let temp_root = Self::unverified_read_root(&self.local_path)?;

        for i in (self.root.version + 1)..(temp_root.version + 1) {
            let root = Self::load_meta_num::<Root, RootMetadata>(&self.local_path,
                                                                 i,
                                                                 &self.root)?;

            info!("Rotated to root metadata version {}", i);
            self.root = root;

            // set to None to untrust old metadata
            // TODO this is bad because it allows rollbacks
            self.targets = None;
            self.timestamp = None;
            self.snapshot = None;
        }

        Ok(())
    }

    fn update_timestamp_local(&mut self) -> Result<bool, Error> {
        let timestamp = Self::load_metadata::<Timestamp, TimestampMetadata>(&self.local_path,
                                                                            &self.root)?;
        match self.timestamp {
            Some(ref t) if t.version > timestamp.version => {
                return Err(Error::VersionDecrease(Role::Timestamp))
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

        Ok(true)
    }

    fn update_snapshot_local(&mut self) -> Result<bool, Error> {
        let meta = match self.timestamp {
            Some(ref timestamp) => timestamp.meta.get("snapshot.json").unwrap(), // TODO
            None => return Err(Error::MissingMetadata(Role::Timestamp)),
        };

        let (hash_alg, expected_hash): (HashType, &HashValue) = HashType::preferences().iter()
            .fold(None, |res, pref| {
                res.or_else(|| if let Some(hash) = meta.hashes.get(&pref) {
                    Some((pref.clone(), hash))
                } else {
                    None
                })
            })
            .ok_or_else(|| Error::NoSupportedHashAlgorithms)?;

        let snapshot = Self::load_metadata_checked::<Snapshot, SnapshotMetadata>(&self.local_path,
                                                                                 &self.root,
                                                                                 meta.length,
                                                                                 &hash_alg,
                                                                                 &expected_hash.0)?;
        match self.snapshot {
            Some(ref s) if s.version > snapshot.version => {
                return Err(Error::VersionDecrease(Role::Snapshot))
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
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    fn update_targets_local(&mut self) -> Result<(), Error> {
        let targets = Self::load_metadata::<Targets, TargetsMetadata>(&self.local_path,
                                                                      &self.root)?;
        match self.targets {
            Some(ref t) if t.version > targets.version => {
                return Err(Error::VersionDecrease(Role::Targets))
            }
            Some(ref t) if t.version == targets.version => return Ok(()),
            _ => self.targets = Some(targets),
        }

        Ok(())
    }

    fn load_metadata<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                  root: &RootMetadata)
                                                  -> Result<M, Error> {
        Self::load_meta_prefix(local_path, "", root, None)
    }

    fn load_metadata_checked<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                          root: &RootMetadata,
                                                          size: i64,
                                                          hash_alg: &HashType,
                                                          expected_hash: &[u8]) -> Result<M, Error> {
        Self::load_meta_prefix(local_path, "", root, Some((size, hash_alg, expected_hash)))
    }

    fn load_meta_num<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                  num: i32,
                                                  root: &RootMetadata)
                                                  -> Result<M, Error> {
        Self::load_meta_prefix(local_path, &format!("{}.", num), root, None)
    }

    fn load_meta_prefix<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                     prefix: &str,
                                                     root: &RootMetadata,
                                                     meta: Option<(i64, &HashType, &[u8])>)
                                                     -> Result<M, Error> {
        let path = local_path.join("metadata/latest").join(format!("{}{}.json", prefix, R::role()));
        info!("Reading metadata from local path: {:?}", path);

        let mut file = File::open(path)?;
        let mut buf = Vec::new();

        match meta {
            Some((size, hash_alg, expected_hash)) => Self::read_and_verify(&mut file,
                                                                           &mut buf,
                                                                           size,
                                                                           &hash_alg,
                                                                           &expected_hash)?,
            None => file.read_to_end(&mut buf).map(|_| ())?,
        };

        let signed = json::from_slice(&buf)?;
        let safe_bytes = Self::verify_meta::<R>(signed, root)?;
        let meta: M = json::from_slice(&safe_bytes)?;

        if meta.expires() <= &UTC::now() {
            return Err(Error::ExpiredMetadata(R::role()));
        }

        Ok(meta)
    }

    fn unverified_read_root(local_path: &Path) -> Result<RootMetadata, Error> {
        let path = local_path.join("metadata/latest").join("root.json");
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let signed: SignedMetadata<Root> = json::from_slice(&buf)?;
        let root_str = signed.signed.to_string();
        Ok(json::from_str(&root_str)?)
    }

    /// Read the root.json metadata and replace keys for the root role with the keys that are given
    /// as arguments to this function. This initial read is unverified in any way.
    fn read_root_with_keys(local_path: &Path, root_keys: &[Key]) -> Result<RootMetadata, Error> {
        let path = local_path.join("metadata").join("latest").join("1.root.json");
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

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
        // TODO use the real cjson lib and not this crap
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

        let (hash_alg, expected_hash): (HashType, HashValue) = HashType::preferences().iter()
            .fold(None, |res, pref| {
                res.or_else(|| if let Some(hash) = target_meta.hashes.get(&pref) {
                    Some((pref.clone(), hash.clone()))
                } else {
                    None
                })
            })
            .ok_or_else(|| Error::NoSupportedHashAlgorithms)?;

        // TODO pretty sure this join is wrong somehow
        let path = self.local_path.join(target);
        info!("Reading target from local path: {:?}", path);

        let mut file = File::open(path)?;
        let mut out = Vec::new();

        Self::read_and_verify(&mut file,
                              &mut out,
                              target_meta.length,
                              &hash_alg,
                              &expected_hash.0)
            .map(|_| ())
    }

    fn read_and_verify<R: Read>(input: &mut R,
                                output: &mut Vec<u8>,
                                size: i64,
                                hash_alg: &HashType,
                                expected_hash: &[u8])
                                -> Result<(), Error> {
        let mut context = match hash_alg {
            &HashType::Sha512 => digest::Context::new(&SHA512),
            &HashType::Sha256 => digest::Context::new(&SHA256),
            &HashType::Unsupported(_) => return Err(Error::NoSupportedHashAlgorithms),
        };

        let mut buf = [0; 1024];
        let mut bytes_left = size;

        loop {
            match input.read(&mut buf) {
                Ok(read_bytes) => {
                    output.extend(&buf[0..read_bytes]);
                    context.update(&buf[0..read_bytes]);
                    bytes_left -= read_bytes as i64;
                    if bytes_left == 0 {
                        break;
                    } else if bytes_left < 0 {
                        return Err(Error::OversizedTarget);
                    }
                }
                e @ Err(_) => e.map(|_| ())?,
            }
        }

        let generated_hash = context.finish();

        if generated_hash.as_ref() == expected_hash {
            Ok(())
        } else {
            Err(Error::TargetHashMismatch)
        }
    }
}


/// The configuration used to initialize a `Tuf` struct.
pub struct Config {
    url: Url,
    local_path: PathBuf,
}

impl Config {
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}


/// Helper that constructs `Config`s and verifies the options.
pub struct ConfigBuilder {
    url: Option<Url>,
    local_path: Option<PathBuf>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        ConfigBuilder {
            url: None,
            local_path: None,
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
        })
    }
}
