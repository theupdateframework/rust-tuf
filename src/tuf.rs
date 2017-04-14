use chrono::UTC;
use crypto::digest::Digest;
use crypto::sha2::{Sha512, Sha256};
use json;
use std::collections::{HashMap, HashSet};
use std::fs::{File, DirBuilder};
use std::io::Read;
use std::marker::PhantomData;
use std::path::{PathBuf, Path};
use url::Url;

use cjson;
use error::Error;
use metadata::{Role, RoleType, Root, Targets, Timestamp, Snapshot, Metadata, SignedMetadata,
               RootMetadata, TargetsMetadata, TimestampMetadata, SnapshotMetadata, HashType,
               HashValue, KeyId, Key};

pub struct Tuf {
    url: Url,
    local_path: PathBuf,
    root: RootMetadata,
    targets: Option<TargetsMetadata>,
    timestamp: Option<TimestampMetadata>,
    snapshot: Option<SnapshotMetadata>,
}

impl Tuf {
    // TODO it should be possible to use Tuf::new() and /then/ tuf.initialize()
    // Right now ::new fails if the paths don't exist.
    pub fn new(config: Config) -> Result<Self, Error> {
        // TODO have this try local then try from the URL since things might not be initialized
        let root = {
            let root = Self::read_root(&config.local_path, &config.root_keys)?;
            // pass it back through the main path to ensure consistency
            Self::load_metadata::<Root, RootMetadata>(&config.local_path, &root)?
        };

        let targets = Self::load_metadata::<Targets, TargetsMetadata>(&config.local_path, &root)?;
        let timestamp = Self::load_metadata::<Timestamp, TimestampMetadata>(&config.local_path,
                                                                            &root)?;
        let snapshot = Self::load_metadata::<Snapshot, SnapshotMetadata>(&config.local_path,
                                                                         &root)?;

        // TODO cross verification of all the metadata against each other
        // TODO check the timestamps aren't expired

        Ok(Tuf {
            url: config.url,
            local_path: config.local_path,
            root: root,
            targets: Some(targets), // TODO we are wrongly assuming that this is always present
            timestamp: Some(timestamp), // TODO we are wrongly assuming that this is always present
            snapshot: Some(snapshot), // TODO we are wrongly assuming that this is always present
        })
    }

    pub fn initialize(&self) -> Result<(), Error> {
        for dir in vec!["metadata", "targets"].iter() {
            DirBuilder::new().recursive(true)
                .create(self.local_path.as_path().join(dir))?

            // TODO error if path is not fully owned by the current user
        }

        Ok(())
    }

    fn load_metadata<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                  root: &RootMetadata)
                                                  -> Result<M, Error> {
        Self::load_meta_prefix(local_path, "", root)
    }

    fn load_meta_num<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                  num: i32,
                                                  root: &RootMetadata)
                                                  -> Result<M, Error> {
        Self::load_meta_prefix(local_path, &format!("{}.", num), root)
    }

    fn load_meta_hash<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                   hash: &str,
                                                   root: &RootMetadata)
                                                   -> Result<M, Error> {
        Self::load_meta_prefix(local_path, &format!("{}.", hash), root)
    }

    fn read_root(local_path: &Path, root_keys: &[Key]) -> Result<RootMetadata, Error> {
        let path = local_path.join("metadata").join("root.json");
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
                        // TODO unwrap
                        key_ids.extend(root_keys.iter().map(|k| json!(k.value.key_id().0)));
                    }
                }
            }
        }

        Ok(json::from_value(signed.signed)?)
    }

    fn load_meta_prefix<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                     prefix: &str,
                                                     root: &RootMetadata)
                                                     -> Result<M, Error> {
        let path = local_path.join("metadata").join(format!("{}{}.json", prefix, R::role()));
        info!("Reading metadata from local path: {:?}", path);

        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let signed = json::from_slice(&buf)?;
        let safe_bytes = Self::verify_meta::<R>(signed, root)?;
        let meta: M = json::from_slice(&safe_bytes)?;

        if meta.expires() <= &UTC::now() {
            return Err(Error::ExpiredMetadata);
        }

        Ok(meta)
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
                }
                m
            });

        println!("role keys {:?}", role.key_ids);
        println!("keys {:?}", keys);

        let mut threshold = role.threshold;
        for sig in signed.signatures.iter() {
            debug!("Verifying role {:?} with key ID {:?}",
                   R::role(),
                   sig.key_id);
            if let Some(key) = keys.get(&sig.key_id) {
                debug!("Verifying role {:?} with key ID {:?}",
                       R::role(),
                       sig.key_id);

                match key.verify(&sig.method, &bytes, &sig.sig) {
                    Ok(()) => threshold -= 1,
                    Err(e) => warn!("Failed to verify with key ID {:?}: {:?}", &sig.key_id, e),
                }
                if threshold == 0 {
                    return Ok(bytes);
                }
            }
        }

        Err(Error::VerificationFailure(format!("Threshold not met: {}/{}",
                                               role.threshold - threshold,
                                               role.threshold)))
    }

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

    // TODO stronger input type
    pub fn verify_target(&self, target: &str) -> Result<(), Error> {
        let target_meta = match self.targets {
            Some(ref targets) => {
                targets.targets
                    .get(target)
                    .ok_or_else(|| Error::UnknownTarget)?
            }
            None => unreachable!(), // TODO
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

        let path = self.local_path.join("targets").join(target);
        info!("Reading target from local path: {:?}", path);
        let mut file = File::open(path)?;

        match hash_alg {
            HashType::Sha512 => {
                Self::read_and_verify(&mut file,
                                      &mut Sha512::new(),
                                      target_meta.length,
                                      &expected_hash.0)
            }
            HashType::Sha256 => {
                Self::read_and_verify(&mut file,
                                      &mut Sha256::new(),
                                      target_meta.length,
                                      &expected_hash.0)
            }
            HashType::Unsupported(_) => Err(Error::NoSupportedHashAlgorithms),
        }
    }

    fn read_and_verify<R: Read, D: Digest>(input: &mut R,
                                           digest: &mut D,
                                           size: i64,
                                           expected_hash: &[u8])
                                           -> Result<(), Error> {
        let mut buf = [0; 1024];
        let mut bytes_left = size;

        loop {
            match input.read(&mut buf) {
                Ok(read_bytes) => {
                    digest.input(&buf[0..read_bytes]);
                    bytes_left -= read_bytes as i64;
                    if bytes_left == 0 {
                        break;
                    } else if bytes_left <= 0 {
                        panic!("Too many bytes read") // TODO this is sad
                    }
                }
                e @ Err(_) => e.map(|_| ())?,
            }
        }

        let mut generated_hash = vec![0; digest.output_bytes()];
        digest.result(&mut generated_hash);

        if generated_hash.as_slice() == expected_hash {
            Ok(())
        } else {
            Err(Error::TargetHashMismatch)
        }
    }
}

pub struct Config {
    url: Url,
    local_path: PathBuf,
    root_keys: Vec<Key>,
}

impl Config {
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}


pub struct ConfigBuilder {
    url: Option<Url>,
    local_path: Option<PathBuf>,
    root_keys: Vec<Key>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        ConfigBuilder {
            url: None,
            local_path: None,
            root_keys: Vec::new(),
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

    /// The initial trusted root keys.
    pub fn root_keys(mut self, root_keys: Vec<Key>) -> Self {
        self.root_keys = root_keys;
        self
    }

    /// Verify the configuration.
    pub fn finish(self) -> Result<Config, Error> {
        // TODO verify url scheme is something we support
        let url = self.url
            .ok_or_else(|| Error::InvalidConfig("Repository URL was not set".to_string()))?;

        let local_path = self.local_path
            .ok_or_else(|| Error::InvalidConfig("Local path was not set".to_string()))?;

        if self.root_keys.is_empty() {
            return Err(Error::InvalidConfig("No root keys supplied".to_string()));
        }

        Ok(Config {
            url: url,
            local_path: local_path,
            root_keys: self.root_keys,
        })
    }
}
