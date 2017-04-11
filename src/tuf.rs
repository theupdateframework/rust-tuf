use json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::path::{PathBuf, Path};
use url::Url;

use cjson;
use error::Error;
use metadata::{Role, RoleType, Root, Targets, Timestamp, Snapshot, Metadata, SignedMetadata,
               RootMetadata, TargetsMetadata, TimestampMetadata, SnapshotMetadata};

pub struct Tuf {
    url: Url,
    local_path: PathBuf,
    root: RootMetadata,
    targets: Option<TargetsMetadata>,
    timestamp: Option<TimestampMetadata>,
    snapshot: Option<SnapshotMetadata>,
}

impl Tuf {
    pub fn new(config: Config) -> Result<Self, Error> {
        // TODO don't do an unverified root read, but make someone hard code keys
        // for the first time around
        let root = {
            let scary_bad_root = Self::unverified_read_root(&config.local_path)?;
            Self::load_metadata::<Root, RootMetadata>(&config.local_path, &scary_bad_root)?
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

    fn unverified_read_root(local_path: &Path) -> Result<RootMetadata, Error> {
        let path = local_path.join("root.json");
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let signed: SignedMetadata<Root> = json::from_slice(&buf)?;
        let root_str = signed.signed.to_string();
        Ok(json::from_str(&root_str)?)
    }

    fn load_meta_prefix<R: RoleType, M: Metadata<R>>(local_path: &Path,
                                                     prefix: &str,
                                                     root: &RootMetadata)
                                                     -> Result<M, Error> {
        let path = local_path.join(format!("{}{}.json", prefix, R::role()));
        info!("Reading metadata from local path: {:?}", path);

        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let signed = json::from_slice(&buf)?;
        let safe_bytes = Self::verify_meta::<R>(signed, root)?;
        Ok(json::from_slice(&safe_bytes)?)
    }

    fn verify_meta<R: RoleType>(signed: SignedMetadata<R>,
                                root: &RootMetadata)
                                -> Result<Vec<u8>, Error> {
        // TODO use the real cjson lib and not this crap
        let bytes =
            cjson::canonicalize(signed.signed).map_err(|err| Error::CanonicalJsonError(err))?;

        let role = root.role_definition::<R>();

        // TODO verify that sigs are unique
        // TODO verify that threshold > 0
        // TODO verify that #keys >= threshold

        let keys = role.key_ids
            .iter()
            .map(|id| (id, root.keys.get(id)))
            .fold(HashMap::new(), |mut m, (id, k)| {
                if let Some(key) = k {
                    m.insert(id, key);
                }
                m
            });

        let mut threshold = role.threshold;
        for sig in signed.signatures.iter() {
            if let Some(key) = keys.get(&sig.key_id) {
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

    // TODO real return type
    pub fn list_targets() -> Vec<String> {
        unimplemented!() // TODO
    }

    // TODO real input type
    pub fn fetch_target(target: String) -> Result<PathBuf, Error> {
        unimplemented!() // TODO
    }
}

pub struct Config {
    url: Url,
    local_path: PathBuf,
}

impl Config {
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}


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

    pub fn url(mut self, url: Url) -> Self {
        self.url = Some(url);
        self
    }

    pub fn local_path(mut self, local_path: PathBuf) -> Self {
        self.local_path = Some(local_path);
        self
    }

    pub fn finish(self) -> Result<Config, Error> {
        let url = self.url.ok_or(Error::InvalidConfig("Repository URL was not set".to_string()))?;
        let local_path = self.local_path
            .ok_or(Error::InvalidConfig("Local path was not set".to_string()))?;

        // TODO error if path is not fully owned by the current user
        // TODO create path if not exists

        Ok(Config {
            url: url,
            local_path: local_path,
        })
    }
}
