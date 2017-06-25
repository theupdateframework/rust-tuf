//! Clients for high level interactions with TUF repositories.

use chrono::offset::Utc;

use Result;
use error::Error;
use interchange::DataInterchange;
use metadata::{MetadataVersion, RootMetadata, Role};
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
    pub fn new(tuf: Tuf<D>, config: Config, local: L, remote: R) -> Self {
        Client {
            tuf: tuf,
            config: config,
            local: local,
            remote: remote,
        }
    }

    /// Update TUF metadata from local and remote repositories.
    pub fn update(&mut self) -> Result<()> {
        self.update_root()
    }

    fn update_root(&mut self) -> Result<()> {
        Self::update_root_chain(&mut self.tuf, &self.config.max_root_size, &mut self.local)?;
        Self::update_root_chain(&mut self.tuf, &self.config.max_root_size, &mut self.remote)?;

        if self.tuf.root().expires() <= &Utc::now() {
            Err(Error::ExpiredMetadata(Role::Root))
        } else {
            Ok(())
        }
    }

    fn update_root_chain<T>(tuf: &mut Tuf<D>, max_root_size: &Option<usize>, repo: &mut T) -> Result<()>
    where
        T: Repository<D>
    {
        let latest_root = repo.fetch_root(&MetadataVersion::None, max_root_size)?;
        let latest_version = D::deserialize::<RootMetadata>(latest_root.unverified_signed())?
            .version();

        if latest_version < tuf.root().version() {
            return Err(Error::VerificationFailure(format!(
                "Latest root version is lower than current root version: {} < {}",
                latest_version,
                tuf.root().version()
            )))
        } else if latest_version == tuf.root().version() {
            return Ok(())
        }

        for i in (tuf.root().version() + 1)..latest_version {
            let signed = repo.fetch_root(&MetadataVersion::Number(i), max_root_size)?;
            tuf.update_root(signed)?;
        }

        tuf.update_root(latest_root)
    }
}

/// Configuration for a TUF `Client`.
pub struct Config {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
}

impl Config {
    /// Initialize a `ConfigBuilder` with the default values.
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Helper for building a validating a TUF `Config`.
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
    fn default() -> Self {
        ConfigBuilder {
            max_root_size: Some(1024 * 1024),
            max_timestamp_size: Some(32 * 1024),
        }
    }
}
