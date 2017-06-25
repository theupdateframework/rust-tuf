//! Clients for high level interactions with TUF repositories.

use repository::Repository;

use Result;
use interchange::DataInterchange;
use metadata::MetadataVersion;
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

    /// Update TUF metadata from local and remote sources.
    pub fn update(&mut self) -> Result<()> {
        self.update_root()
    }

    fn update_root(&mut self) -> Result<()> {
        // TODO this doesn't build the chain back up from scratch
        let root = self.local.fetch_root(
            &MetadataVersion::None,
            &self.config.max_root_size,
        )?;
        self.tuf.update_root(root)?;

        // TODO this doesn't build the chain back up from scratch
        let root = self.remote.fetch_root(
            &MetadataVersion::None,
            &self.config.max_root_size,
        )?;
        
        // TODO store the newly fetched roots in the local repo

        self.tuf.update_root(root)
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
