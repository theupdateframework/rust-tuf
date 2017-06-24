use repository::Repository;

use Result;
use metadata::interchange::DataInterchange;
use metadata::MetadataVersion;
use tuf::Tuf;

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
    pub fn new(tuf: Tuf<D>, config: Config, local: L, remote: R) -> Self {
        Client {
            tuf: tuf,
            config: config,
            local: local,
            remote: remote,
        }
    }

    pub fn update(&mut self) -> Result<()> {
        self.update_root()
    }

    fn update_root(&mut self) -> Result<()> {
        let root = self.local.fetch_root(
            &MetadataVersion::None,
            &self.config.max_root_size,
        )?;
        self.tuf.update_root(root)?;

        let root = self.remote.fetch_root(
            &MetadataVersion::None,
            &self.config.max_root_size,
        )?;
        self.tuf.update_root(root)
    }
}


pub struct Config {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
}

impl Config {
    pub fn build() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

pub struct ConfigBuilder {
    max_root_size: Option<usize>,
    max_timestamp_size: Option<usize>,
}

impl ConfigBuilder {
    pub fn finish(self) -> Result<Config> {
        Ok(Config {
            max_root_size: self.max_root_size,
            max_timestamp_size: self.max_timestamp_size,
        })
    }

    pub fn max_root_size(mut self, max: Option<usize>) -> Self {
        self.max_root_size = max;
        self
    }

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
