//! Interfaces for interacting with different types of TUF repositories.

use hyper::{Url, Client};
use hyper::client::response::Response;
use hyper::header::{Headers, UserAgent};
use std::collections::HashMap;
use std::fs::{self, File, DirBuilder};
use std::io::Read;
use std::marker::PhantomData;
use std::path::PathBuf;

use Result;
use error::Error;
use metadata::{SignedMetadata, MetadataVersion, Unverified, Verified, Role, Metadata};
use interchange::DataInterchange;

/// Top-level trait that represents a TUF repository and contains all the ways it can be interacted
/// with.
pub trait Repository<D>
where
    D: DataInterchange,
{
    /// Initialize the repository.
    fn initialize(&mut self) -> Result<()>;

    /// Store signed metadata.
    fn store_metadata<M>(
        &mut self,
        role: &Role,
        version: &MetadataVersion,
        metadata: &SignedMetadata<D, M, Verified>,
    ) -> Result<()>
    where
        M: Metadata;

    /// Fetch signed metadata.
    fn fetch_metadata<M>(
        &mut self,
        role: &Role,
        version: &MetadataVersion,
        max_size: &Option<usize>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata;

    /// Get the version string that addresses the metadata.
    fn version_string(role: &Role, version: &MetadataVersion) -> String {
        // TODO this doesn't support delegations that could have `/` chars in them
        format!("{}{}{}", version.prefix(), role, D::extension())
    }

    /// Read the from given reader, optionally capped at `max_size` bytes.
    fn safe_read<R: Read>(read: &mut R, max_size: &Option<usize>) -> Result<Vec<u8>> {
        match max_size {
            &Some(max_size) => {
                let mut buf = vec![0; max_size];
                read.read_exact(&mut buf)?;
                Ok(buf)
            }
            &None => {
                let mut buf = Vec::new();
                let _ = read.read_to_end(&mut buf)?;
                Ok(buf)
            }
        }
    }
}

/// A repository contained on the local file system.
pub struct FileSystemRepository<D>
where
    D: DataInterchange,
{
    local_path: PathBuf,
    _interchange: PhantomData<D>,
}

impl<D> FileSystemRepository<D>
where
    D: DataInterchange,
{
    /// Create a new repository on the local file system.
    pub fn new(local_path: PathBuf) -> Self {
        FileSystemRepository {
            local_path: local_path,
            _interchange: PhantomData,
        }
    }
}

impl<D> Repository<D> for FileSystemRepository<D>
where
    D: DataInterchange,
{
    fn initialize(&mut self) -> Result<()> {
        for p in &["metadata", "targets"] {
            DirBuilder::new().recursive(true).create(
                self.local_path.join(p),
            )?
        }

        Ok(())
    }

    fn store_metadata<M>(
        &mut self,
        role: &Role,
        version: &MetadataVersion,
        metadata: &SignedMetadata<D, M, Verified>,
    ) -> Result<()>
    where
        M: Metadata,
    {
        if role != &M::role() {
            return Err(Error::IllegalArgument(format!(
                "Attempted to store {} metadata as {}.",
                M::role(),
                role
            )));
        }
        let version_str = Self::version_string(role, version);
        let path = self.local_path.join("metadata").join(&version_str);

        if path.exists() {
            debug!("Metadata path exists. Deleting: {:?}", path);
            fs::remove_file(&path)?
        }

        let mut file = File::create(&path)?;
        D::to_writer(&mut file, metadata)?;
        Ok(())

    }

    /// Fetch signed metadata.
    fn fetch_metadata<M>(
        &mut self,
        role: &Role,
        version: &MetadataVersion,
        max_size: &Option<usize>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata,
    {
        let version_str = Self::version_string(role, version);
        let path = self.local_path.join("metadata").join(&version_str);
        let mut file = File::open(&path)?;
        let buf = Self::safe_read(&mut file, max_size)?;
        Ok(D::from_reader(&*buf)?)
    }
}


/// A repository accessible over HTTP.
pub struct HttpRepository<D>
where
    D: DataInterchange,
{
    url: Url,
    client: Client,
    user_agent: String,
    _interchange: PhantomData<D>,
}

impl<D> HttpRepository<D>
where
    D: DataInterchange,
{
    /// Create a new repository with the given `Url` and `Client`. Callers *should* include a
    /// custom User-Agent prefix to maintainers of TUF repositories keep track of which client
    /// versions exist in the field.
    pub fn new(url: Url, client: Client, user_agent_prefix: Option<String>) -> Self {
        let user_agent = match user_agent_prefix {
            Some(ua) => format!("{} (rust-tuf/{})", ua, env!("CARGO_PKG_VERSION")),
            None => format!("rust-tuf/{}", env!("CARGO_PKG_VERSION")),
        };

        HttpRepository {
            url: url,
            client: client,
            user_agent: user_agent,
            _interchange: PhantomData,
        }
    }

    fn get(&self, path: &str) -> Result<Response> {
        let mut headers = Headers::new();
        headers.set(UserAgent(self.user_agent.clone()));

        let req = self.client.get(self.url.join(path)?).headers(headers);
        Ok(req.send()?)
    }
}

impl<D> Repository<D> for HttpRepository<D>
where
    D: DataInterchange,
{
    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    fn store_metadata<M>(
        &mut self,
        role: &Role,
        _: &MetadataVersion,
        _: &SignedMetadata<D, M, Verified>,
    ) -> Result<()>
    where
        M: Metadata,
    {
        if role != &M::role() {
            return Err(Error::IllegalArgument(format!(
                "Attempted to store {} metadata as {}.",
                M::role(),
                role
            )));
        }
        Err(Error::Generic(
            "Http repo store root not implemented".to_string(),
        ))
    }

    fn fetch_metadata<M>(
        &mut self,
        role: &Role,
        version: &MetadataVersion,
        max_size: &Option<usize>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata,
    {
        let version_str = Self::version_string(role, version);
        let mut resp = self.get(&version_str)?;
        let buf = Self::safe_read(&mut resp, max_size)?;
        Ok(D::from_reader(&*buf)?)
    }
}


/// An ephemeral repository contained solely in memory.
pub struct EphemeralRepository<D>
where
    D: DataInterchange,
{
    metadata: HashMap<String, Vec<u8>>,
    _interchange: PhantomData<D>,
}

impl<D> EphemeralRepository<D>
where
    D: DataInterchange,
{
    /// Create a new ephemercal repository.
    pub fn new() -> Self {
        EphemeralRepository {
            metadata: HashMap::new(),
            _interchange: PhantomData,
        }
    }
}

impl<D> Repository<D> for EphemeralRepository<D>
where
    D: DataInterchange,
{
    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    fn store_metadata<M>(
        &mut self,
        role: &Role,
        version: &MetadataVersion,
        root: &SignedMetadata<D, M, Verified>,
    ) -> Result<()>
    where
        M: Metadata,
    {
        if role != &M::role() {
            return Err(Error::IllegalArgument(format!(
                "Attempted to store {} metadata as {}.",
                M::role(),
                role
            )));
        }

        let version_str = Self::version_string(role, version);
        let mut buf = Vec::new();
        D::to_writer(&mut buf, root)?;
        let _ = self.metadata.insert(version_str, buf);
        Ok(())
    }

    fn fetch_metadata<M>(
        &mut self,
        role: &Role,
        version: &MetadataVersion,
        _: &Option<usize>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata,
    {
        let version_str = Self::version_string(role, version);
        match self.metadata.get(&version_str) {
            Some(bytes) => D::from_reader(&**bytes),
            None => Err(Error::NotFound),
        }
    }
}
