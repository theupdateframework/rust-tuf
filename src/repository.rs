//! Interfaces for interacting with different types of TUF repositories.

use hyper::{Url, Client};
use hyper::client::response::Response;
use hyper::header::{Headers, UserAgent};
use ring::digest::{self, SHA256, SHA512};
use std::collections::HashMap;
use std::fs::{self, File, DirBuilder};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::PathBuf;

use Result;
use crypto::{HashAlgorithm, HashValue};
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
        hash_data: Option<(&HashAlgorithm, &HashValue)>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata;

    /// Get the version string that addresses the metadata.
    fn version_string(role: &Role, version: &MetadataVersion) -> String {
        // TODO this doesn't support delegations that could have `/` chars in them
        format!("{}{}{}", version.prefix(), role, D::extension())
    }

    /// Read the from given reader, optionally capped at `max_size` bytes, optionally requiring
    /// hashes to match.
    fn safe_read<R, W>(
        read: &mut R,
        write: &mut W,
        max_size: Option<i64>,
        hash_data: Option<(&HashAlgorithm, &HashValue)>,
    ) -> Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut context = match hash_data {
            Some((&HashAlgorithm::Sha256, _)) => Some(digest::Context::new(&SHA256)),
            Some((&HashAlgorithm::Sha512, _)) => Some(digest::Context::new(&SHA512)),
            None => None,
        };

        let mut buf = [0; 1024];
        let mut bytes_left = max_size.unwrap_or(::std::i64::MAX);

        loop {
            match read.read(&mut buf) {
                Ok(read_bytes) => {
                    if read_bytes == 0 {
                        break;
                    }

                    bytes_left -= read_bytes as i64;
                    if bytes_left < 0 {
                        return Err(Error::VerificationFailure(
                            "Read exceeded the maximum allowed bytes.".into(),
                        ));
                    }

                    write.write_all(&buf[0..read_bytes])?;

                    match context {
                        Some(ref mut c) => c.update(&buf[0..read_bytes]),
                        None => (),
                    };
                }
                e @ Err(_) => e.map(|_| ())?,
            }
        }

        let generated_hash = context.map(|c| c.finish());

        match (generated_hash, hash_data) {
            (Some(generated_hash), Some((_, expected_hash)))
                if generated_hash.as_ref() != expected_hash.value() => {
                Err(Error::VerificationFailure(
                    "Generated hash did not match expected hash.".into(),
                ))
            }
            (Some(_), None) => {
                let msg = "Hash calculated when no expected hash supplied. \
                           This is a programming error. Please report this as a bug.";
                error!("{}", msg);
                Err(Error::Programming(msg.into()))
            }
            (None, Some(_)) => {
                let msg = "No hash calculated when expected hash supplied. \
                           This is a programming error. Please report this as a bug.";
                error!("{}", msg);
                Err(Error::Programming(msg.into()))
            }
            (Some(_), Some(_)) |
            (None, None) => Ok(()),
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
        hash_data: Option<(&HashAlgorithm, &HashValue)>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata,
    {
        let version_str = Self::version_string(role, version);
        let path = self.local_path.join("metadata").join(&version_str);
        let mut file = File::open(&path)?;
        let mut out = Vec::new();
        Self::safe_read(&mut file, &mut out, max_size.map(|x| x as i64), hash_data)?;
        Ok(D::from_reader(&*out)?)
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
        Err(Error::Opaque(
            "Http repo store root not implemented".to_string(),
        ))
    }

    fn fetch_metadata<M>(
        &mut self,
        role: &Role,
        version: &MetadataVersion,
        max_size: &Option<usize>,
        hash_data: Option<(&HashAlgorithm, &HashValue)>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata,
    {
        let version_str = Self::version_string(role, version);
        let mut resp = self.get(&version_str)?;
        let mut out = Vec::new();
        Self::safe_read(&mut resp, &mut out, max_size.map(|x| x as i64), hash_data)?;
        Ok(D::from_reader(&*out)?)
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
        _: Option<(&HashAlgorithm, &HashValue)>,
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
