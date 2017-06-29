//! Interfaces for interacting with different types of TUF repositories.

use hyper::{Url, Client};
use hyper::client::response::Response;
use hyper::header::{Headers, UserAgent};
use hyper::status::StatusCode;
use ring::digest::{self, SHA256, SHA512};
use std::collections::HashMap;
use std::fs::{self, File, DirBuilder};
use std::io::{Read, Write, Cursor};
use std::marker::PhantomData;
use std::path::PathBuf;
use tempfile::NamedTempFile;

use Result;
use crypto::{self, HashAlgorithm, HashValue};
use error::Error;
use metadata::{SignedMetadata, MetadataVersion, Unverified, Verified, Role, Metadata, TargetPath, TargetDescription, MetadataPath};
use interchange::DataInterchange;

/// Top-level trait that represents a TUF repository and contains all the ways it can be interacted
/// with.
pub trait Repository<D>
where
    D: DataInterchange,
{
    /// The type returned when reading a target.
    type TargetRead: Read;

    /// Initialize the repository.
    fn initialize(&mut self) -> Result<()>;

    /// Store signed metadata.
    fn store_metadata<M>(
        &mut self,
        role: &Role,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        metadata: &SignedMetadata<D, M, Verified>,
    ) -> Result<()>
    where
        M: Metadata;

    /// Fetch signed metadata.
    fn fetch_metadata<M>(
        &mut self,
        role: &Role,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        max_size: &Option<usize>,
        hash_data: Option<(&HashAlgorithm, &HashValue)>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata;

    /// Store the given target.
    fn store_target<R>(&mut self, read: R, target_path: &TargetPath, target_description: &TargetDescription) -> Result<()>
    where
        R: Read;

    /// Fetch the given target.
    ///
    /// **WARNING**: The target will **NOT** yet be verified.
    fn fetch_target(&mut self, target_path: &TargetPath) -> Result<Self::TargetRead>;

    /// Perform a sanity check that `M`, `Role`, and `MetadataPath` all desrcribe the same entity.
    fn check<M>(role: &Role, meta_path: &MetadataPath) -> Result<()>
    where
        M: Metadata
    {
        if role != &M::role() {
            return Err(Error::IllegalArgument(format!(
                "Attempted to store {} metadata as {}.",
                M::role(),
                role
            )));
        }

        if !role.fuzzy_matches_path(meta_path) {
            return Err(Error::IllegalArgument(format!(
                "Role {} does not match path {:?}",
                role,
                meta_path)))
        }

        Ok(())
    }

    /// Read the from given reader, optionally capped at `max_size` bytes, optionally requiring
    /// hashes to match.
    fn safe_read<R, W>(
        mut read: R,
        mut write: W,
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
    type TargetRead = File;

    fn initialize(&mut self) -> Result<()> {
        for p in &["metadata", "targets", "temp"] {
            DirBuilder::new().recursive(true).create(
                self.local_path.join(p),
            )?
        }

        Ok(())
    }

    fn store_metadata<M>(
        &mut self,
        role: &Role,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        metadata: &SignedMetadata<D, M, Verified>,
    ) -> Result<()>
    where
        M: Metadata,
    {
        Self::check::<M>(role, meta_path)?;

        let mut path = self.local_path.join("metadata");
        path.extend(meta_path.components::<D>(version));

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
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        max_size: &Option<usize>,
        hash_data: Option<(&HashAlgorithm, &HashValue)>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata,
    {
        Self::check::<M>(role, meta_path)?;

        let mut path = self.local_path.join("metadata");
        path.extend(meta_path.components::<D>(&version));

        let mut file = File::open(&path)?;
        let mut out = Vec::new();
        Self::safe_read(&mut file, &mut out, max_size.map(|x| x as i64), hash_data)?;

        Ok(D::from_reader(&*out)?)
    }

    fn store_target<R>(&mut self, read: R, target_path: &TargetPath, target_description: &TargetDescription) -> Result<()>
    where
        R: Read
    {
        let mut temp_file = NamedTempFile::new_in(self.local_path.join("temp"))?;
        let hash_data = crypto::hash_preference(target_description.hashes())?;
        Self::safe_read(read, &mut temp_file, Some(target_description.length() as i64), Some(hash_data))?;

        let mut path = self.local_path.clone().join("targets");
        path.extend(target_path.components());
        temp_file.persist(&path)?;

        Ok(())
    }

    fn fetch_target(&mut self, target_path: &TargetPath) -> Result<File> {
        let mut path = self.local_path.join("targets");
        path.extend(target_path.components());

        if !path.exists() {
            return Err(Error::NotFound)
        }

        Ok(File::open(&path)?)
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

    fn get(&self, components: &[String]) -> Result<Response> {
        let mut headers = Headers::new();
        headers.set(UserAgent(self.user_agent.clone()));

        let mut url = self.url.clone();
        url.path_segments_mut()
            .map_err(|_| Error::IllegalArgument(format!("URL was 'cannot-be-a-base': {:?}", self.url)))?
            .extend(components);

        let req = self.client.get(url.clone()).headers(headers);
        let resp = req.send()?;

        if !resp.status.is_success() {
            if resp.status == StatusCode::NotFound {
                Err(Error::NotFound)
            } else {
                Err(Error::Opaque(format!("Error getting {:?}: {:?}", url, resp)))
            }
        } else {
            Ok(resp)
        }
    }
}

impl<D> Repository<D> for HttpRepository<D>
where
    D: DataInterchange,
{
    type TargetRead = Response;

    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    /// This always returns `Err` as storing over HTTP is not yet supported.
    fn store_metadata<M>(
        &mut self,
        _: &Role,
        _: &MetadataPath,
        _: &MetadataVersion,
        _: &SignedMetadata<D, M, Verified>,
    ) -> Result<()>
    where
        M: Metadata,
    {
        Err(Error::Opaque(
            "Http repo store metadata not implemented".to_string(),
        ))
    }

    fn fetch_metadata<M>(
        &mut self,
        role: &Role,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        max_size: &Option<usize>,
        hash_data: Option<(&HashAlgorithm, &HashValue)>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata,
    {
        Self::check::<M>(role, meta_path)?;

        let mut resp = self.get(&meta_path.components::<D>(&version))?;
        let mut out = Vec::new();
        Self::safe_read(&mut resp, &mut out, max_size.map(|x| x as i64), hash_data)?;
        Ok(D::from_reader(&*out)?)
    }

    /// This always returns `Err` as storing over HTTP is not yet supported.
    fn store_target<R>(&mut self, _: R, _: &TargetPath, _: &TargetDescription) -> Result<()>
    where
        R: Read
    {
        Err(Error::Opaque(
            "Http repo store  not implemented".to_string(),
        ))
    }

    fn fetch_target(&mut self, target_path: &TargetPath) -> Result<Self::TargetRead> {
        let resp = self.get(&target_path.components())?;
        Ok(resp)
    }
}


/// An ephemeral repository contained solely in memory.
pub struct EphemeralRepository<D>
where
    D: DataInterchange,
{
    metadata: HashMap<(MetadataPath, MetadataVersion), Vec<u8>>,
    targets: HashMap<TargetPath, Vec<u8>>,
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
            targets: HashMap::new(),
            _interchange: PhantomData,
        }
    }
}

impl<D> Repository<D> for EphemeralRepository<D>
where
    D: DataInterchange,
{
    type TargetRead = Cursor<Vec<u8>>;

    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    fn store_metadata<M>(
        &mut self,
        role: &Role,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        metadata: &SignedMetadata<D, M, Verified>,
    ) -> Result<()>
    where
        M: Metadata,
    {
        Self::check::<M>(role, meta_path)?;
        let mut buf = Vec::new();
        D::to_writer(&mut buf, metadata)?;
        let _ = self.metadata.insert((meta_path.clone(), version.clone()), buf);
        Ok(())
    }

    fn fetch_metadata<M>(
        &mut self,
        role: &Role,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        max_size: &Option<usize>,
        hash_data: Option<(&HashAlgorithm, &HashValue)>,
    ) -> Result<SignedMetadata<D, M, Unverified>>
    where
        M: Metadata,
    { 
        Self::check::<M>(role, meta_path)?;

        match self.metadata.get(&(meta_path.clone(), version.clone())) {
            Some(bytes) => {
                let mut buf = Vec::new();
                Self::safe_read(bytes.as_slice(), &mut buf, max_size.map(|x| x as i64), hash_data)?;
                D::from_reader(&*buf)
            },
            None => Err(Error::NotFound),
        }
    }

    fn store_target<R>(&mut self, read: R, target_path: &TargetPath, target_description: &TargetDescription) -> Result<()>
    where
        R: Read
    {
        let mut buf = Vec::new();
        let hash_data = crypto::hash_preference(target_description.hashes())?;
        Self::safe_read(read, &mut buf, Some(target_description.length() as i64), Some(hash_data))?;
        let _ = self.targets.insert(target_path.clone(), buf);
        Ok(())
    }

    fn fetch_target(&mut self, target_path: &TargetPath) -> Result<Self::TargetRead> {
        match self.targets.get(target_path) {
            Some(bytes) => Ok(Cursor::new(bytes.clone())),
            None => Err(Error::NotFound)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tempdir::TempDir;
    use interchange::JsonDataInterchange;

    #[test]
    fn ephemeral_repo_targets() {
        let mut repo = EphemeralRepository::<JsonDataInterchange>::new();
        repo.initialize().unwrap();

        let data: &[u8] = b"like tears in the rain";
        let target_description = TargetDescription::from_reader(data).unwrap();
        let path = TargetPath::new("batty".into()).unwrap();
        repo.store_target(data, &path, &target_description).unwrap();

        let mut read = repo.fetch_target(&path).unwrap();
        let mut buf = Vec::new();
        read.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), data);

        let bad_data: &[u8] = b"you're in a desert";
        assert!(repo.store_target(bad_data, &path, &target_description).is_err());

        let mut read = repo.fetch_target(&path).unwrap();
        let mut buf = Vec::new();
        read.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), data);
    }

    #[test]
    fn file_system_repo_targets() {
        let temp_dir = TempDir::new("rust-tuf").unwrap();
        let mut repo = FileSystemRepository::<JsonDataInterchange>::new(temp_dir.path().to_path_buf());
        repo.initialize().unwrap();

        let data: &[u8] = b"like tears in the rain";
        let target_description = TargetDescription::from_reader(data).unwrap();
        let path = TargetPath::new("batty".into()).unwrap();
        repo.store_target(data, &path, &target_description).unwrap();
        assert!(temp_dir.path().join("targets").join("batty").exists());

        let mut read = repo.fetch_target(&path).unwrap();
        let mut buf = Vec::new();
        read.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), data);

        let bad_data: &[u8] = b"you're in a desert";
        assert!(repo.store_target(bad_data, &path, &target_description).is_err());

        let mut read = repo.fetch_target(&path).unwrap();
        let mut buf = Vec::new();
        read.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), data);
    }
}
