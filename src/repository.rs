//! Interfaces for interacting with different types of TUF repositories.

use futures::compat::{Future01CompatExt, Stream01CompatExt};
use futures::io::{AllowStdIo, AsyncRead};
use futures::prelude::*;
use http::{Response, StatusCode, Uri};
use hyper::body::Body;
use hyper::client::connect::Connect;
use hyper::Client;
use hyper::Request;
use log::debug;
use std::collections::HashMap;
use std::fs::{DirBuilder, File};
use std::io::{self, Cursor};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tempfile::{self, NamedTempFile};

use crate::crypto::{self, HashAlgorithm, HashValue};
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{
    Metadata, MetadataPath, MetadataVersion, SignedMetadata, TargetDescription, TargetPath,
};
use crate::util::SafeReader;
use crate::{Result, TufFuture};
use url::Url;

/// Top-level trait that represents a TUF repository and contains all the ways it can be interacted
/// with.
pub trait Repository<D>
where
    D: DataInterchange,
{
    /// Store signed metadata.
    ///
    /// Note: This **MUST** canonicalize the bytes before storing them as a read will expect the
    /// hashes of the metadata to match.
    fn store_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        metadata: &'a SignedMetadata<D, M>,
    ) -> TufFuture<'a, Result<()>>
    where
        M: Metadata + 'static;

    /// Fetch signed metadata.
    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: &'a Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> TufFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static;

    /// Store the given target.
    fn store_target<'a, R>(
        &'a self,
        read: R,
        target_path: &'a TargetPath,
    ) -> TufFuture<'a, Result<()>>
    where
        R: AsyncRead + 'a;

    /// Fetch the given target.
    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> TufFuture<'a, Result<Box<dyn AsyncRead>>>;

    /// Perform a sanity check that `M`, `Role`, and `MetadataPath` all desrcribe the same entity.
    fn check<M>(meta_path: &MetadataPath) -> Result<()>
    where
        M: Metadata,
    {
        if !M::ROLE.fuzzy_matches_path(meta_path) {
            return Err(Error::IllegalArgument(format!(
                "Role {} does not match path {:?}",
                M::ROLE,
                meta_path
            )));
        }

        Ok(())
    }
}

/// A repository contained on the local file system.
pub struct FileSystemRepository<D>
where
    D: DataInterchange,
{
    local_path: PathBuf,
    interchange: PhantomData<D>,
}

impl<D> FileSystemRepository<D>
where
    D: DataInterchange,
{
    /// Create a new repository on the local file system.
    pub fn new(local_path: PathBuf) -> Result<Self> {
        for p in &["metadata", "targets", "temp"] {
            DirBuilder::new()
                .recursive(true)
                .create(local_path.join(p))?
        }

        Ok(FileSystemRepository {
            local_path,
            interchange: PhantomData,
        })
    }
}

impl<D> Repository<D> for FileSystemRepository<D>
where
    D: DataInterchange,
{
    fn store_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        metadata: &'a SignedMetadata<D, M>,
    ) -> TufFuture<'a, Result<()>>
    where
        M: Metadata + 'static,
    {
        Box::pin(
            async move {
                Self::check::<M>(meta_path)?;

                let mut path = self.local_path.join("metadata");
                path.extend(meta_path.components::<D>(version));

                if path.exists() {
                    debug!("Metadata path exists. Overwriting: {:?}", path);
                }

                let mut temp_file = create_temp_file(&path)?;
                D::to_writer(&mut temp_file, metadata)?;
                temp_file.persist(&path)?;

                Ok(())
            },
        )
    }

    /// Fetch signed metadata.
    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: &'a Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> TufFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static,
    {
        Box::pin(
            async move {
                Self::check::<M>(&meta_path)?;

                let mut path = self.local_path.join("metadata");
                path.extend(meta_path.components::<D>(&version));

                let mut reader = SafeReader::new(
                    AllowStdIo::new(File::open(&path)?),
                    max_length.unwrap_or(::std::usize::MAX) as u64,
                    0,
                    hash_data,
                )?;

                let mut buf = Vec::with_capacity(max_length.unwrap_or(0));
                await!(reader.read_to_end(&mut buf))?;

                Ok(D::from_slice(&buf)?)
            },
        )
    }

    fn store_target<'a, R>(
        &'a self,
        mut read: R,
        target_path: &'a TargetPath,
    ) -> TufFuture<'a, Result<()>>
    where
        R: AsyncRead + 'a,
    {
        Box::pin(
            async move {
                let mut path = self.local_path.join("targets");
                path.extend(target_path.components());

                if path.exists() {
                    debug!("Target path exists. Overwriting: {:?}", path);
                }

                let mut temp_file = AllowStdIo::new(create_temp_file(&path)?);
                await!(read.copy_into(&mut temp_file))?;
                temp_file.into_inner().persist(&path)?;

                Ok(())
            },
        )
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> TufFuture<'a, Result<Box<dyn AsyncRead>>> {
        Box::pin(
            async move {
                let mut path = self.local_path.join("targets");
                path.extend(target_path.components());

                if !path.exists() {
                    return Err(Error::NotFound);
                }

                let (alg, value) = crypto::hash_preference(target_description.hashes())?;

                let reader: Box<dyn AsyncRead> = Box::new(SafeReader::new(
                    AllowStdIo::new(File::open(&path)?),
                    target_description.length(),
                    0,
                    Some((alg, value.clone())),
                )?);

                Ok(reader)
            },
        )
    }
}

fn create_temp_file(path: &Path) -> Result<NamedTempFile> {
    // We want to atomically write the file to make sure clients can never see a partially written
    // file.  In order to do this, we'll write to a temporary file in the same directory as our
    // target, otherwise we risk writing the temporary file to one mountpoint, and then
    // non-atomically copying the file to another mountpoint.

    if let Some(parent) = path.parent() {
        DirBuilder::new().recursive(true).create(parent)?;
        Ok(NamedTempFile::new_in(parent)?)
    } else {
        Ok(NamedTempFile::new_in(".")?)
    }
}

/// A builder to create a repository accessible over HTTP.
pub struct HttpRepositoryBuilder<C, D>
where
    C: Connect + Sync + 'static,
    D: DataInterchange,
{
    url: Url,
    client: Client<C>,
    interchange: PhantomData<D>,
    user_agent: Option<String>,
    metadata_prefix: Option<Vec<String>>,
    min_bytes_per_second: u32,
}

impl<C, D> HttpRepositoryBuilder<C, D>
where
    C: Connect + Sync + 'static,
    D: DataInterchange,
{
    /// Create a new repository with the given `Url` and `Client`.
    pub fn new(url: Url, client: Client<C>) -> Self {
        HttpRepositoryBuilder {
            url: url,
            client: client,
            interchange: PhantomData,
            user_agent: None,
            metadata_prefix: None,
            min_bytes_per_second: 4096,
        }
    }

    /// Set the User-Agent prefix.
    ///
    /// Callers *should* include a custom User-Agent prefix to help maintainers of TUF repositories
    /// keep track of which client versions exist in the field.
    ///
    pub fn user_agent<T: Into<String>>(mut self, user_agent: T) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// The argument `metadata_prefix` is used provide an alternate path where metadata is stored on
    /// the repository. If `None`, this defaults to `/`. For example, if there is a TUF repository
    /// at `https://tuf.example.com/`, but all metadata is stored at `/meta/`, then passing the
    /// arg `Some("meta".into())` would cause `root.json` to be fetched from
    /// `https://tuf.example.com/meta/root.json`.
    pub fn metadata_prefix(mut self, metadata_prefix: Vec<String>) -> Self {
        self.metadata_prefix = Some(metadata_prefix);
        self
    }

    /// Set the minimum bytes per second for a read to be considered good.
    pub fn min_bytes_per_second(mut self, min: u32) -> Self {
        self.min_bytes_per_second = min;
        self
    }

    /// Build a `HttpRepository`.
    pub fn build(self) -> HttpRepository<C, D> {
        let user_agent = match self.user_agent {
            Some(user_agent) => user_agent,
            None => "rust-tuf".into(),
        };

        HttpRepository {
            url: self.url,
            client: self.client,
            interchange: self.interchange,
            user_agent: user_agent,
            metadata_prefix: self.metadata_prefix,
            min_bytes_per_second: self.min_bytes_per_second,
        }
    }
}

/// A repository accessible over HTTP.
pub struct HttpRepository<C, D>
where
    C: Connect + Sync + 'static,
    D: DataInterchange,
{
    url: Url,
    client: Client<C>,
    user_agent: String,
    metadata_prefix: Option<Vec<String>>,
    min_bytes_per_second: u32,
    interchange: PhantomData<D>,
}

impl<C, D> HttpRepository<C, D>
where
    C: Connect + Sync + 'static,
    D: DataInterchange,
{
    async fn get<'a>(
        &'a self,
        prefix: &'a Option<Vec<String>>,
        components: &'a [String],
    ) -> Result<Response<Body>> {
        let mut url = self.url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                Error::IllegalArgument(format!("URL was 'cannot-be-a-base': {:?}", self.url))
            })?;
            if let Some(ref prefix) = prefix {
                segments.extend(prefix);
            }
            segments.extend(components);
        }

        let uri: Uri = url.into_string().parse().map_err(|_| {
            Error::IllegalArgument(format!("URL was 'cannot-be-a-base': {:?}", self.url))
        })?;

        let req = Request::builder()
            .uri(uri)
            .header("User-Agent", &*self.user_agent)
            .body(Body::default())?;

        let resp = await!(self.client.request(req).compat())?;
        let status = resp.status();

        if !status.is_success() {
            if status == StatusCode::NOT_FOUND {
                Err(Error::NotFound)
            } else {
                Err(Error::Opaque(format!(
                    "Error getting {:?}: {:?}",
                    self.url, resp
                )))
            }
        } else {
            Ok(resp)
        }
    }
}

impl<C, D> Repository<D> for HttpRepository<C, D>
where
    C: Connect + Sync + 'static,
    D: DataInterchange,
{
    /// This always returns `Err` as storing over HTTP is not yet supported.
    fn store_metadata<'a, M>(
        &'a self,
        _: &'a MetadataPath,
        _: &'a MetadataVersion,
        _: &'a SignedMetadata<D, M>,
    ) -> TufFuture<'a, Result<()>>
    where
        M: Metadata + 'static,
    {
        Box::pin(
            async {
                Err(Error::Opaque(
                    "Http repo store metadata not implemented".to_string(),
                ))
            },
        )
    }

    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: &'a Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> TufFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static,
    {
        Box::pin(
            async move {
                Self::check::<M>(meta_path)?;

                let components = meta_path.components::<D>(&version);
                let resp = await!(self.get(&self.metadata_prefix, &components))?;

                let stream = resp
                    .into_body()
                    .compat()
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err));

                let mut reader = SafeReader::new(
                    stream.into_async_read(),
                    max_length.unwrap_or(::std::usize::MAX) as u64,
                    self.min_bytes_per_second,
                    hash_data,
                )?;

                let mut buf = Vec::new();
                await!(reader.read_to_end(&mut buf))?;

                Ok(D::from_slice(&buf)?)
            },
        )
    }

    /// This always returns `Err` as storing over HTTP is not yet supported.
    fn store_target<'a, R>(&'a self, _: R, _: &'a TargetPath) -> TufFuture<'a, Result<()>>
    where
        R: AsyncRead + 'a,
    {
        Box::pin(async { Err(Error::Opaque("Http repo store not implemented".to_string())) })
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> TufFuture<'a, Result<Box<dyn AsyncRead>>> {
        Box::pin(
            async move {
                let (alg, value) = crypto::hash_preference(target_description.hashes())?;
                let components = target_path.components();
                let resp = await!(self.get(&None, &components))?;

                let stream = resp
                    .into_body()
                    .compat()
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err));

                let reader = SafeReader::new(
                    stream.into_async_read(),
                    target_description.length(),
                    self.min_bytes_per_second,
                    Some((alg, value.clone())),
                )?;

                Ok(Box::new(reader) as Box<dyn AsyncRead>)
            },
        )
    }
}

type ArcHashMap<K, V> = Arc<RwLock<HashMap<K, V>>>;

/// An ephemeral repository contained solely in memory.
pub struct EphemeralRepository<D>
where
    D: DataInterchange,
{
    metadata: ArcHashMap<(MetadataPath, MetadataVersion), Vec<u8>>,
    targets: ArcHashMap<TargetPath, Vec<u8>>,
    interchange: PhantomData<D>,
}

impl<D> EphemeralRepository<D>
where
    D: DataInterchange,
{
    /// Create a new ephemercal repository.
    pub fn new() -> Self {
        EphemeralRepository {
            metadata: Arc::new(RwLock::new(HashMap::new())),
            targets: Arc::new(RwLock::new(HashMap::new())),
            interchange: PhantomData,
        }
    }
}

impl<D> Default for EphemeralRepository<D>
where
    D: DataInterchange,
{
    fn default() -> Self {
        EphemeralRepository::new()
    }
}

impl<D> Repository<D> for EphemeralRepository<D>
where
    D: DataInterchange,
{
    fn store_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        metadata: &'a SignedMetadata<D, M>,
    ) -> TufFuture<'a, Result<()>>
    where
        M: Metadata + 'static,
    {
        Box::pin(
            async move {
                Self::check::<M>(meta_path)?;
                let mut buf = Vec::new();
                D::to_writer(&mut buf, metadata)?;
                let mut metadata = self.metadata.write().unwrap();
                let _ = metadata.insert((meta_path.clone(), version.clone()), buf);
                Ok(())
            },
        )
    }

    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: &'a Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> TufFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static,
    {
        Box::pin(
            async move {
                Self::check::<M>(meta_path)?;

                let metadata = self.metadata.read().unwrap();
                match metadata.get(&(meta_path.clone(), version.clone())) {
                    Some(bytes) => {
                        let mut reader = SafeReader::new(
                            &**bytes,
                            max_length.unwrap_or(::std::usize::MAX) as u64,
                            0,
                            hash_data,
                        )?;

                        let mut buf = Vec::with_capacity(max_length.unwrap_or(0));
                        await!(reader.read_to_end(&mut buf))?;

                        D::from_slice(&buf)
                    }
                    None => Err(Error::NotFound),
                }
            },
        )
    }

    fn store_target<'a, R>(
        &'a self,
        mut read: R,
        target_path: &'a TargetPath,
    ) -> TufFuture<'a, Result<()>>
    where
        R: AsyncRead + 'a,
    {
        Box::pin(
            async move {
                println!("EphemeralRepository.store_target: {:?}", target_path);
                let mut buf = Vec::new();
                await!(read.read_to_end(&mut buf))?;
                let mut targets = self.targets.write().unwrap();
                let _ = targets.insert(target_path.clone(), buf);
                Ok(())
            },
        )
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> TufFuture<'a, Result<Box<dyn AsyncRead>>> {
        Box::pin(
            async move {
                let targets = self.targets.read().unwrap();
                match targets.get(target_path) {
                    Some(bytes) => {
                        let cur = Cursor::new(bytes.clone());
                        let (alg, value) = crypto::hash_preference(target_description.hashes())?;

                        let reader: Box<dyn AsyncRead> = Box::new(SafeReader::new(
                            cur,
                            target_description.length(),
                            0,
                            Some((alg, value.clone())),
                        )?);

                        Ok(reader)
                    }
                    None => Err(Error::NotFound),
                }
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::interchange::Json;
    use futures::executor::block_on;
    use futures::io::AsyncReadExt;
    use tempfile;

    #[test]
    fn ephemeral_repo_targets() {
        block_on(
            async {
                let repo = EphemeralRepository::<Json>::new();

                let data: &[u8] = b"like tears in the rain";
                let target_description =
                    TargetDescription::from_reader(data, &[HashAlgorithm::Sha256]).unwrap();
                let path = TargetPath::new("batty".into()).unwrap();
                await!(repo.store_target(data, &path)).unwrap();

                let mut read = await!(repo.fetch_target(&path, &target_description)).unwrap();
                let mut buf = Vec::new();
                await!(read.read_to_end(&mut buf)).unwrap();
                assert_eq!(buf.as_slice(), data);

                let bad_data: &[u8] = b"you're in a desert";
                await!(repo.store_target(bad_data, &path)).unwrap();
                let mut read = await!(repo.fetch_target(&path, &target_description)).unwrap();
                assert!(await!(read.read_to_end(&mut buf)).is_err());
            },
        )
    }

    #[test]
    fn file_system_repo_targets() {
        block_on(
            async {
                let temp_dir = tempfile::Builder::new()
                    .prefix("rust-tuf")
                    .tempdir()
                    .unwrap();
                let repo =
                    FileSystemRepository::<Json>::new(temp_dir.path().to_path_buf()).unwrap();

                // test that init worked
                assert!(temp_dir.path().join("metadata").exists());
                assert!(temp_dir.path().join("targets").exists());
                assert!(temp_dir.path().join("temp").exists());

                let data: &[u8] = b"like tears in the rain";
                let target_description =
                    TargetDescription::from_reader(data, &[HashAlgorithm::Sha256]).unwrap();
                let path = TargetPath::new("foo/bar/baz".into()).unwrap();
                await!(repo.store_target(data, &path)).unwrap();
                assert!(temp_dir
                    .path()
                    .join("targets")
                    .join("foo")
                    .join("bar")
                    .join("baz")
                    .exists());

                let mut buf = Vec::new();

                // Enclose `fetch_target` in a scope to make sure the file is closed.
                // This is needed for `tempfile` on Windows, which doesn't open the
                // files in a mode that allows the file to be opened multiple times.
                {
                    let mut read = await!(repo.fetch_target(&path, &target_description)).unwrap();
                    await!(read.read_to_end(&mut buf)).unwrap();
                    assert_eq!(buf.as_slice(), data);
                }

                let bad_data: &[u8] = b"you're in a desert";
                await!(repo.store_target(bad_data, &path)).unwrap();
                let mut read = await!(repo.fetch_target(&path, &target_description)).unwrap();
                assert!(await!(read.read_to_end(&mut buf)).is_err());
            },
        )
    }
}
