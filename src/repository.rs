//! Interfaces for interacting with different types of TUF repositories.

use futures_io::AsyncRead;
use futures_util::compat::{Future01CompatExt, Stream01CompatExt};
use futures_util::future::{BoxFuture, FutureExt};
use futures_util::io::{copy, AllowStdIo, AsyncReadExt, Cursor};
use futures_util::stream::TryStreamExt;
use http::{Response, StatusCode, Uri};
use hyper::body::Body;
use hyper::client::connect::Connect;
use hyper::Client;
use hyper::Request;
use log::debug;
use parking_lot::RwLock;
use percent_encoding::utf8_percent_encode;
use std::collections::HashMap;
use std::fs::{DirBuilder, File};
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::{self, NamedTempFile};
use url::Url;

use crate::crypto::{self, HashAlgorithm, HashValue};
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{
    Metadata, MetadataPath, MetadataVersion, SignedMetadata, TargetDescription, TargetPath,
};
use crate::util::SafeReader;
use crate::Result;

/// Top-level trait that represents a TUF repository and contains all the ways it can be interacted
/// with.
pub trait Repository<D>
where
    D: DataInterchange + Sync,
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
    ) -> BoxFuture<'a, Result<()>>
    where
        M: Metadata + Sync + 'static;

    /// Fetch signed metadata.
    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> BoxFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static;

    /// Store the given target.
    fn store_target<'a, R>(
        &'a self,
        read: R,
        target_path: &'a TargetPath,
    ) -> BoxFuture<'a, Result<()>>
    where
        R: AsyncRead + Send + Unpin + 'a;

    /// Fetch the given target.
    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>>;

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

impl<T, D> Repository<D> for &T
where
    T: Repository<D>,
    D: DataInterchange + Sync,
{
    fn store_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        metadata: &'a SignedMetadata<D, M>,
    ) -> BoxFuture<'a, Result<()>>
    where
        M: Metadata + Sync + 'static,
    {
        (**self).store_metadata(meta_path, version, metadata)
    }

    /// Fetch signed metadata.
    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> BoxFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static,
    {
        (**self).fetch_metadata(meta_path, version, max_length, hash_data)
    }

    /// Store the given target.
    fn store_target<'a, R>(
        &'a self,
        read: R,
        target_path: &'a TargetPath,
    ) -> BoxFuture<'a, Result<()>>
    where
        R: AsyncRead + Send + Unpin + 'a,
    {
        (**self).store_target(read, target_path)
    }

    /// Fetch the given target.
    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>> {
        {
            (**self).fetch_target(target_path, target_description)
        }
    }
}

/// A builder to create a repository contained on the local file system.
pub struct FileSystemRepositoryBuilder {
    local_path: PathBuf,
    metadata_prefix: Option<PathBuf>,
    targets_prefix: Option<PathBuf>,
}

impl FileSystemRepositoryBuilder {
    /// Create a new repository with the given `local_path` prefix.
    pub fn new<P: Into<PathBuf>>(local_path: P) -> Self {
        FileSystemRepositoryBuilder {
            local_path: local_path.into(),
            metadata_prefix: None,
            targets_prefix: None,
        }
    }

    /// The argument `metadata_prefix` is used to provide an alternate path where metadata is
    /// stored on the repository. If `None`, this defaults to `/`. For example, if there is a TUF
    /// repository at `/usr/local/repo/`, but all metadata is stored at `/usr/local/repo/meta/`,
    /// then passing the arg `Some("meta".into())` would cause `root.json` to be fetched from
    /// `/usr/local/repo/meta/root.json`.
    pub fn metadata_prefix<P: Into<PathBuf>>(mut self, metadata_prefix: P) -> Self {
        self.metadata_prefix = Some(metadata_prefix.into());
        self
    }

    /// The argument `targets_prefix` is used to provide an alternate path where targets are
    /// stored on the repository. If `None`, this defaults to `/`. For example, if there is a TUF
    /// repository at `/usr/local/repo/`, but all targets are stored at `/usr/local/repo/targets/`,
    /// then passing the arg `Some("targets".into())` would cause `hello-world` to be fetched from
    /// `/usr/local/repo/targets/hello-world`.
    pub fn targets_prefix<P: Into<PathBuf>>(mut self, targets_prefix: P) -> Self {
        self.targets_prefix = Some(targets_prefix.into());
        self
    }

    /// Build a `FileSystemRepository`.
    pub fn build<D>(self) -> Result<FileSystemRepository<D>>
    where
        D: DataInterchange,
    {
        let metadata_path = if let Some(metadata_prefix) = self.metadata_prefix {
            self.local_path.join(metadata_prefix)
        } else {
            self.local_path.clone()
        };
        DirBuilder::new().recursive(true).create(&metadata_path)?;

        let targets_path = if let Some(targets_prefix) = self.targets_prefix {
            self.local_path.join(targets_prefix)
        } else {
            self.local_path.clone()
        };
        DirBuilder::new().recursive(true).create(&targets_path)?;

        Ok(FileSystemRepository {
            metadata_path,
            targets_path,
            interchange: PhantomData,
        })
    }
}

/// A repository contained on the local file system.
pub struct FileSystemRepository<D>
where
    D: DataInterchange,
{
    metadata_path: PathBuf,
    targets_path: PathBuf,
    interchange: PhantomData<D>,
}

impl<D> FileSystemRepository<D>
where
    D: DataInterchange,
{
    /// Create a new repository on the local file system.
    pub fn new(local_path: PathBuf) -> Result<Self> {
        FileSystemRepositoryBuilder::new(local_path)
            .metadata_prefix("metadata")
            .targets_prefix("targets")
            .build()
    }
}

impl<D> Repository<D> for FileSystemRepository<D>
where
    D: DataInterchange + Sync,
{
    fn store_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        metadata: &'a SignedMetadata<D, M>,
    ) -> BoxFuture<'a, Result<()>>
    where
        M: Metadata + Sync + 'static,
    {
        async move {
            Self::check::<M>(meta_path)?;

            let mut path = self.metadata_path.clone();
            path.extend(meta_path.components::<D>(version));

            if path.exists() {
                debug!("Metadata path exists. Overwriting: {:?}", path);
            }

            let mut temp_file = create_temp_file(&path)?;
            D::to_writer(&mut temp_file, metadata)?;
            temp_file.persist(&path)?;

            Ok(())
        }
        .boxed()
    }

    /// Fetch signed metadata.
    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> BoxFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static,
    {
        async move {
            Self::check::<M>(&meta_path)?;

            let mut path = self.metadata_path.clone();
            path.extend(meta_path.components::<D>(&version));

            let mut reader = SafeReader::new(
                AllowStdIo::new(File::open(&path)?),
                max_length.unwrap_or(::std::usize::MAX) as u64,
                0,
                hash_data,
            )?;

            let mut buf = Vec::with_capacity(max_length.unwrap_or(0));
            reader.read_to_end(&mut buf).await?;

            Ok(D::from_slice(&buf)?)
        }
        .boxed()
    }

    fn store_target<'a, R>(
        &'a self,
        read: R,
        target_path: &'a TargetPath,
    ) -> BoxFuture<'a, Result<()>>
    where
        R: AsyncRead + Send + Unpin + 'a,
    {
        async move {
            let mut path = self.targets_path.clone();
            path.extend(target_path.components());

            if path.exists() {
                debug!("Target path exists. Overwriting: {:?}", path);
            }

            let mut temp_file = AllowStdIo::new(create_temp_file(&path)?);
            copy(read, &mut temp_file).await?;
            temp_file.into_inner().persist(&path)?;

            Ok(())
        }
        .boxed()
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>> {
        async move {
            let mut path = self.targets_path.clone();
            path.extend(target_path.components());

            if !path.exists() {
                return Err(Error::NotFound);
            }

            let (alg, value) = crypto::hash_preference(target_description.hashes())?;

            let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(SafeReader::new(
                AllowStdIo::new(File::open(&path)?),
                target_description.length(),
                0,
                Some((alg, value.clone())),
            )?);

            Ok(reader)
        }
        .boxed()
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
    uri: Uri,
    client: Client<C>,
    interchange: PhantomData<D>,
    user_agent: Option<String>,
    metadata_prefix: Option<Vec<String>>,
    targets_prefix: Option<Vec<String>>,
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
            uri: url.to_string().parse::<Uri>().unwrap(), // This is dangerous, but will only exist for a short time as we migrate APIs.
            client: client,
            interchange: PhantomData,
            user_agent: None,
            metadata_prefix: None,
            targets_prefix: None,
            min_bytes_per_second: 4096,
        }
    }

    /// Create a new repository with the given `Url` and `Client`.
    pub fn new_with_uri(uri: Uri, client: Client<C>) -> Self {
        HttpRepositoryBuilder {
            uri: uri,
            client: client,
            interchange: PhantomData,
            user_agent: None,
            metadata_prefix: None,
            targets_prefix: None,
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

    /// The argument `metadata_prefix` is used to provide an alternate path where metadata is
    /// stored on the repository. If `None`, this defaults to `/`. For example, if there is a TUF
    /// repository at `https://tuf.example.com/`, but all metadata is stored at `/meta/`, then
    /// passing the arg `Some("meta".into())` would cause `root.json` to be fetched from
    /// `https://tuf.example.com/meta/root.json`.
    pub fn metadata_prefix(mut self, metadata_prefix: Vec<String>) -> Self {
        self.metadata_prefix = Some(metadata_prefix);
        self
    }

    /// The argument `targets_prefix` is used to provide an alternate path where targets is
    /// stored on the repository. If `None`, this defaults to `/`. For example, if there is a TUF
    /// repository at `https://tuf.example.com/`, but all targets are stored at `/targets/`, then
    /// passing the arg `Some("targets".into())` would cause `hello-world` to be fetched from
    /// `https://tuf.example.com/targets/hello-world`.
    pub fn targets_prefix(mut self, targets_prefix: Vec<String>) -> Self {
        self.targets_prefix = Some(targets_prefix);
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
            uri: self.uri,
            client: self.client,
            interchange: self.interchange,
            user_agent: user_agent,
            metadata_prefix: self.metadata_prefix,
            targets_prefix: self.targets_prefix,
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
    uri: Uri,
    client: Client<C>,
    user_agent: String,
    metadata_prefix: Option<Vec<String>>,
    targets_prefix: Option<Vec<String>>,
    min_bytes_per_second: u32,
    interchange: PhantomData<D>,
}

// Configuration for urlencoding URI path elements.
// From https://url.spec.whatwg.org/#path-percent-encode-set
const URLENCODE_FRAGMENT: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`');
const URLENCODE_PATH: &percent_encoding::AsciiSet =
    &URLENCODE_FRAGMENT.add(b'#').add(b'?').add(b'{').add(b'}');

fn extend_uri(uri: Uri, prefix: &Option<Vec<String>>, components: &[String]) -> Result<Uri> {
    let mut uri_parts = uri.into_parts();

    let (path, query) = match &uri_parts.path_and_query {
        Some(path_and_query) => (path_and_query.path(), path_and_query.query()),
        None => ("", None),
    };

    let mut modified_path = path.to_owned();
    if modified_path.ends_with("/") {
        modified_path.pop();
    }

    let mut path_split = modified_path
        .split("/")
        .map(String::from)
        .collect::<Vec<_>>();
    let mut new_path_elements: Vec<&str> = vec![];

    if let Some(ref prefix) = prefix {
        new_path_elements.extend(prefix.iter().map(String::as_str));
    }
    new_path_elements.extend(components.iter().map(String::as_str));

    // Urlencode new items to match behavior of PathSegmentsMut.extend from
    // https://docs.rs/url/2.1.0/url/struct.PathSegmentsMut.html
    let encoded_new_path_elements = new_path_elements
        .into_iter()
        .map(|path_segment| utf8_percent_encode(&path_segment, URLENCODE_PATH).collect());
    path_split.extend(encoded_new_path_elements);
    let constructed_path = path_split.join("/");

    uri_parts.path_and_query =
        match query {
            Some(query) => Some(format!("{}?{}", constructed_path, query).parse().map_err(
                |_| {
                    Error::IllegalArgument(format!(
                        "Invalid path and query: {:?}, {:?}",
                        constructed_path, query
                    ))
                },
            )?),
            None => Some(constructed_path.parse().map_err(|_| {
                Error::IllegalArgument(format!("Invalid URI path: {:?}", constructed_path))
            })?),
        };

    Ok(Uri::from_parts(uri_parts).map_err(|_| {
        Error::IllegalArgument(format!(
            "Invalid URI parts: {:?}, {:?}, {:?}",
            constructed_path, prefix, components
        ))
    })?)
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
        let base_uri = self.uri.clone();
        let uri = extend_uri(base_uri, prefix, components)?;

        let req = Request::builder()
            .uri(uri)
            .header("User-Agent", &*self.user_agent)
            .body(Body::default())?;

        let resp = self.client.request(req).compat().await?;
        let status = resp.status();

        if !status.is_success() {
            if status == StatusCode::NOT_FOUND {
                Err(Error::NotFound)
            } else {
                Err(Error::Opaque(format!(
                    "Error getting {:?}: {:?}",
                    self.uri, resp
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
    D: DataInterchange + Send + Sync,
{
    /// This always returns `Err` as storing over HTTP is not yet supported.
    fn store_metadata<'a, M>(
        &'a self,
        _: &'a MetadataPath,
        _: &'a MetadataVersion,
        _: &'a SignedMetadata<D, M>,
    ) -> BoxFuture<'a, Result<()>>
    where
        M: Metadata + 'static,
    {
        async {
            Err(Error::Opaque(
                "Http repo store metadata not implemented".to_string(),
            ))
        }
        .boxed()
    }

    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> BoxFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static,
    {
        async move {
            Self::check::<M>(meta_path)?;

            let components = meta_path.components::<D>(&version);
            let resp = self.get(&self.metadata_prefix, &components).await?;

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
            reader.read_to_end(&mut buf).await?;

            Ok(D::from_slice(&buf)?)
        }
        .boxed()
    }

    /// This always returns `Err` as storing over HTTP is not yet supported.
    fn store_target<'a, R>(&'a self, _: R, _: &'a TargetPath) -> BoxFuture<'a, Result<()>>
    where
        R: AsyncRead + 'a,
    {
        async { Err(Error::Opaque("Http repo store not implemented".to_string())) }.boxed()
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>> {
        async move {
            let (alg, value) = crypto::hash_preference(target_description.hashes())?;
            let components = target_path.components();
            let resp = self.get(&self.targets_prefix, &components).await?;

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

            Ok(Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>)
        }
        .boxed()
    }
}

type ArcHashMap<K, V> = Arc<RwLock<HashMap<K, V>>>;

/// An ephemeral repository contained solely in memory.
#[derive(Debug)]
pub struct EphemeralRepository<D>
where
    D: DataInterchange,
{
    metadata: ArcHashMap<(MetadataPath, MetadataVersion), Vec<u8>>,
    targets: ArcHashMap<TargetPath, Arc<Vec<u8>>>,
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
    D: DataInterchange + Sync,
{
    fn store_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        metadata: &'a SignedMetadata<D, M>,
    ) -> BoxFuture<'a, Result<()>>
    where
        M: Metadata + Sync + 'static,
    {
        async move {
            Self::check::<M>(meta_path)?;
            let mut buf = Vec::new();
            D::to_writer(&mut buf, metadata)?;
            self.metadata
                .write()
                .insert((meta_path.clone(), version.clone()), buf);
            Ok(())
        }
        .boxed()
    }

    fn fetch_metadata<'a, M>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        max_length: Option<usize>,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> BoxFuture<'a, Result<SignedMetadata<D, M>>>
    where
        M: Metadata + 'static,
    {
        async move {
            Self::check::<M>(meta_path)?;

            let bytes = match self
                .metadata
                .read()
                .get(&(meta_path.clone(), version.clone()))
            {
                Some(bytes) => bytes.clone(),
                None => {
                    return Err(Error::NotFound);
                }
            };

            let mut reader = SafeReader::new(
                &*bytes,
                max_length.unwrap_or(::std::usize::MAX) as u64,
                0,
                hash_data,
            )?;

            let mut buf = Vec::with_capacity(max_length.unwrap_or(0));
            reader.read_to_end(&mut buf).await?;

            D::from_slice(&buf)
        }
        .boxed()
    }

    fn store_target<'a, R>(
        &'a self,
        mut read: R,
        target_path: &'a TargetPath,
    ) -> BoxFuture<'a, Result<()>>
    where
        R: AsyncRead + Send + Unpin + 'a,
    {
        async move {
            let mut buf = Vec::new();
            read.read_to_end(&mut buf).await?;
            self.targets
                .write()
                .insert(target_path.clone(), Arc::new(buf));
            Ok(())
        }
        .boxed()
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>> {
        // Helper wrapper in order to get Arc<Vec<u8>> to be compatible with Cursor.
        struct Wrapper(Arc<Vec<u8>>);
        impl AsRef<[u8]> for Wrapper {
            fn as_ref(&self) -> &[u8] {
                &**self.0
            }
        }

        async move {
            let bytes = match self.targets.read().get(target_path) {
                Some(bytes) => bytes.clone(),
                None => {
                    return Err(Error::NotFound);
                }
            };

            let (alg, value) = crypto::hash_preference(target_description.hashes())?;

            let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(SafeReader::new(
                Cursor::new(Wrapper(bytes)),
                target_description.length(),
                0,
                Some((alg, value.clone())),
            )?);

            Ok(reader)
        }
        .boxed()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::interchange::Json;
    use futures_executor::block_on;
    use tempfile;

    // Old behavior of the `HttpRepository::get` extension
    // functionality
    fn http_repository_extend_using_url(
        base_url: Url,
        prefix: &Option<Vec<String>>,
        components: &[String],
    ) -> url::Url {
        let mut url = base_url.clone();
        {
            let mut segments = url.path_segments_mut().unwrap();
            if let Some(ref prefix) = prefix {
                segments.extend(prefix);
            }
            segments.extend(components);
        }
        return url;
    }

    #[test]
    fn http_repository_uri_construction() {
        let base_uri = "http://example.com/one";

        let prefix = Some(vec![String::from("prefix")]);
        let components = [
            String::from("components_one"),
            String::from("components_two"),
        ];

        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(uri, &prefix, &components).unwrap();

        let url =
            http_repository_extend_using_url(Url::parse(base_uri).unwrap(), &prefix, &components);

        assert_eq!(url.to_string(), extended_uri.to_string());
        assert_eq!(
            extended_uri.to_string(),
            "http://example.com/one/prefix/components_one/components_two"
        );
    }

    #[test]
    fn http_repository_uri_construction_encoded() {
        let base_uri = "http://example.com/one";

        let prefix = Some(vec![String::from("prefix")]);
        let components = [String::from("chars to encode#?")];
        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(uri, &prefix, &components)
            .expect("correctly generated a URI with a zone id");

        let url =
            http_repository_extend_using_url(Url::parse(base_uri).unwrap(), &prefix, &components);

        assert_eq!(url.to_string(), extended_uri.to_string());
        assert_eq!(
            extended_uri.to_string(),
            "http://example.com/one/prefix/chars%20to%20encode%23%3F"
        );
    }

    #[test]
    fn http_repository_uri_construction_no_components() {
        let base_uri = "http://example.com/one";

        let prefix = Some(vec![String::from("prefix")]);
        let components = [];

        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(uri, &prefix, &components).unwrap();

        let url =
            http_repository_extend_using_url(Url::parse(base_uri).unwrap(), &prefix, &components);

        assert_eq!(url.to_string(), extended_uri.to_string());
        assert_eq!(extended_uri.to_string(), "http://example.com/one/prefix");
    }

    #[test]
    fn http_repository_uri_construction_no_prefix() {
        let base_uri = "http://example.com/one";

        let prefix = None;
        let components = [
            String::from("components_one"),
            String::from("components_two"),
        ];

        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(uri, &prefix, &components).unwrap();

        let url =
            http_repository_extend_using_url(Url::parse(base_uri).unwrap(), &prefix, &components);

        assert_eq!(url.to_string(), extended_uri.to_string());
        assert_eq!(
            extended_uri.to_string(),
            "http://example.com/one/components_one/components_two"
        );
    }

    #[test]
    fn http_repository_uri_construction_with_query() {
        let base_uri = "http://example.com/one?test=1";

        let prefix = None;
        let components = [
            String::from("components_one"),
            String::from("components_two"),
        ];

        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(uri, &prefix, &components).unwrap();

        let url =
            http_repository_extend_using_url(Url::parse(base_uri).unwrap(), &prefix, &components);

        assert_eq!(url.to_string(), extended_uri.to_string());
        assert_eq!(
            extended_uri.to_string(),
            "http://example.com/one/components_one/components_two?test=1"
        );
    }

    #[test]
    fn http_repository_uri_construction_ipv6_zoneid() {
        let base_uri = "http://[aaaa::aaaa:aaaa:aaaa:1234%252]:80";

        let prefix = Some(vec![String::from("prefix")]);
        let components = [
            String::from("componenents_one"),
            String::from("components_two"),
        ];
        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(uri, &prefix, &components)
            .expect("correctly generated a URI with a zone id");
        assert_eq!(
            extended_uri.to_string(),
            "http://[aaaa::aaaa:aaaa:aaaa:1234%252]:80/prefix/componenents_one/components_two"
        );
    }

    #[test]
    fn ephemeral_repo_targets() {
        block_on(async {
            let repo = EphemeralRepository::<Json>::new();

            let data: &[u8] = b"like tears in the rain";
            let target_description =
                TargetDescription::from_reader(data, &[HashAlgorithm::Sha256]).unwrap();
            let path = TargetPath::new("batty".into()).unwrap();
            repo.store_target(data, &path).await.unwrap();

            let mut read = repo.fetch_target(&path, &target_description).await.unwrap();
            let mut buf = Vec::new();
            read.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), data);

            let bad_data: &[u8] = b"you're in a desert";
            repo.store_target(bad_data, &path).await.unwrap();
            let mut read = repo.fetch_target(&path, &target_description).await.unwrap();
            assert!(read.read_to_end(&mut buf).await.is_err());
        })
    }

    #[test]
    fn file_system_repo_targets() {
        block_on(async {
            let temp_dir = tempfile::Builder::new()
                .prefix("rust-tuf")
                .tempdir()
                .unwrap();
            let repo = FileSystemRepositoryBuilder::new(temp_dir.path().to_path_buf())
                .metadata_prefix("meta")
                .targets_prefix("targs")
                .build::<Json>()
                .unwrap();

            // test that init worked
            assert!(temp_dir.path().join("meta").exists());
            assert!(temp_dir.path().join("targs").exists());

            let data: &[u8] = b"like tears in the rain";
            let target_description =
                TargetDescription::from_reader(data, &[HashAlgorithm::Sha256]).unwrap();
            let path = TargetPath::new("foo/bar/baz".into()).unwrap();
            repo.store_target(data, &path).await.unwrap();
            assert!(temp_dir
                .path()
                .join("targs")
                .join("foo")
                .join("bar")
                .join("baz")
                .exists());

            let mut buf = Vec::new();

            // Enclose `fetch_target` in a scope to make sure the file is closed.
            // This is needed for `tempfile` on Windows, which doesn't open the
            // files in a mode that allows the file to be opened multiple times.
            {
                let mut read = repo.fetch_target(&path, &target_description).await.unwrap();
                read.read_to_end(&mut buf).await.unwrap();
                assert_eq!(buf.as_slice(), data);
            }

            let bad_data: &[u8] = b"you're in a desert";
            repo.store_target(bad_data, &path).await.unwrap();
            let mut read = repo.fetch_target(&path, &target_description).await.unwrap();
            assert!(read.read_to_end(&mut buf).await.is_err());
        })
    }
}
