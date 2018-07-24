//! Interfaces for interacting with different types of TUF repositories.

use bytes::Bytes;
use futures::{stream, Future, Stream};
use futures_fs::FsPool;
use http::Uri;
use hyper::body::Body;
use hyper::client::connect::Connect;
use hyper::client::ResponseFuture;
use hyper::Request;
use hyper::Client;
use std::collections::HashMap;
use std::fs::{self, DirBuilder, File};
use std::io::Write;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tempfile::NamedTempFile;

use crypto::{self, HashAlgorithm, HashValue};
use error::Error;
use interchange::DataInterchange;
use metadata::{
    Metadata, MetadataPath, MetadataVersion, SignedMetadata, TargetDescription, TargetPath,
};
use url::Url;
use util::{SafeStreamExt, future_ok, future_err, stream_err};
use {TufStream, Result, TufFuture};

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
    fn store_metadata<M>(
        &self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        metadata: &SignedMetadata<D, M>,
    ) -> TufFuture<()>
    where
        M: Metadata;

    /// Fetch signed metadata.
    fn fetch_metadata<M>(
        &self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        max_size: Option<usize>,
        min_bytes_per_second: u32,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> TufFuture<SignedMetadata<D, M>>
    where
        M: Metadata + 'static;

    /// Store the given target.
    fn store_target<S>(&self, stream: S, target_path: &TargetPath) -> TufFuture<()>
    where
        S: Stream<Item=Bytes, Error=Error> + 'static;

    /// Fetch the given target.
    fn fetch_target(
        &self,
        target_path: &TargetPath,
        target_description: &TargetDescription,
        min_bytes_per_second: u32,
    ) -> TufStream<Bytes>;

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
    pool: FsPool,
    local_path: PathBuf,
    interchange: PhantomData<D>,
}

impl<D> FileSystemRepository<D>
where
    D: DataInterchange + 'static,
{
    /// Create a new repository on the local file system.
    pub fn new(pool: FsPool, local_path: PathBuf) -> Result<Self> {
        for p in &["metadata", "targets", "temp"] {
            DirBuilder::new()
                .recursive(true)
                .create(local_path.join(p))?
        }

        Ok(FileSystemRepository {
            pool,
            local_path,
            interchange: PhantomData,
        })
    }
}

impl<D> Repository<D> for FileSystemRepository<D>
where
    D: DataInterchange + 'static,
{
    fn store_metadata<M>(
        &self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        metadata: &SignedMetadata<D, M>,
    ) -> TufFuture<()>
    where
        M: Metadata,
    {
        try_future!(Self::check::<M>(meta_path));

        let components = meta_path.components::<D>(version);

        let mut path = self.local_path.join("metadata");
        path.extend(&components);

        if path.exists() {
            debug!("Metadata path exists. Deleting: {:?}", path);
            try_future!(fs::remove_file(&path));
        }

        if components.len() > 1 {
            let mut path = self.local_path.clone();
            path.extend(&components[..(components.len() - 1)]);
            try_future!(DirBuilder::new().recursive(true).create(path));
        }

        let mut file = try_future!(File::create(&path));
        try_future!(D::to_writer(&mut file, metadata));

        future_ok(())
    }

    /// Fetch signed metadata.
    fn fetch_metadata<M>(
        &self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        max_size: Option<usize>,
        min_bytes_per_second: u32,
        hash_data: Option<(&HashAlgorithm, HashValue)>,
    ) -> TufFuture<SignedMetadata<D, M>>
    where
        M: Metadata + 'static,
    {
        try_future!(Self::check::<M>(meta_path));

        let mut path = self.local_path.join("metadata");
        path.extend(meta_path.components::<D>(&version));

        Box::new(
            try_future!(
                self.pool
                    .read(path, Default::default())
                    .map_err(Error::from)
                    .safe_stream(
                        max_size.unwrap_or(::std::usize::MAX) as u64,
                        min_bytes_per_second,
                        hash_data,
                    )
            )
            .concat2()
            .and_then(|bytes| D::from_reader(&bytes[..]))
        )
    }

    fn store_target<S>(&self, stream: S, target_path: &TargetPath) -> TufFuture<()>
    where
        S: Stream<Item=Bytes, Error=Error> + 'static,
    {
        let temp_file = try_future!(NamedTempFile::new_in(self.local_path.join("temp")));

        let local_path = self.local_path.clone();
        let components = target_path.components();

        Box::new(
            stream
                .fold(temp_file, |mut temp_file, bytes| -> Result<NamedTempFile> {
                    temp_file.write_all(&bytes)?;
                    Ok(temp_file)
                })
                .and_then(move |temp_file| {
                    let mut path = local_path.clone().join("targets");
                    if components.len() > 1 {
                        let mut path = path.clone();
                        path.extend(&components[..(components.len() - 1)]);
                        DirBuilder::new().recursive(true).create(path)?;
                    }
                    path.extend(components);
                    temp_file.persist(&path)?;
                    Ok(())
                })
        )
    }

    fn fetch_target(
        &self,
        target_path: &TargetPath,
        target_description: &TargetDescription,
        min_bytes_per_second: u32,
    ) -> TufStream<Bytes> {
        let mut path = self.local_path.join("targets");
        path.extend(target_path.components());

        if !path.exists() {
            return stream_err(Error::NotFound);
        }

        let (alg, value) = try_stream!(crypto::hash_preference(target_description.hashes()));

        Box::new(
            try_stream!(
                self.pool
                    .read(path, Default::default())
                    .map_err(Error::from)
                    .safe_stream(
                        target_description.size(),
                        min_bytes_per_second,
                        Some((alg, value.clone())),
                    )
            )
        )
    }
}

/// A repository accessible over HTTP.
pub struct HttpRepository<C, D>
where
    C: Connect + Sync + 'static,
    C::Transport: 'static,
    C::Future: 'static,
    D: DataInterchange,
{
    url: Url,
    client: Client<C>,
    user_agent: String,
    metadata_prefix: Option<Vec<String>>,
    interchange: PhantomData<D>,
}

impl<C, D> HttpRepository<C, D>
where
    C: Connect + Sync + 'static,
    C::Transport: 'static,
    C::Future: 'static,
    D: DataInterchange + 'static,
{
    /// Create a new repository with the given `Uri` and `Client`.
    ///
    /// Callers *should* include a custom User-Agent prefix to help maintainers of TUF repositories
    /// keep track of which client versions exist in the field.
    ///
    /// The argument `metadata_prefix` is used provide an alternate path where metadata is stored on
    /// the repository. If `None`, this defaults to `/`. For example, if there is a TUF repository
    /// at `https://tuf.example.com/`, but all metadata is stored at `/meta/`, then passing the
    /// arg `Some("meta".into())` would cause `root.json` to be fetched from
    /// `https://tuf.example.com/meta/root.json`.
    pub fn new(
        url: Url,
        client: Client<C>,
        user_agent_prefix: Option<String>,
        metadata_prefix: Option<Vec<String>>,
    ) -> Self {
        let user_agent = match user_agent_prefix {
            Some(ua) => format!("{} (rust-tuf/{})", ua, env!("CARGO_PKG_VERSION")),
            None => format!("rust-tuf/{}", env!("CARGO_PKG_VERSION")),
        };

        HttpRepository {
            url,
            client,
            user_agent,
            metadata_prefix,
            interchange: PhantomData,
        }
    }

    fn get(&self, prefix: &Option<Vec<String>>, components: &[String]) -> Result<ResponseFuture> {
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

        Ok(self.client.request(req))
    }
}

impl<C, D> Repository<D> for HttpRepository<C, D>
where
    C: Connect + Sync + 'static,
    C::Transport: 'static,
    C::Future: 'static,
    D: DataInterchange + 'static,
{
    /// This always returns `Err` as storing over HTTP is not yet supported.
    fn store_metadata<M>(
        &self,
        _: &MetadataPath,
        _: &MetadataVersion,
        _: &SignedMetadata<D, M>,
    ) -> TufFuture<()>
    where
        M: Metadata,
    {
        future_err(Error::Opaque("Http repo store metadata not implemented".to_string()))
    }

    fn fetch_metadata<M>(
        &self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        max_size: Option<usize>,
        min_bytes_per_second: u32,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> TufFuture<SignedMetadata<D, M>>
    where
        M: Metadata + 'static,
    {
        try_future!(Self::check::<M>(meta_path));

        let resp = try_future!(
            self.get(&self.metadata_prefix, &meta_path.components::<D>(&version))
        );

        let bytes = try_future!(
            resp
                .map(|resp| resp.into_body().map(|chunk| chunk.into_bytes()))
                .flatten_stream()
                .map_err(Error::from)
                .safe_stream(
                    max_size.unwrap_or(::std::usize::MAX) as u64,
                    min_bytes_per_second,
                    hash_data,
                )
        );

        Box::new(
            bytes
                .concat2()
                .and_then(|bytes| D::from_reader(&bytes[..]))
        )
    }

    /// This always returns `Err` as storing over HTTP is not yet supported.
    fn store_target<S>(&self, _: S, _: &TargetPath) -> TufFuture<()>
    where
        S: Stream<Item=Bytes, Error=Error> + 'static,
    {
        future_err(Error::Opaque("Http repo store not implemented".to_string()))
    }

    fn fetch_target(
        &self,
        target_path: &TargetPath,
        target_description: &TargetDescription,
        min_bytes_per_second: u32,
    ) -> TufStream<Bytes> {
        let (alg, value) = try_stream!(
            crypto::hash_preference(target_description.hashes())
        );

        let resp = try_stream!(
            self.get(&None, &target_path.components())
        );

        Box::new(
            try_stream!(resp
                .map(|resp| resp.into_body())
                .flatten_stream()
                .map_err(Error::from)
                .map(|chunk| chunk.into_bytes())
                .safe_stream(
                    target_description.size(),
                    min_bytes_per_second,
                    Some((alg, value.clone())),
                )
            )
        )
    }
}

/// An ephemeral repository contained solely in memory.
pub struct EphemeralRepository<D>
where
    D: DataInterchange + 'static,
{
    metadata: Arc<RwLock<HashMap<(MetadataPath, MetadataVersion), Bytes>>>,
    targets: Arc<RwLock<HashMap<TargetPath, Bytes>>>,
    interchange: PhantomData<D>,
}

impl<D> EphemeralRepository<D>
where
    D: DataInterchange + 'static,
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
    D: DataInterchange + 'static,
{
    fn default() -> Self {
        EphemeralRepository::new()
    }
}

impl<D> Repository<D> for EphemeralRepository<D>
where
    D: DataInterchange + 'static,
{
    fn store_metadata<M>(
        &self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        metadata: &SignedMetadata<D, M>,
    ) -> TufFuture<()>
    where
        M: Metadata,
    {
        try_future!(Self::check::<M>(meta_path));

        let mut buf = Vec::new();
        try_future!(D::to_writer(&mut buf, metadata));

        let mut metadata = self.metadata.write().unwrap();
        let _ = metadata.insert((meta_path.clone(), version.clone()), Bytes::from(buf));

        future_ok(())
    }

    fn fetch_metadata<M>(
        &self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        max_size: Option<usize>,
        min_bytes_per_second: u32,
        hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> TufFuture<SignedMetadata<D, M>>
    where
        M: Metadata + 'static,
    {
        try_future!(Self::check::<M>(meta_path));

        let bytes = {
            let metadata = self.metadata.read().expect("poisoned lock");

            if let Some(bytes) = metadata.get(&(meta_path.clone(), version.clone())) {
                bytes.clone()
            } else {
                return future_err(Error::NotFound);
            }
        };

        // FIXME: we probably only need to validate the hash once on insert instead of
        // every time we read it.
        let bytes = try_future!(
            stream::once(Ok(bytes))
                .safe_stream(
                    max_size.unwrap_or(::std::usize::MAX) as u64,
                    min_bytes_per_second,
                    hash_data,
                )
        );

        Box::new(
            bytes
                .concat2()
                .and_then(|bytes| D::from_reader(&bytes[..]))
        )
    }

    fn store_target<S>(&self, stream: S, target_path: &TargetPath) -> TufFuture<()>
    where
        S: Stream<Item=Bytes, Error=Error> + 'static,
    {
        let buf = Vec::new();
        let targets = self.targets.clone();
        let target_path = target_path.clone();

        Box::new(
            stream
                .fold(buf, |mut buf, bytes| -> Result<_> {
                    buf.extend(&bytes);
                    Ok(buf)
                })
                .and_then(move |buf| {
                    let mut targets = targets.write().unwrap();
                    let _ = targets.insert(target_path, Bytes::from(buf));
                    Ok(())
                })
        )
    }

    fn fetch_target(
        &self,
        target_path: &TargetPath,
        target_description: &TargetDescription,
        min_bytes_per_second: u32,
    ) -> TufStream<Bytes> {
        let (alg, value) = try_stream!(crypto::hash_preference(target_description.hashes()));

        let bytes = {
            let targets = self.targets.read().expect("poisoned lock");

            if let Some(bytes) = targets.get(target_path) {
                bytes.clone()
            } else {
                return stream_err(Error::NotFound);
            }
        };

        // FIXME: we probably only need to validate the hash once on insert instead of
        // every time we read it.
        let stream = try_stream!(
            stream::once(Ok(bytes)).safe_stream(
                target_description.size(),
                min_bytes_per_second,
                Some((alg, value.clone())),
            )
        );

        Box::new(stream)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use interchange::Json;
    use tempdir::TempDir;

    #[test]
    fn ephemeral_repo_targets() {
        let repo = EphemeralRepository::<Json>::new();

        let data: &[u8] = b"like tears in the rain";
        let target_description =
            TargetDescription::from_reader(data, &[HashAlgorithm::Sha256]).unwrap();
        let path = TargetPath::new("batty".into()).unwrap();
        repo.store_target(stream::once(Ok(Bytes::from_static(data))), &path)
            .wait()
            .unwrap();

        let buf = repo.fetch_target(&path, &target_description, 0)
            .concat2()
            .wait()
            .unwrap();
        assert_eq!(data, &buf);

        let bad_data: &[u8] = b"you're in a desert";
        repo.store_target(stream::once(Ok(Bytes::from_static(bad_data))), &path)
            .wait()
            .unwrap();
        let buf = repo.fetch_target(&path, &target_description, 0)
            .concat2()
            .wait();
        assert!(buf.is_err());
    }

    #[test]
    fn file_system_repo_targets() {
        let temp_dir = TempDir::new("rust-tuf").unwrap();
        let repo = FileSystemRepository::<Json>::new(
            FsPool::new(1),
            temp_dir.path().to_path_buf(),
        ).unwrap();

        // test that init worked
        assert!(temp_dir.path().join("metadata").exists());
        assert!(temp_dir.path().join("targets").exists());
        assert!(temp_dir.path().join("temp").exists());

        let data: &[u8] = b"like tears in the rain";
        let target_description =
            TargetDescription::from_reader(data, &[HashAlgorithm::Sha256]).unwrap();
        let path = TargetPath::new("foo/bar/baz".into()).unwrap();
        repo.store_target(stream::once(Ok(Bytes::from_static(data))), &path)
            .wait()
            .unwrap();
        assert!(
            temp_dir
                .path()
                .join("targets")
                .join("foo")
                .join("bar")
                .join("baz")
                .exists()
        );

        // Enclose `fetch_target` in a scope to make sure the file is closed.
        // This is needed for `tempfile` on Windows, which doesn't open the
        // files in a mode that allows the file to be opened multiple times.
        let buf = {
            repo.fetch_target(&path, &target_description, 0)
                .concat2()
                .wait()
                .unwrap()
        };
        assert_eq!(data, &buf);

        let bad_data: &[u8] = b"you're in a desert";
        repo.store_target(stream::once(Ok(Bytes::from_static(bad_data))), &path)
            .wait()
            .unwrap();
        let buf = repo.fetch_target(&path, &target_description, 0)
            .concat2()
            .wait();
        assert!(buf.is_err());
    }
}
