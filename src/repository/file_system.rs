//! Repository implementation backed by a file system.

use futures_io::AsyncRead;
use futures_util::future::{BoxFuture, FutureExt};
use futures_util::io::{copy, AllowStdIo, AsyncReadExt};
use log::debug;
use std::fs::{DirBuilder, File};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::crypto::{self, HashAlgorithm, HashValue};
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{
    Metadata, MetadataPath, MetadataVersion, SignedMetadata, TargetDescription, TargetPath,
};
use crate::repository::Repository;
use crate::util::SafeReader;
use crate::Result;

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

#[cfg(test)]
mod test {
    use super::*;
    use crate::interchange::Json;
    use crate::metadata::{Role, RootMetadata};
    use futures_executor::block_on;
    use tempfile;

    #[test]
    fn file_system_repo_metadata_not_found_error() {
        block_on(async {
            let temp_dir = tempfile::Builder::new()
                .prefix("rust-tuf")
                .tempdir()
                .unwrap();
            let repo = FileSystemRepositoryBuilder::new(temp_dir.path())
                .build::<Json>()
                .unwrap();

            assert_eq!(
                repo.fetch_metadata::<RootMetadata>(
                    &MetadataPath::from_role(&Role::Root),
                    &MetadataVersion::None,
                    None,
                    None
                )
                .await,
                Err(Error::NotFound)
            );
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
