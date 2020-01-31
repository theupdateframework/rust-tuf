//! Interfaces for interacting with different types of TUF repositories.

use crate::crypto::{HashAlgorithm, HashValue};
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{
    Metadata, MetadataPath, MetadataVersion, SignedMetadata, TargetDescription, TargetPath,
};
use crate::Result;
use futures_io::AsyncRead;
use futures_util::future::BoxFuture;

mod file_system;
pub use self::file_system::{FileSystemRepository, FileSystemRepositoryBuilder};

mod http;
pub use self::http::{HttpRepository, HttpRepositoryBuilder};

mod ephemeral;
pub use self::ephemeral::EphemeralRepository;

/// A readable TUF repository.
pub trait RepositoryProvider<D>
where
    D: DataInterchange + Sync,
{
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

    /// Fetch the given target.
    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>>;

    /// Perform a sanity check that `M`, `Role`, and `MetadataPath` all describe the same entity.
    fn check<M>(meta_path: &MetadataPath) -> Result<()>
    where
        M: Metadata,
    {
        check_metadata_path::<M>(meta_path)
    }
}

/// A writable TUF repository. Most implementors of this trait should also implement
/// `RepositoryProvider<D>`.
pub trait RepositoryStorage<D>
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

    /// Store the given target.
    fn store_target<'a, R>(
        &'a self,
        read: R,
        target_path: &'a TargetPath,
    ) -> BoxFuture<'a, Result<()>>
    where
        R: AsyncRead + Send + Unpin + 'a;

    /// Perform a sanity check that `M`, `Role`, and `MetadataPath` all describe the same entity.
    fn check<M>(meta_path: &MetadataPath) -> Result<()>
    where
        M: Metadata,
    {
        check_metadata_path::<M>(meta_path)
    }
}

/// Top-level trait that represents a TUF repository and contains all the ways it can be interacted
/// with.
pub trait Repository<D>: RepositoryProvider<D> + RepositoryStorage<D>
where
    D: DataInterchange + Sync,
{
    /// Perform a sanity check that `M`, `Role`, and `MetadataPath` all describe the same entity.
    fn check<M>(meta_path: &MetadataPath) -> Result<()>
    where
        M: Metadata,
    {
        check_metadata_path::<M>(meta_path)
    }
}

impl<T, D> Repository<D> for T
where
    D: DataInterchange + Sync,
    T: RepositoryProvider<D> + RepositoryStorage<D>,
{
}

fn check_metadata_path<M>(meta_path: &MetadataPath) -> Result<()>
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

impl<T, D> RepositoryProvider<D> for &T
where
    T: RepositoryProvider<D>,
    D: DataInterchange + Sync,
{
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

    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        target_description: &'a TargetDescription,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>> {
        (**self).fetch_target(target_path, target_description)
    }
}

impl<T, D> RepositoryStorage<D> for &T
where
    T: RepositoryStorage<D>,
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
}
