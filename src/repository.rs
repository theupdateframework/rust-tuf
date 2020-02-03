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
