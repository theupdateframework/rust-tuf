//! Repository implementation backed by memory

use futures_io::AsyncRead;
use futures_util::future::{BoxFuture, FutureExt};
use futures_util::io::{AsyncReadExt, Cursor};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::crypto::{self, HashAlgorithm, HashValue};
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{
    Metadata, MetadataPath, MetadataVersion, SignedMetadata, TargetDescription, TargetPath,
};
use crate::repository::Repository;
use crate::util::SafeAsyncRead;
use crate::Result;

type ArcHashMap<K, V> = Arc<RwLock<HashMap<K, V>>>;

/// An ephemeral repository contained solely in memory.
#[derive(Debug)]
pub struct EphemeralRepository<D>
where
    D: DataInterchange,
{
    metadata: ArcHashMap<(MetadataPath, MetadataVersion), Arc<[u8]>>,
    targets: ArcHashMap<TargetPath, Arc<[u8]>>,
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
                .insert((meta_path.clone(), version.clone()), Arc::from(buf));
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
                Some(bytes) => Arc::clone(&bytes),
                None => {
                    return Err(Error::NotFound);
                }
            };

            let mut reader = Cursor::new(bytes)
                .check_length_and_hash(max_length.unwrap_or(::std::usize::MAX) as u64, hash_data)?;

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
                .insert(target_path.clone(), Arc::from(buf));
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
            let bytes = match self.targets.read().get(target_path) {
                Some(bytes) => Arc::clone(&bytes),
                None => {
                    return Err(Error::NotFound);
                }
            };

            let (alg, value) = crypto::hash_preference(target_description.hashes())?;

            let reader: Box<dyn AsyncRead + Send + Unpin> =
                Box::new(Cursor::new(bytes).check_length_and_hash(
                    target_description.length(),
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
}
