//! Repository implementation backed by memory

use futures_io::AsyncRead;
use futures_util::future::{BoxFuture, FutureExt};
use futures_util::io::{AsyncReadExt, Cursor};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::crypto::{HashAlgorithm, HashValue};
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{MetadataPath, MetadataVersion, TargetDescription, TargetPath};
use crate::repository::{RepositoryProvider, RepositoryStorage};
use crate::Result;

type ArcHashMap<K, V> = Arc<RwLock<HashMap<K, V>>>;

/// An ephemeral repository contained solely in memory.
#[derive(Debug)]
pub struct EphemeralRepository<D> {
    metadata: ArcHashMap<(MetadataPath, MetadataVersion), Arc<[u8]>>,
    targets: ArcHashMap<TargetPath, Arc<[u8]>>,
    _interchange: PhantomData<D>,
}

impl<D> EphemeralRepository<D>
where
    D: DataInterchange,
{
    /// Create a new ephemeral repository.
    pub fn new() -> Self {
        Self {
            metadata: Arc::new(RwLock::new(HashMap::new())),
            targets: Arc::new(RwLock::new(HashMap::new())),
            _interchange: PhantomData,
        }
    }

    /// Return a map for all the metadata in the repository.
    pub fn metadata(&self) -> ArcHashMap<(MetadataPath, MetadataVersion), Arc<[u8]>> {
        Arc::clone(&self.metadata)
    }

    /// Return a map for all the targets in the repository.
    pub fn targets(&self) -> ArcHashMap<TargetPath, Arc<[u8]>> {
        Arc::clone(&self.targets)
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

impl<D> RepositoryProvider<D> for EphemeralRepository<D>
where
    D: DataInterchange + Sync,
{
    fn fetch_metadata<'a>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        _max_length: Option<usize>,
        _hash_data: Option<(&'static HashAlgorithm, HashValue)>,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>> {
        async move {
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

            let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(Cursor::new(bytes));
            Ok(reader)
        }
        .boxed()
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &'a TargetPath,
        _target_description: &'a TargetDescription,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin>>> {
        async move {
            let bytes = match self.targets.read().get(target_path) {
                Some(bytes) => Arc::clone(&bytes),
                None => {
                    return Err(Error::NotFound);
                }
            };

            let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(Cursor::new(bytes));
            Ok(reader)
        }
        .boxed()
    }
}

impl<D> RepositoryStorage<D> for EphemeralRepository<D>
where
    D: DataInterchange + Sync,
{
    fn store_metadata<'a>(
        &'a self,
        meta_path: &'a MetadataPath,
        version: &'a MetadataVersion,
        metadata: &'a mut (dyn AsyncRead + Send + Unpin + 'a),
    ) -> BoxFuture<'a, Result<()>> {
        async move {
            let mut buf = Vec::new();
            metadata.read_to_end(&mut buf).await?;
            self.metadata
                .write()
                .insert((meta_path.clone(), version.clone()), Arc::from(buf));
            Ok(())
        }
        .boxed()
    }

    fn store_target<'a>(
        &'a self,
        read: &'a mut (dyn AsyncRead + Send + Unpin + 'a),
        target_path: &'a TargetPath,
    ) -> BoxFuture<'a, Result<()>> {
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
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::{
            crypto::{self, HashAlgorithm},
            interchange::Json,
            metadata::{MetadataPath, MetadataVersion, RawSignedMetadata, Role, RootMetadata},
        },
        futures_executor::block_on,
        maplit::hashmap,
    };

    #[test]
    fn ephemeral_repo_metadata() {
        block_on(async {
            let path = MetadataPath::from_role(&Role::Root);
            let version = MetadataVersion::None;
            let data: &[u8] = b"valid metadata";
            let _metadata = RawSignedMetadata::<Json, RootMetadata>::new(data.to_vec());
            let data_hash = crypto::calculate_hash(data, HashAlgorithm::Sha256);

            let repo = EphemeralRepository::<Json>::new();
            repo.store_metadata(&path, &version, &mut &*data)
                .await
                .unwrap();

            let mut read = repo
                .fetch_metadata(
                    &path,
                    &version,
                    None,
                    Some((&HashAlgorithm::Sha256, data_hash)),
                )
                .await
                .unwrap();

            let mut buf = Vec::new();
            read.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), data);

            assert_eq!(
                &*repo.metadata().read(),
                &hashmap! {
                    (path, version) => Arc::from(data.to_vec().into_boxed_slice()),
                }
            );
        })
    }

    #[test]
    fn ephemeral_repo_targets() {
        block_on(async {
            let repo = EphemeralRepository::<Json>::new();

            let data: &[u8] = b"like tears in the rain";
            let target_description =
                TargetDescription::from_reader(data, &[HashAlgorithm::Sha256]).unwrap();
            let path = TargetPath::new("batty".into()).unwrap();
            repo.store_target(&mut &*data, &path).await.unwrap();

            let mut read = repo.fetch_target(&path, &target_description).await.unwrap();
            let mut buf = Vec::new();
            read.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), data);

            // RepositoryProvider implementations do not guarantee data is not corrupt.
            let bad_path = TargetPath::new("bad".into()).unwrap();
            let bad_data: &[u8] = b"you're in a desert";
            repo.store_target(&mut &*bad_data, &bad_path).await.unwrap();

            let mut read = repo
                .fetch_target(&bad_path, &target_description)
                .await
                .unwrap();
            buf.clear();
            read.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), bad_data);

            assert_eq!(
                &*repo.targets().read(),
                &hashmap! {
                    path => Arc::from(data.to_vec().into_boxed_slice()),
                    bad_path => Arc::from(bad_data.to_vec().into_boxed_slice()),
                }
            );
        })
    }
}
