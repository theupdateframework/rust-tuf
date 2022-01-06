//! Repository implementation backed by memory

use futures_io::AsyncRead;
use futures_util::future::{BoxFuture, FutureExt};
use futures_util::io::{AsyncReadExt, Cursor};
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{MetadataPath, MetadataVersion, TargetPath};
use crate::repository::{RepositoryProvider, RepositoryStorage};
use crate::Result;

/// An ephemeral repository contained solely in memory.
#[derive(Debug)]
pub struct EphemeralRepository<D> {
    metadata: HashMap<(MetadataPath, MetadataVersion), Box<[u8]>>,
    targets: HashMap<TargetPath, Box<[u8]>>,
    _interchange: PhantomData<D>,
}

impl<D> EphemeralRepository<D>
where
    D: DataInterchange,
{
    /// Create a new ephemeral repository.
    pub fn new() -> Self {
        Self {
            metadata: HashMap::new(),
            targets: HashMap::new(),
            _interchange: PhantomData,
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

impl<D> RepositoryProvider<D> for EphemeralRepository<D>
where
    D: DataInterchange + Sync,
{
    fn fetch_metadata<'a>(
        &'a self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin + 'a>>> {
        let bytes = match self.metadata.get(&(meta_path.clone(), version.clone())) {
            Some(bytes) => Ok(bytes),
            None => Err(Error::NotFound),
        };
        async move {
            let bytes = bytes?;
            let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(Cursor::new(bytes));
            Ok(reader)
        }
        .boxed()
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &TargetPath,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin + 'a>>> {
        let bytes = match self.targets.get(target_path) {
            Some(bytes) => Ok(bytes),
            None => Err(Error::NotFound),
        };
        async move {
            let bytes = bytes?;
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
        &'a mut self,
        meta_path: &MetadataPath,
        version: &MetadataVersion,
        metadata: &'a mut (dyn AsyncRead + Send + Unpin + 'a),
    ) -> BoxFuture<'a, Result<()>> {
        let meta_path = meta_path.clone();
        let version = version.clone();
        let self_metadata = &mut self.metadata;
        async move {
            let mut buf = Vec::new();
            metadata.read_to_end(&mut buf).await?;
            buf.shrink_to_fit();
            self_metadata.insert((meta_path, version), buf.into_boxed_slice());
            Ok(())
        }
        .boxed()
    }

    fn store_target<'a>(
        &'a mut self,
        target_path: &TargetPath,
        read: &'a mut (dyn AsyncRead + Send + Unpin + 'a),
    ) -> BoxFuture<'a, Result<()>> {
        let target_path = target_path.clone();
        let self_targets = &mut self.targets;
        async move {
            let mut buf = Vec::new();
            read.read_to_end(&mut buf).await?;
            buf.shrink_to_fit();
            self_targets.insert(target_path.clone(), buf.into_boxed_slice());
            Ok(())
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
            let mut repo = EphemeralRepository::<Json>::new();

            let data: &[u8] = b"like tears in the rain";
            let path = TargetPath::new("batty").unwrap();
            repo.store_target(&path, &mut &*data).await.unwrap();

            let mut read = repo.fetch_target(&path).await.unwrap();
            let mut buf = Vec::new();
            read.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), data);
            drop(read);

            // RepositoryProvider implementations do not guarantee data is not corrupt.
            let bad_data: &[u8] = b"you're in a desert";
            repo.store_target(&path, &mut &*bad_data).await.unwrap();
            let mut read = repo.fetch_target(&path).await.unwrap();
            buf.clear();
            read.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), bad_data);
        })
    }
}
