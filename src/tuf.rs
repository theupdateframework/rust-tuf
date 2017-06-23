//! Structs and functions for interacting with TUF repositories.
use std::marker::PhantomData;

use error::Error;
use metadata::{SignedMetadata, RootMetadata, KeyId};
use metadata::interchange::{RawData, DataInterchange};


#[derive(Debug)]
pub struct Tuf<D: DataInterchange, R: RawData<D>> {
    _raw_data: PhantomData<R>,
    _interchange: PhantomData<D>,
}

impl<D: DataInterchange, R: RawData<D>> Tuf<D, R> {
    pub fn from_root_pinned(root: &SignedMetadata<D, R, RootMetadata>,
                            root_key_ids: &[KeyId])
                            -> Result<Self, Error> {
        panic!() // TODO
    }

    pub fn from_root(root: &SignedMetadata<D, R, RootMetadata>) -> Result<Self, Error> {
        panic!() // TODO
    }
}
