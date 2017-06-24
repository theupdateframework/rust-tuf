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
    pub fn from_root_pinned(
        mut signed_root: SignedMetadata<D, R, RootMetadata>,
        root_key_ids: &[KeyId],
    ) -> Result<Self, Error> {
        signed_root.signatures_mut().retain(|s| {
            root_key_ids.contains(s.key_id())
        });
        let canonical_bytes = signed_root.signed().canonicalize()?;
        let root = signed_root.signed().deserialize::<RootMetadata>()?;

        let mut valid = 0;
        for sig in signed_root.signatures() {}

        panic!() // TODO
    }

    pub fn from_root(signed_root: SignedMetadata<D, R, RootMetadata>) -> Result<Self, Error> {
        panic!() // TODO
    }
}
