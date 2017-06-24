//! Structs and functions for interacting with TUF repositories.
use std::marker::PhantomData;

use error::Error;
use metadata::{SignedMetadata, RootMetadata, KeyId};
use metadata::interchange::{RawData, DataInterchange};


#[derive(Debug)]
pub struct Tuf<D: DataInterchange, R: RawData<D>> {
    root: RootMetadata,
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
        Self::from_root(signed_root)
    }

    pub fn from_root(signed_root: SignedMetadata<D, R, RootMetadata>) -> Result<Self, Error> {
        if signed_root.signatures().len() < 1 {
            return Err(Error::VerificationFailure(
                    "The root metadata was not signed with any authorized keys.".into()))
        }

        let canonical_bytes = signed_root.signed().canonicalize()?;
        let root = signed_root.signed().deserialize::<RootMetadata>()?;

        let mut signatures_needed = root.root().threshold();
        if signatures_needed < 1 {
            return Err(Error::VerificationFailure("Threshold must be strictly greater than zero".into()))
        }

        for sig in signed_root.signatures() {
            if !root.root().key_ids().contains(sig.key_id()) {
                warn!("Key ID {:?} is not authorized to sign root metadata.", sig.key_id());
                continue
            }

            match root.keys().get(sig.key_id()) {
                Some(ref pub_key) => {
                    match pub_key.verify(sig.scheme(), &canonical_bytes, sig.signature()) {
                        Ok(()) => {
                            debug!("Good signature from key ID {:?}", pub_key.key_id());
                            signatures_needed -= 1;    
                        },
                        Err(e) => {
                            warn!("Bad signature from key ID {:?}", pub_key.key_id());   
                        },
                    }
                },
                None => {
                    warn!("Key ID {:?} was not found in the set of available keys.", sig.key_id());
                }
            }
            if signatures_needed == 0 {
                break
            }
        }

        Ok(Tuf {
            root: root,
            _raw_data: PhantomData,
            _interchange: PhantomData,
        })
    }
}
