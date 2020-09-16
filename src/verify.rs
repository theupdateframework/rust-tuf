use log::{debug, warn};
use serde_derive::Deserialize;
use std::collections::HashMap;

use crate::crypto::{KeyId, PublicKey, Signature};
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::metadata::{Metadata, RawSignedMetadata};
use crate::Result;

#[derive(Clone, Debug)]
pub struct Verified<T> {
    value: T,
}

impl<T> Verified<T> {
    fn new(value: T) -> Self {
        Verified { value }
    }
}

impl<T> std::ops::Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Verify this metadata.
///
/// ```
/// # use chrono::prelude::*;
/// # use tuf::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
/// # use tuf::interchange::Json;
/// # use tuf::metadata::{SnapshotMetadataBuilder, SignedMetadata};
///
/// # fn main() {
/// let key_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
/// let key_1 = PrivateKey::from_pkcs8(&key_1, SignatureScheme::Ed25519).unwrap();
///
/// let key_2: &[u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
/// let key_2 = PrivateKey::from_pkcs8(&key_2, SignatureScheme::Ed25519).unwrap();
///
/// let snapshot = SnapshotMetadataBuilder::new().build().unwrap();
/// let snapshot = SignedMetadata::<Json, _>::new(&snapshot, &key_1).unwrap();
///
/// assert!(snapshot.verify(
///     1,
///     vec![key_1.public()],
/// ).is_ok());
///
/// // fail with increased threshold
/// assert!(snapshot.verify(
///     2,
///     vec![key_1.public()],
/// ).is_err());
///
/// // fail when the keys aren't authorized
/// assert!(snapshot.verify(
///     1,
///     vec![key_2.public()],
/// ).is_err());
///
/// // fail when the keys don't exist
/// assert!(snapshot.verify(
///     1,
///     &[],
/// ).is_err());
/// # }
pub(crate) fn verify_signatures<'a, D, M, I>(
    raw_metadata: &RawSignedMetadata<D, M>,
    threshold: u32,
    authorized_keys: I,
) -> Result<Verified<M>>
where
    D: DataInterchange,
    M: Metadata,
    I: IntoIterator<Item = &'a PublicKey>,
{
    if threshold < 1 {
        return Err(Error::VerificationFailure(
            "Threshold must be strictly greater than zero".into(),
        ));
    }

    let authorized_keys = authorized_keys
        .into_iter()
        .map(|k| (k.key_id(), k))
        .collect::<HashMap<&KeyId, &PublicKey>>();

    // Extract the signatures and canonicalize the bytes.
    let (signatures, canonical_bytes) = {
        #[derive(Deserialize)]
        pub struct SignedMetadata<D: DataInterchange> {
            signatures: Vec<Signature>,
            signed: D::RawData,
        }

        let unverified: SignedMetadata<D> = D::from_slice(raw_metadata.as_bytes())?;

        if unverified.signatures.is_empty() {
            return Err(Error::VerificationFailure(
                "The metadata was not signed with any authorized keys.".into(),
            ));
        }

        let canonical_bytes = D::canonicalize(&unverified.signed)?;
        (unverified.signatures, canonical_bytes)
    };

    let mut signatures_needed = threshold;

    // Create a key_id->signature map to deduplicate the key_ids.
    let signatures = signatures
        .iter()
        .map(|sig| (sig.key_id(), sig))
        .collect::<HashMap<&KeyId, &Signature>>();

    for (key_id, sig) in signatures {
        match authorized_keys.get(key_id) {
            Some(ref pub_key) => match pub_key.verify(&canonical_bytes, sig) {
                Ok(()) => {
                    debug!("Good signature from key ID {:?}", pub_key.key_id());
                    signatures_needed -= 1;
                }
                Err(e) => {
                    warn!("Bad signature from key ID {:?}: {:?}", pub_key.key_id(), e);
                }
            },
            None => {
                warn!(
                    "Key ID {:?} was not found in the set of authorized keys.",
                    sig.key_id()
                );
            }
        }
        if signatures_needed == 0 {
            break;
        }
    }

    if signatures_needed > 0 {
        return Err(Error::VerificationFailure(format!(
            "Signature threshold not met: {}/{}",
            threshold - signatures_needed,
            threshold
        )));
    }

    // Everything looks good so deserialize the metadata.
    //
    // Note: Canonicalization (or any other transformation of data) could modify or filter out
    // information about the data. Therefore, while we've confirmed the canonical bytes are signed,
    // we shouldn't interpret this as if the raw bytes were signed. So we deserialize from the
    // `canonical_bytes`, rather than from `raw_meta.as_bytes()`.
    let verified_metadata = D::from_slice(&canonical_bytes)?;

    Ok(Verified::new(verified_metadata))
}
