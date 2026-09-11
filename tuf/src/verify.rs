//! The `verify` module performs signature verification.

use log::{debug, warn};
use serde::Deserialize;
use std::collections::HashMap;

use crate::crypto::{KeyId, PublicKey, Signature};
use crate::error::Error;
use crate::metadata::{Metadata, MetadataPath, MetadataThreshold, RawSignedMetadata};
use crate::pouf::Pouf;

/// `Verified` is a wrapper type that signifies the inner type has had it's signature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified<T> {
    value: T,
}

impl<T> Verified<T> {
    // Create a new `Verified` around some type. This must be kept private to this module in order
    // to guarantee the `V` can only be created through signature verification.
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
/// # use tuf::crypto::{Ed25519PrivateKey, PrivateKey, SignatureScheme, HashAlgorithm};
/// # use tuf::pouf::Pouf1;
/// # use tuf::metadata::{MetadataPath, MetadataThreshold, SnapshotMetadataBuilder, SignedMetadata};
/// # use tuf::verify::verify_signatures;
///
/// let key_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
/// let key_1 = Ed25519PrivateKey::from_pkcs8(&key_1).unwrap();
///
/// let key_2: &[u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
/// let key_2 = Ed25519PrivateKey::from_pkcs8(&key_2).unwrap();
///
/// let raw_snapshot = SnapshotMetadataBuilder::new()
///     .signed::<Pouf1>(&key_1)
///     .unwrap()
///     .to_raw()
///     .unwrap();
///
/// assert!(verify_signatures(
///     &MetadataPath::snapshot(),
///     &raw_snapshot,
///     MetadataThreshold::ONE,
///     vec![key_1.public()],
/// ).is_ok());
///
/// // fail with increased threshold
/// assert!(verify_signatures(
///     &MetadataPath::snapshot(),
///     &raw_snapshot,
///     MetadataThreshold::new(2.try_into().unwrap()),
///     vec![key_1.public()],
/// ).is_err());
///
/// // fail when the keys aren't authorized
/// assert!(verify_signatures(
///     &MetadataPath::snapshot(),
///     &raw_snapshot,
///     MetadataThreshold::ONE,
///     vec![key_2.public()],
/// ).is_err());
///
/// // fail when the keys don't exist
/// assert!(verify_signatures(
///     &MetadataPath::snapshot(),
///     &raw_snapshot,
///     MetadataThreshold::ONE,
///     &[],
/// ).is_err());
pub fn verify_signatures<'a, D, M, I>(
    role: &MetadataPath,
    raw_metadata: &RawSignedMetadata<D, M>,
    threshold: MetadataThreshold,
    authorized_keys: I,
) -> Result<Verified<M>, Error>
where
    D: Pouf,
    M: Metadata,
    I: IntoIterator<Item = &'a PublicKey>,
{
    let authorized_keys = authorized_keys
        .into_iter()
        .map(|k| (k.key_id(), k))
        .collect::<HashMap<&KeyId, &PublicKey>>();

    // Extract the signatures and canonicalize the bytes.
    let (signatures, canonical_bytes) = {
        #[derive(Deserialize)]
        pub struct SignedMetadata<D: Pouf> {
            signatures: Vec<Signature>,
            signed: D::RawData,
        }

        let unverified: SignedMetadata<D> = D::from_slice(raw_metadata.as_bytes())?;

        let canonical_bytes = D::canonicalize(&unverified.signed)?;
        (unverified.signatures, canonical_bytes)
    };

    let mut signatures_needed: u32 = threshold.get();

    /////////////////////////////////////////
    // TUF-1.0.36 §4.2.1 (https://theupdateframework.github.io/specification/v1.0.36/#file-formats-object-format)
    //
    //     [...] The keyid MUST be unique in the "signatures" array: multiple signatures with the
    //     same keyid are not allowed.
    let mut unique_sigs = HashMap::new();
    for sig in &signatures {
        if unique_sigs.insert(sig.key_id(), sig).is_some() {
            return Err(Error::MetadataSignaturesHasDuplicateKeyId {
                role: role.clone(),
                key_id: sig.key_id().clone(),
            });
        }
    }
    let signatures = unique_sigs;

    for (key_id, sig) in signatures {
        match authorized_keys.get(key_id) {
            Some(pub_key) => match pub_key.verify(role, &canonical_bytes, sig) {
                Ok(()) => {
                    debug!("Good signature from key ID {:?}", pub_key.key_id());
                    signatures_needed = signatures_needed.saturating_sub(1);
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
        return Err(Error::MetadataMissingSignatures {
            role: role.clone(),
            number_of_valid_signatures: threshold.get().saturating_sub(signatures_needed),
            threshold,
        });
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{Ed25519PrivateKey, PrivateKey};
    use crate::metadata::{MetadataPath, MetadataThreshold, RootMetadata, SignedMetadata};
    use crate::pouf::pouf1::Pouf1;
    use assert_matches::assert_matches;
    use serde_json::json;

    const ED25519_1_PK8: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");

    fn json_root_metadata() -> serde_json::Value {
        json!({
            "_type": "root",
            "spec_version": "1.0.0",
            "version": 1,
            "expires": "2017-01-01T00:00:00Z",
            "consistent_snapshot": false,
            "keys": {
                "12435b260b6172bd750aeb102f54a347c56b109e0524ab1f144593c07af66356": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "68d9ecb387371005a8eb8e60105305c34356a8fcd859d7fef3cc228bf2b2b3b2",
                    },
                },
                "3af6b427c05274532231760f39d81212fdf8ac1a9f8fddf12722623ccec02fec": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "1410ae3053aa70bbfa98428a879d64d3002a3578f7dfaaeb1cb0764e860f7e0b",
                    },
                },
                "b9c336828063cf4fe5348e9fe2d86827c7b3104a76b1f4484a56bbef1ef08cfb": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "166376c90a7f717d027056272f361c252fb050bed1a067ff2089a0302fbab73d",
                    },
                },
                "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "eb8ac26b5c9ef0279e3be3e82262a93bce16fe58ee422500d38caf461c65a3b6",
                    },
                }
            },
            "roles": {
                "root": {
                    "threshold": 1,
                    "keyids": ["e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554"],
                },
                "snapshot": {
                    "threshold": 1,
                    "keyids": ["12435b260b6172bd750aeb102f54a347c56b109e0524ab1f144593c07af66356"],
                },
                "targets": {
                    "threshold": 1,
                    "keyids": ["b9c336828063cf4fe5348e9fe2d86827c7b3104a76b1f4484a56bbef1ef08cfb"],
                },
                "timestamp": {
                    "threshold": 1,
                    "keyids": ["3af6b427c05274532231760f39d81212fdf8ac1a9f8fddf12722623ccec02fec"],
                },
            },
        })
    }

    #[test]
    fn verify_signatures_rejects_duplicate_key_ids() {
        let root_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
        let key_id = root_key.public().key_id().clone();

        let json = json!({
            "signatures": [{
                "keyid": key_id,
                "sig": "1f944e022d0b30c5a9ddc9c210026f396e18a17cc9a4ee92c339a8ee63357608dba8121847a825c3a5c84c1081435436bd784c8086c3103cdd1489e79cff2802"
            },
            {
                "keyid": key_id,
                "sig": "1f944e022d0b30c5a9ddc9c210026f396e18a17cc9a4ee92c339a8ee63357608dba8121847a825c3a5c84c1081435436bd784c8086c3103cdd1489e79cff2802"
            }],
            "signed": json_root_metadata()
        });

        let decoded: SignedMetadata<Pouf1, RootMetadata> = serde_json::from_value(json).unwrap();
        let raw_root = decoded.to_raw().unwrap();

        assert_matches!(
            verify_signatures(
                &MetadataPath::root(),
                &raw_root,
                MetadataThreshold::new(2.try_into().unwrap()),
                &[root_key.public().clone()],
            ),
            Err(Error::MetadataSignaturesHasDuplicateKeyId {
                role,
                key_id: dup_key_id,
            })
            if role == MetadataPath::root() && dup_key_id == key_id
        );

        assert_matches!(
            verify_signatures(
                &MetadataPath::root(),
                &raw_root,
                MetadataThreshold::ONE,
                &[root_key.public().clone()],
            ),
            Err(Error::MetadataSignaturesHasDuplicateKeyId {
                role,
                key_id: dup_key_id,
            })
            if role == MetadataPath::root() && dup_key_id == key_id
        );
    }
}
