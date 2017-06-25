//! Components needed to verify TUF metadata and targets.

use std::marker::PhantomData;

use Result;
use crypto::KeyId;
use error::Error;
use interchange::DataInterchange;
use metadata::{SignedMetadata, RootMetadata, VerificationStatus};

/// Contains trusted TUF metadata and can be used to verify other metadata and targets.
#[derive(Debug)]
pub struct Tuf<D: DataInterchange> {
    root: RootMetadata,
    _interchange: PhantomData<D>,
}

impl<D: DataInterchange> Tuf<D> {

    /// Create a new `TUF` struct from a known set of pinned root keys that are used to verify the
    /// signed metadata.
    pub fn from_root_pinned<V>(
        mut signed_root: SignedMetadata<D, RootMetadata, V>,
        root_key_ids: &[KeyId],
    ) -> Result<Self>
    where
        V: VerificationStatus,
    {
        signed_root.signatures_mut().retain(|s| {
            root_key_ids.contains(s.key_id())
        });
        Self::from_root(signed_root)
    }

    /// Create a new `TUF` struct from a piece of metadata that is assumed to be trusted.
    ///
    /// *WARNING*: This is trust-on-first-use (TOFU) and offers weaker security guarantees than the
    /// related method `from_root_pinned`.
    pub fn from_root<V>(signed_root: SignedMetadata<D, RootMetadata, V>) -> Result<Self>
    where
        V: VerificationStatus,
    {
        let root = D::deserialize::<RootMetadata>(signed_root.unverified_signed())?;
        let _ = signed_root.verify(
            root.root().threshold(),
            root.root().key_ids(),
            root.keys(),
        )?;
        Ok(Tuf {
            root: root,
            _interchange: PhantomData,
        })
    }

    /// Verify and update the root metadata.
    pub fn update_root<V>(&mut self, signed_root: SignedMetadata<D, RootMetadata, V>) -> Result<()>
    where
        V: VerificationStatus,
    {
        let signed_root = signed_root.verify(
            self.root.root().threshold(),
            self.root.root().key_ids(),
            self.root.keys(),
        )?;

        let root = D::deserialize::<RootMetadata>(signed_root.unverified_signed())?;

        match root.version() {
            x if x == self.root.version() => {
                info!("Attempted to update root to new metadata with the same version. Refusing to update.")
            },
            x if x < self.root.version() => {
                return Err(Error::VerificationFailure(format!("Attempted to roll back root at version {} to {}.", self.root.version(), x)))
            }
            _ => (),
        }

        // TODO this is allowed to be expired, which is ok for updating the root chain, but not ok
        // for actually verifying anything else later

        let _ = signed_root.verify(
            root.root().threshold(),
            root.root().key_ids(),
            root.keys(),
        )?;

        self.root = root;
        Ok(())
    }
}
