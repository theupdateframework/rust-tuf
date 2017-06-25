//! Components needed to verify TUF metadata and targets.

use std::marker::PhantomData;

use Result;
use crypto::KeyId;
use error::Error;
use interchange::DataInterchange;
use metadata::{SignedMetadata, RootMetadata, VerificationStatus, TimestampMetadata};

/// Contains trusted TUF metadata and can be used to verify other metadata and targets.
#[derive(Debug)]
pub struct Tuf<D: DataInterchange> {
    root: RootMetadata,
    timestamp: Option<TimestampMetadata>,
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
            timestamp: None,
            _interchange: PhantomData,
        })
    }

    /// An immutable reference to the root metadata.
    pub fn root(&self) -> &RootMetadata {
        &self.root
    }

    /// An immutable reference to the optinoal timestamp metadata.
    pub fn timestamp(&self) -> Option<&TimestampMetadata> {
        self.timestamp.as_ref()
    }

    /// Verify and update the root metadata.
    pub fn update_root<V>(
        &mut self,
        signed_root: SignedMetadata<D, RootMetadata, V>,
    ) -> Result<bool>
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
                info!(
                    "Attempted to update root to new metadata with the same version. \
                      Refusing to update."
                );
                return Ok(false);
            }
            x if x < self.root.version() => {
                return Err(Error::VerificationFailure(format!(
                    "Attempted to roll back root metadata at version {} to {}.",
                    self.root.version(),
                    x
                )))
            }
            _ => (),
        }

        let _ = signed_root.verify(
            root.root().threshold(),
            root.root().key_ids(),
            root.keys(),
        )?;

        self.root = root;
        Ok(true)
    }

    /// Verify and update the timestamp metadata.
    pub fn update_timestamp<V>(
        &mut self,
        signed_timestamp: SignedMetadata<D, TimestampMetadata, V>,
    ) -> Result<bool>
    where
        V: VerificationStatus,
    {
        let signed_timestamp = signed_timestamp.verify(
            self.root.timestamp().threshold(),
            self.root.timestamp().key_ids(),
            self.root.keys(),
        )?;

        let current_version = self.timestamp.as_ref().map(|t| t.version()).unwrap_or(0);
        let timestamp: TimestampMetadata = D::deserialize(&signed_timestamp.signed())?;

        if timestamp.expires() <= &Utc::now() {
            return Err(Error::ExpiredMetadata(Role::Timestamp));
        }

        if timestamp.version() < current_version {
            Err(Error::VerificationFailure(format!(
                "Attempted to roll back timestamp metdata at version {} to {}.",
                current_version,
                timestamp.version()
            )))
        } else if timestamp.version() == current_version {
            Ok(false)
        } else {
            Ok(true)
        }
    }
}
