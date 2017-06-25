use std::marker::PhantomData;

use Result;
use crypto::KeyId;
use interchange::DataInterchange;
use metadata::{SignedMetadata, RootMetadata, VerificationStatus};


#[derive(Debug)]
pub struct Tuf<D: DataInterchange> {
    root: RootMetadata,
    _interchange: PhantomData<D>,
}

impl<D: DataInterchange> Tuf<D> {
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
        let _ = signed_root.verify(
            root.root().threshold(),
            root.root().key_ids(),
            root.keys(),
        )?;
        self.root = root;
        Ok(())
    }
}
