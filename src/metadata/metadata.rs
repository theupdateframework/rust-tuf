use data_encoding::HEXLOWER;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::fmt::{self, Debug};
use std::marker::PhantomData;

use metadata::interchange::{RawData, DataInterchange};

#[derive(Debug)]
pub enum MetadataVersion {
    None,
    Number(u32),
    Hash(String),
}

impl MetadataVersion {
    pub fn prefix(&self) -> String {
        match self {
            &MetadataVersion::None => String::new(),
            &MetadataVersion::Number(ref x) => format!("{}.", x),
            &MetadataVersion::Hash(ref s) => format!("{}.", s),
        }
    }
}

pub trait Metadata: Debug + PartialEq + Serialize + DeserializeOwned {}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMetadata<D: DataInterchange, R: RawData<D>, M: Metadata> {
    signatures: Vec<u8>,
    signed: R,
    _interchage: PhantomData<D>,
    _metadata: PhantomData<M>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RootMetadata {}

impl Metadata for RootMetadata {}

#[derive(Debug)]
pub struct Signature {
    key_id: KeyId,
    method: SignatureScheme,
    sig: SignatureValue,
}

#[derive(PartialEq)]
pub struct KeyId(Vec<u8>);

impl Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        write!(f, "KeyId {{ \"{}\" }}", HEXLOWER.encode(&self.0))
    }
}

#[derive(Debug, PartialEq)]
pub enum SignatureScheme {
    Ed25519,
    RsaSsaPssSha256,
    RsaSsaPssSha512,
    Unsupported(String),
}

#[derive(PartialEq)]
pub struct SignatureValue(Vec<u8>);

impl Debug for SignatureValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        write!(f, "SignatureValue {{ \"{}\" }}", HEXLOWER.encode(&self.0))
    }
}
