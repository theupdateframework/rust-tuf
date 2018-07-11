//! Structures and functions to aid in various TUF data interchange formats.

mod cjson;

use json;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::fmt::Debug;
use std::io::{Read, Write};

use Result;
use error::Error;

/// The format used for data interchange, serialization, and deserialization.
pub trait DataInterchange: Debug + PartialEq + Clone {
    /// The type of data that is contained in the `signed` portion of metadata.
    type RawData: Serialize + DeserializeOwned + Clone + PartialEq;

    /// The data interchange's extension.
    fn extension() -> &'static str;

    /// A function that canonicalizes data to allow for deterministic signatures.
    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>>;

    /// Deserialize from `RawData`.
    fn deserialize<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned;

    /// Serialize into `RawData`.
    fn serialize<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize;

    /// Write a struct to a stream.
    ///
    /// Note: This *MUST* write the bytes canonically for hashes to line up correctly in other
    /// areas of the library.
    fn to_writer<W, T: Sized>(writer: W, value: &T) -> Result<()>
    where
        W: Write,
        T: Serialize;

    /// Read a struct from a stream.
    fn from_reader<R, T>(rdr: R) -> Result<T>
    where
        R: Read,
        T: DeserializeOwned;
}

/// JSON data interchange.
///
/// # Schema
///
/// This doesn't use JSON Schema because that specification language is rage inducing. Here's
/// something else instead.
///
/// ## Common Entities
///
/// `NATURAL_NUMBER` is an integer in the range `[1, 2**32)`.
///
/// `EXPIRES` is an ISO-8601 date time in format `YYYY-MM-DD'T'hh:mm:ss'Z'`.
///
/// `KEY_ID` is the base64url encoded value of `sha256(spki(pub_key))`.
///
/// `PUB_KEY` is the following:
///
/// ```bash
/// {
///   "type": KEY_TYPE,
///   "scheme": SCHEME,
///   "value": PUBLIC
/// }
/// ```
///
/// `PUBLIC` is a base64url encoded `SubjectPublicKeyInfo` DER public key.
///
/// `KEY_TYPE` is a string (either `rsa` or `ed25519`).
///
/// `SCHEME` is a string (either `ed25519`, `rsassa-pss-sha256`, or `rsassa-pss-sha512`
///
/// `HASH_VALUE` is a base64url encoded hash value.
///
/// `SIG_VALUE` is a base64url encoded signature value.
///
/// `METADATA_DESCRIPTION` is the following:
///
/// ```bash
/// {
///   "version": NATURAL_NUMBER,
///   "size": NATURAL_NUMBER,
///   "hashes": {
///     HASH_ALGORITHM: HASH_VALUE
///     ...
///   }
/// }
/// ```
///
/// ## `SignedMetadata`
///
/// ```bash
/// {
///   "signatures": [SIGNATURE],
///   "signed": SIGNED
/// }
/// ```
///
/// `SIGNATURE` is:
///
/// ```bash
/// {
///   "key_id": KEY_ID,
///   "signature": SIG_VALUE
/// }
/// ```
///
/// `SIGNED` is one of:
///
/// - `RootMetadata`
/// - `SnapshotMetadata`
/// - `TargetsMetadata`
/// - `TimestampMetadata`
///
/// The the elements of `signatures` must have unique `key_id`s.
///
/// ## `RootMetadata`
///
/// ```bash
/// {
///   "type": "root",
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "keys": [PUB_KEY, ...]
///   "root": ROLE_DESCRIPTION,
///   "snapshot": ROLE_DESCRIPTION,
///   "targets": ROLE_DESCRIPTION,
///   "timestamp": ROLE_DESCRIPTION
/// }
/// ```
///
/// `ROLE_DESCRIPTION` is the following:
///
/// ```bash
/// {
///   "threshold": NATURAL_NUMBER,
///   "key_ids": [KEY_ID, ...]
/// }
/// ```
///
/// ## `SnapshotMetadata`
///
/// ```bash
/// {
///   "type": "snapshot",
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "meta": {
///     META_PATH: METADATA_DESCRIPTION
///   }
/// }
/// ```
///
/// `META_PATH` is a string.
///
///
/// ## `TargetsMetadata`
///
/// ```bash
/// {
///   "type": "timestamp",
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "targets": {
///     TARGET_PATH: TARGET_DESCRIPTION
///     ...
///   },
///   "delegations": DELEGATIONS
/// }
/// ```
///
/// `DELEGATIONS` is optional and is described by the following:
///
/// ```bash
/// {
///   "keys": [PUB_KEY, ...]
///   "roles": {
///     ROLE: DELEGATION,
///     ...
///   }
/// }
/// ```
///
/// `DELEGATION` is:
///
/// ```bash
/// {
///   "name": ROLE,
///   "threshold": NATURAL_NUMBER,
///   "terminating": BOOLEAN,
///   "key_ids": [KEY_ID, ...],
///   "paths": [PATH, ...]
/// }
/// ```
///
/// `ROLE` is a string,
///
/// `PATH` is a string.
///
/// ## `TimestampMetadata`
///
/// ```bash
/// {
///   "type": "timestamp",
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "snapshot": METADATA_DESCRIPTION
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Json {}
impl DataInterchange for Json {
    type RawData = json::Value;

    /// ```
    /// # use tuf::interchange::{DataInterchange, Json};
    /// assert_eq!(Json::extension(), "json");
    /// ```
    fn extension() -> &'static str {
        "json"
    }

    /// ```
    /// # use tuf::interchange::{DataInterchange, Json};
    /// # use std::collections::HashMap;
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let raw = Json::from_reader(jsn).unwrap();
    /// let out = Json::canonicalize(&raw).unwrap();
    /// assert_eq!(out, br#"{"baz":"quux","foo":"bar"}"#);
    /// ```
    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        cjson::canonicalize(raw_data).map_err(Error::Opaque)
    }

    /// ```
    /// # #[macro_use]
    /// # extern crate serde_derive;
    /// # #[macro_use]
    /// # extern crate serde_json;
    /// # extern crate tuf;
    /// # use tuf::interchange::{DataInterchange, Json};
    /// # use std::collections::HashMap;
    /// #
    /// #[derive(Deserialize, Debug, PartialEq)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// # fn main() {
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let de: Thing = Json::deserialize(&jsn).unwrap();
    /// assert_eq!(de, thing);
    /// # }
    /// ```
    fn deserialize<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Ok(json::from_value(raw_data.clone())?)
    }

    /// ```
    /// # #[macro_use]
    /// # extern crate serde_derive;
    /// # #[macro_use]
    /// # extern crate serde_json;
    /// # extern crate tuf;
    /// # use tuf::interchange::{DataInterchange, Json};
    /// # use std::collections::HashMap;
    /// #
    /// #[derive(Serialize)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// # fn main() {
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let se: serde_json::Value = Json::serialize(&thing).unwrap();
    /// assert_eq!(se, jsn);
    /// # }
    /// ```
    fn serialize<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Ok(json::to_value(data)?)
    }

    /// ```
    /// # use tuf::interchange::{DataInterchange, Json};
    /// let arr = vec![1, 2, 3];
    /// let mut buf = Vec::new();
    /// Json::to_writer(&mut buf, &arr).unwrap();
    /// assert!(&buf == b"[1, 2, 3]" || &buf == b"[1,2,3]");
    /// ```
    fn to_writer<W, T: Sized>(mut writer: W, value: &T) -> Result<()>
    where
        W: Write,
        T: Serialize,
    {
        let bytes = Self::canonicalize(&Self::serialize(value)?)?;
        writer.write_all(&bytes)?;
        Ok(())
    }

    /// ```
    /// # use tuf::interchange::{DataInterchange, Json};
    /// # use std::collections::HashMap;
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let _: HashMap<String, String> = Json::from_reader(jsn).unwrap();
    /// ```
    fn from_reader<R, T>(rdr: R) -> Result<T>
    where
        R: Read,
        T: DeserializeOwned,
    {
        Ok(json::from_reader(rdr)?)
    }
}
