//! Contains structures and functions to aid in various TUF data interchange formats.

mod cjson;

use json;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::io::{Read, Write};

use Result;
use error::Error;

/// The format used for data interchange, serialization, and deserialization.
pub trait DataInterchange {
    /// The type of data that is contained in the `signed` portion of metadata.
    type RawData: Serialize + DeserializeOwned;

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
    fn to_writer<W, T: ?Sized>(writer: W, value: &T) -> Result<()>
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
pub struct JsonDataInterchange {}
impl DataInterchange for JsonDataInterchange {
    type RawData = json::Value;

    /// ```
    /// use tuf::interchange::{DataInterchange, JsonDataInterchange};
    ///
    /// assert_eq!(JsonDataInterchange::extension(), "json");
    /// ```
    fn extension() -> &'static str {
        "json"
    }

    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        cjson::canonicalize(raw_data).map_err(|e| Error::Opaque(e))
    }

    fn deserialize<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Ok(json::from_value(raw_data.clone())?)
    }

    fn serialize<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Ok(json::to_value(data)?)
    }

    fn to_writer<W, T: ?Sized>(writer: W, value: &T) -> Result<()>
    where
        W: Write,
        T: Serialize,
    {
        Ok(json::to_writer(writer, value)?)
    }

    fn from_reader<R, T>(rdr: R) -> Result<T>
    where
        R: Read,
        T: DeserializeOwned,
    {
        Ok(json::from_reader(rdr)?)
    }
}
