mod cjson;

use json;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::io::{Read, Write};

use Result;
use error::Error;
use metadata::Metadata;

/// The format used for data interchange, serialization, and deserialization.
pub trait DataInterchange {
    type RawData: Serialize + DeserializeOwned;

    fn suffix() -> &'static str;

    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>>;

    fn deserialize<M: Metadata>(raw_data: &Self::RawData) -> Result<M>;

    fn serialize<M: Metadata>(metadata: &M) -> Result<Self::RawData>;

    fn to_writer<W, T: ?Sized>(writer: W, value: &T) -> Result<()>
    where
        W: Write,
        T: Serialize;

    fn from_reader<R, T>(rdr: R) -> Result<T>
    where
        R: Read,
        T: DeserializeOwned;
}

pub struct JsonDataInterchange {}
impl DataInterchange for JsonDataInterchange {
    type RawData = json::Value;

    fn suffix() -> &'static str {
        "json"
    }

    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        cjson::canonicalize(raw_data).map_err(|e| Error::Generic(e))
    }

    fn deserialize<M: Metadata>(raw_data: &Self::RawData) -> Result<M> {
        Ok(json::from_value(raw_data.clone())?)
    }

    fn serialize<M: Metadata>(metadata: &M) -> Result<Self::RawData> {
        Ok(json::to_value(metadata)?)
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
