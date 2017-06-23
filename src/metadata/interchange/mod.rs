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
    fn suffix() -> &'static str;

    fn to_writer<W, T: ?Sized>(writer: W, value: &T) -> Result<()>
        where W: Write,
              T: Serialize;

    fn from_reader<R, T>(rdr: R) -> Result<T>
        where R: Read,
              T: DeserializeOwned;
}

pub struct JsonDataInterchange {}
impl DataInterchange for JsonDataInterchange {
    fn suffix() -> &'static str {
        "json"
    }

    fn to_writer<W, T: ?Sized>(writer: W, value: &T) -> Result<()>
        where W: Write,
              T: Serialize
    {
        Ok(json::to_writer(writer, value)?)
    }

    fn from_reader<R, T>(rdr: R) -> Result<T>
        where R: Read,
              T: DeserializeOwned
    {
        Ok(json::from_reader(rdr)?)
    }
}


pub trait RawData<D: DataInterchange>: Sized {
    fn canonicalize(&self) -> Result<Vec<u8>>;
    fn deserialize<M: Metadata>(&self) -> Result<M>;
    fn serialize<M: Metadata>(metadata: &M) -> Result<Self>;
}

pub struct JsonRawData {
    raw_json: json::Value,
}

impl RawData<JsonDataInterchange> for JsonRawData {
    fn canonicalize(&self) -> Result<Vec<u8>> {
        cjson::canonicalize(&self.raw_json).map_err(|e| Error::Generic(e))
    }

    fn deserialize<M: Metadata>(&self) -> Result<M> {
        Ok(json::from_value(self.raw_json.clone())?)
    }

    fn serialize<M: Metadata>(metadata: &M) -> Result<Self> {
        Ok(JsonRawData { raw_json: json::to_value(metadata)? })
    }
}
