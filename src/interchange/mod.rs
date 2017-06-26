//! Contains structures and functions to aid in various TUF data interchange formats.

mod cjson;

use json;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::fmt::Debug;
use std::io::{Read, Write};

use Result;
use error::Error;

/// The format used for data interchange, serialization, and deserialization.
pub trait DataInterchange: Debug {
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
#[derive(Debug)]
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

    /// ```
    /// use tuf::interchange::{DataInterchange, JsonDataInterchange};
    /// use std::collections::HashMap;
    ///
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let raw = JsonDataInterchange::from_reader(jsn).unwrap();
    /// let out = JsonDataInterchange::canonicalize(&raw).unwrap();
    /// assert_eq!(out, br#"{"baz":"quux","foo":"bar"}"#);
    /// ```
    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        cjson::canonicalize(raw_data).map_err(|e| Error::Opaque(e))
    }

    /// ```
    /// use tuf::interchange::{DataInterchange, JsonDataInterchange};
    /// use std::collections::HashMap;
    /// 
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let raw = JsonDataInterchange::from_reader(jsn).unwrap();
    /// let mut map = HashMap::new();
    /// let _ = map.insert("foo".to_string(), "bar".to_string());
    /// let _ = map.insert("baz".to_string(), "quux".to_string());
    /// let de: HashMap<String, String> = JsonDataInterchange::deserialize(&raw).unwrap();
    /// assert_eq!(de, map);
    /// ```
    fn deserialize<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Ok(json::from_value(raw_data.clone())?)
    }

    /// ```
    /// use tuf::interchange::{DataInterchange, JsonDataInterchange};
    /// use std::collections::HashMap;
    /// 
    /// let arr = vec![1, 2, 3];
    /// let raw = JsonDataInterchange::serialize(&arr).unwrap();
    /// assert!(raw.is_array());
    ///
    /// let mut map = HashMap::new();
    /// let _ = map.insert("abc", 123);
    /// let raw = JsonDataInterchange::serialize(&map).unwrap();
    /// assert!(raw.is_object());
    /// ```
    fn serialize<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Ok(json::to_value(data)?)
    }

    /// ```
    /// use tuf::interchange::{DataInterchange, JsonDataInterchange};
    ///
    /// let arr = vec![1, 2, 3];
    /// let mut buf = Vec::new();
    /// JsonDataInterchange::to_writer(&mut buf, &arr).unwrap();
    /// assert!(&buf == b"[1, 2, 3]" || &buf == b"[1,2,3]");
    /// ```
    fn to_writer<W, T: ?Sized>(writer: W, value: &T) -> Result<()>
    where
        W: Write,
        T: Serialize,
    {
        Ok(json::to_writer(writer, value)?)
    }

    /// ```
    /// use tuf::interchange::{DataInterchange, JsonDataInterchange};
    /// use std::collections::HashMap;
    ///
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let _: HashMap<String, String> = JsonDataInterchange::from_reader(jsn).unwrap();
    /// ```
    fn from_reader<R, T>(rdr: R) -> Result<T>
    where
        R: Read,
        T: DeserializeOwned,
    {
        Ok(json::from_reader(rdr)?)
    }
}
