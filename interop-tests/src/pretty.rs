use {
    serde::de::DeserializeOwned,
    serde::ser::Serialize,
    tuf::{
        pouf::{Pouf, Pouf1},
        Result,
    },
};

/// Pretty JSON data pouf.
///
/// This is identical to [tuf::pouf::Pouf1] in all manners except for the `canonicalize` method.
/// Instead of writing the metadata in the canonical format, it first canonicalizes it, then pretty
/// prints the metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPretty;

impl Pouf for JsonPretty {
    type RawData = serde_json::Value;

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use tuf::pouf::Pouf;
    /// #
    /// assert_eq!(JsonPretty::extension(), "json");
    /// ```
    fn extension() -> &'static str {
        Pouf1::extension()
    }

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use serde_json::json;
    /// # use tuf::pouf::Pouf;
    /// #
    /// let json = json!({
    ///     "o": {
    ///         "a": [1, 2, 3],
    ///         "s": "string",
    ///         "n": 123,
    ///         "t": true,
    ///         "f": false,
    ///         "0": null,
    ///     },
    /// });
    ///
    /// let bytes = JsonPretty::canonicalize(&json).unwrap();
    ///
    /// assert_eq!(&String::from_utf8(bytes).unwrap(), r#"{
    ///   "o": {
    ///     "0": null,
    ///     "a": [
    ///       1,
    ///       2,
    ///       3
    ///     ],
    ///     "f": false,
    ///     "n": 123,
    ///     "s": "string",
    ///     "t": true
    ///   }
    /// }"#);
    /// ```
    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        let bytes = Pouf1::canonicalize(raw_data)?;
        Ok(serde_json::to_vec_pretty(&Self::from_slice::<
            Self::RawData,
        >(&bytes)?)?)
    }

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use serde_derive::Deserialize;
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # use tuf::pouf::Pouf;
    /// #
    /// #[derive(Deserialize, Debug, PartialEq)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let de: Thing = JsonPretty::deserialize(&jsn).unwrap();
    /// assert_eq!(de, thing);
    /// ```
    fn deserialize<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Pouf1::deserialize(raw_data)
    }

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use serde_derive::Serialize;
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # use tuf::pouf::Pouf;
    /// #
    /// #[derive(Serialize)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let se: serde_json::Value = JsonPretty::serialize(&thing).unwrap();
    /// assert_eq!(se, jsn);
    /// ```
    fn serialize<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Pouf1::serialize(data)
    }

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use std::collections::HashMap;
    /// # use tuf::pouf::Pouf;
    /// #
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let _: HashMap<String, String> = JsonPretty::from_slice(&jsn).unwrap();
    /// ```
    fn from_slice<T>(slice: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Pouf1::from_slice(slice)
    }
}
