extern crate chrono;
extern crate data_encoding;
extern crate hyper;
extern crate itoa;
#[macro_use]
extern crate log;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json as json;
extern crate url;
extern crate untrusted;
extern crate uuid;

mod cjson;
mod metadata;
mod error;
mod tuf;
pub mod util;

pub use tuf::*;
pub use error::*;

/// Module containing the various metadata components used by TUF.
pub mod meta {
    pub use metadata::{Key, KeyValue, KeyType};
}
