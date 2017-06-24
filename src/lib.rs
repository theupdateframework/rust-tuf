// TODO #![deny(missing_docs)]

extern crate chrono;
extern crate data_encoding;
extern crate env_logger;
extern crate hyper;
extern crate itoa;
#[macro_use]
extern crate log;
extern crate pem;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate serde_json as json;
#[cfg(not(test))]
extern crate serde_json as json;
#[cfg(test)]
extern crate tempdir;
extern crate url;
extern crate untrusted;
extern crate uuid;
extern crate walkdir;

pub mod error;

/// Alias for `Result<T, Error>`.
pub type Result<T> = ::std::result::Result<T, Error>;

pub mod client;
pub mod crypto;
pub mod interchange;
pub mod metadata;
pub mod repository;
mod rsa;
mod shims;
pub mod tuf;
mod util;

pub use tuf::*;
pub use error::*;
