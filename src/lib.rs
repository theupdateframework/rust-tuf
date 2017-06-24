//! This crate provides an API for talking to repositories that implement The Update Framework
//! (TUF). Currently only downloading and verification of metadata is possible, not creating new
//! metadata or storing targets.
//!
//! If you are unfamiliar with TUF, you should read up on via the [official
//! website](http://theupdateframework.github.io/). This crate aims to implement the entirety of
//! the specification as defined at the [head of the `develop`
//! branch](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt) in the
//! official TUF git repository.

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
#[macro_use]
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

mod client;
mod metadata;
pub mod repository;
mod rsa;
pub mod tuf;
mod util;

pub use tuf::*;
pub use error::*;

/// Module containing the various metadata components used by TUF.
pub mod meta {}
