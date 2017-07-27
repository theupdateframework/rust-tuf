//! This crate provides an API for talking to repositories that implement The Update Framework
//! (TUF).
//!
//! If you are unfamiliar with TUF, you should read up on it via the [official
//! website](http://theupdateframework.github.io/). This crate aims to implement the entirety of
//! the specification as defined at the [head of the `develop`
//! branch](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt) in the
//! official TUF git repository.
//!
//! Additionally, the following two papers are valuable supplements in understanding how to
//! actually implement TUF for a community repository.
//!
//! - [The Diplomat Paper
//! (2016)](https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/kuppusamy)
//! - [The Mercury Paper
//! (2017)](https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy)
//!
//! Failure to read the spec and the above papers will likely lead to an implementation that does
//! not take advantage of all the security guarantees that TUF offers.
//!
//! # Interoperability
//!
//! It should be noted that historically the TUF spec defined exactly one metadata format and one
//! way of organizing metadata within a repository. Thus, all TUF implementation could perfectly
//! interoperate. The TUF spec has moved to describing *how a framework should behave* leaving many
//! of the detais up to the implementor. Therefore, there are **zero** guarantees that this library
//! will work with any other TUF implemenation. Should you want to access a TUF repository that
//! uses `rust-tuf` as its backend from another language, ASN.1 modules and metadata schemas are
//! provided that will allow you to interoperate with this library.

#![deny(missing_docs)]

extern crate chrono;
extern crate data_encoding;
extern crate derp;
extern crate hyper;
extern crate itoa;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[cfg(test)]
#[macro_use]
extern crate maplit;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;

#[cfg(not(test))]
extern crate serde_json as json;
#[cfg(test)]
#[macro_use]
extern crate serde_json as json;

#[cfg(test)]
extern crate tempdir;
extern crate tempfile;
extern crate url;
extern crate untrusted;
extern crate uuid;

pub mod error;

/// Alias for `Result<T, Error>`.
pub type Result<T> = ::std::result::Result<T, Error>;

pub mod client;
pub mod crypto;
pub mod interchange;
pub mod metadata;
pub mod repository;
mod shims;
pub mod tuf;
mod util;

pub use error::*;
pub use tuf::*;
pub use util::*;
