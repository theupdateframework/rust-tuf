//! This crate provides an API for talking to repositories that implement The Update Framework
//! (TUF).
//!
//! If you are unfamiliar with TUF, you should read up on via the [official
//! website](http://theupdateframework.github.io/). This crate aims to implement the entirety of
//! the specification as defined at the [head of the `develop`
//! branch](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt) in the
//! official TUF git repository.
//!
//! # Example
//!
//! ```no_run
//! extern crate hyper;
//! extern crate tuf;
//! extern crate url;
//!
//! use hyper::client::Client as HttpClient;
//! use std::fs::File;
//! use std::path::PathBuf;
//! use tuf::Tuf;
//! use tuf::crypto::KeyId;
//! use tuf::client::{Client, Config};
//! use tuf::metadata::{RootMetadata, Unverified, SignedMetadata};
//! use tuf::interchange::{DataInterchange, JsonDataInterchange};
//! use tuf::repository::{Repository, FileSystemRepository, HttpRepository};
//! use url::Url;
//!
//! static TRUSTED_ROOT_KEY_IDS: &'static [&str] = &[
//!     "13d1cfd0bdc95c0404738cd8601453df23dd2d34aebf2bcea43064400872d643",
//!     "23cec6550d04ff73d0ccf60ad322e21011a2b4ad3e9170f3daa8437b63807c56",
//!     "85f6c314f168a8c3d92a57f2d9bb6ab495a4ac921f02d2e32befc7bc812bd904",
//! ];
//!
//! fn get_original_root() -> File { unimplemented!() }
//!
//! fn main() {
//!     let root: SignedMetadata<JsonDataInterchange, RootMetadata, Unverified> =
//!         JsonDataInterchange::from_reader(get_original_root()).unwrap();
//!
//!     let key_ids: Vec<KeyId> = TRUSTED_ROOT_KEY_IDS.iter()
//!         .map(|k| KeyId::from_string(k).unwrap())
//!         .collect();
//!
//!     let tuf = Tuf::<JsonDataInterchange>::from_root_pinned(root, &key_ids).unwrap();
//!
//!     let mut local = FileSystemRepository::new(PathBuf::from("~/.rustup"));
//!
//!     let mut remote = HttpRepository::new(
//!         Url::parse("https://static.rust-lang.org/").unwrap(),
//!         HttpClient::new(),
//!         Some("rustup/1.4.0".into()));
//!
//!     let config = Config::build().finish().unwrap();
//!     let mut client = Client::new(tuf, config, local, remote).unwrap();
//!     let _ = client.update_local().unwrap();
//!     let _ = client.update_remote().unwrap();
//! }
//! ```

#![deny(missing_docs)]

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
mod rsa;
mod shims;
pub mod tuf;

pub use tuf::*;
pub use error::*;
