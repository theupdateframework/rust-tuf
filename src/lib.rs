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
//! use std::path::PathBuf;
//! use tuf::Tuf;
//! use tuf::crypto::KeyId;
//! use tuf::client::{Client, Config};
//! use tuf::metadata::{RootMetadata, Unverified, SignedMetadata, Role, MetadataPath,
//!     MetadataVersion};
//! use tuf::interchange::JsonDataInterchange;
//! use tuf::repository::{Repository, FileSystemRepository, HttpRepository};
//! use url::Url;
//!
//! static TRUSTED_ROOT_KEY_IDS: &'static [&str] = &[
//!     "diNfThTFm0PI8R-Bq7NztUIvZbZiaC_weJBgcqaHlWw=",
//!     "ar9AgoRsmeEcf6Ponta_1TZu1ds5uXbDemBig30O7ck=",
//!     "T5vfRrM1iHpgzGwAHe7MbJH_7r4chkOAphV3OPCCv0I=",
//! ];
//!
//! fn main() {
//!     let key_ids: Vec<KeyId> = TRUSTED_ROOT_KEY_IDS.iter()
//!         .map(|k| KeyId::from_string(k).unwrap())
//!         .collect();
//!
//!     let mut local = FileSystemRepository::new(PathBuf::from("~/.rustup"));
//!
//!     let mut remote = HttpRepository::new(
//!         Url::parse("https://static.rust-lang.org/").unwrap(),
//!         HttpClient::new(),
//!         Some("rustup/1.4.0".into()));
//!
//!     let config = Config::build().finish().unwrap();
//!
//!     // fetching this original root from the network is safe because
//!     // we are using trusted, pinned keys to verify it
//!     let root = remote.fetch_metadata(&Role::Root,
//!                                      &MetadataPath::from_role(&Role::Root),
//!                                      &MetadataVersion::None,
//!                                      config.max_root_size(),
//!                                      None).unwrap();
//!
//!     let tuf = Tuf::<JsonDataInterchange>::from_root_pinned(root, &key_ids).unwrap();
//!
//!     let mut client = Client::new(tuf, config, local, remote).unwrap();
//!     let _ = client.update_local().unwrap();
//!     let _ = client.update_remote().unwrap();
//! }
//! ```

#![deny(missing_docs)]

extern crate chrono;
extern crate data_encoding;
extern crate derp;
extern crate env_logger;
extern crate hyper;
extern crate itoa;
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

pub use tuf::*;
pub use error::*;
