//! This crate provides an API for talking to repositories that implement The Update Framework
//! (TUF). Currently only downloading and verification of metadata is possible, not creating new
//! metadata or storing targets.
//!
//! If you are unfamiliar with TUF, you should read up on via the [official
//! website](http://theupdateframework.github.io/). This crate aims to implement the entirety of
//! the specification as defined at the [head of the `develop`
//! branch](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt) in the
//! official TUF git repository.
//!
//! ## Examples
//!
//! ### A Standalone Example
//!
//! ```no_run
//! extern crate tuf;
//! extern crate hyper;
//! use hyper::Url;
//! use tuf::{Tuf, Config, RemoteRepo};
//! use std::path::PathBuf;
//!
//! fn main() {
//!     let config = Config::build()
//!         .remote(RemoteRepo::Http(Url::parse("http://localhost:8080/").unwrap()))
//!         .local_path(PathBuf::from("/var/lib/tuf"))
//!         .finish()
//!         .unwrap();
//!     let mut tuf = Tuf::new(config).unwrap();
//!     let path_to_crate = tuf.fetch_target("targets/some_crate/0.1.0/pkg.crate").unwrap();
//!     println!("Crate available at {}", path_to_crate.to_string_lossy());
//! }
//!
//! ```
//!
//! The `Tuf` struct is the central piece to using this crate. It handles downloading and verifying
//! of metadata as well as the storage of metadata and targets.

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
extern crate serde_json as json;
extern crate url;
extern crate untrusted;
extern crate uuid;
extern crate walkdir;

mod cjson;
pub mod error;
mod http;
mod metadata;
mod rsa;
pub mod tuf;
mod util;

pub use tuf::*;
pub use error::*;

/// Module containing the various metadata components used by TUF.
pub mod meta {
    pub use metadata::{Key, KeyValue, KeyType};
}
