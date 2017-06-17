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
//! extern crate url;
//! use tuf::{Tuf, Config, RemoteRepo};
//! use std::path::PathBuf;
//! use url::Url;
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
//!
//! ### An Integrated Example
//!
//! TUF is designed to be a drop in solution to verifying metadata and targets within an existing
//! update library.
//!
//! Consider the following sample application that
//!
//! ```no_run
//! extern crate url;
//! use std::path::PathBuf;
//! use url::Url;
//!
//! struct MyUpdater<'a> {
//!     remote_url: Url,
//!     local_cache: PathBuf,
//!     package_list: Vec<&'a str>,
//! }
//!
//! impl<'a> MyUpdater<'a> {
//!     fn new(remote_url: Url, local_cache: PathBuf) -> Self {
//!         MyUpdater {
//!             remote_url: remote_url,
//!             local_cache: local_cache,
//!             package_list: Vec::new(),
//!         }
//!     }
//!
//!     fn update_lists(&mut self) -> Result<(), String> {
//!         unimplemented!() // idk like some http + fs io probably
//!     }
//!
//!     fn fetch_package(&self, package: &str) -> Result<PathBuf, String> {
//!         if self.package_list.contains(&package) {
//!             unimplemented!() // moar http + fs io
//!         } else {
//!             return Err("Unknown package".to_string())
//!         }
//!     }
//! }
//!
//! fn main() {
//!     let url = Url::parse("http://crates.io/").unwrap();
//!     let cache = PathBuf::from("/var/lib/my-updater/");
//!     let mut updater = MyUpdater::new(url, cache);
//!     updater.update_lists().unwrap();
//!     let path_to_crate = updater.fetch_package("some_crate/0.1.0").unwrap();
//!     println!("Crate available at {}", path_to_crate.to_string_lossy());
//! }
//!
//! ```
//!
//! This simple updater (baring some migration shims), could be altered to use TUF as follows.
//!
//! ```no_run
//! extern crate tuf;
//! extern crate url;
//! use std::path::PathBuf;
//! use tuf::{Tuf, Config, RemoteRepo};
//! use url::Url;
//!
//! struct MyUpdater {
//!     tuf: Tuf,
//! }
//!
//! impl MyUpdater {
//!     fn new(remote_url: Url, local_cache: PathBuf) -> Result<Self, String> {
//!         let config = Config::build()
//!             .remote(RemoteRepo::Http(remote_url))
//!             .local_path(local_cache)
//!             .finish()
//!             .map_err(|e| format!("{:?}", e))?;
//!         let tuf = Tuf::new(config)
//!             .map_err(|e| format!("{:?}", e))?;
//!         Ok(MyUpdater {
//!             tuf: tuf,
//!         })
//!     }
//!
//!     fn update_lists(&mut self) -> Result<(), String> {
//!         self.tuf.update().map_err(|e| format!("{:?}", e))
//!     }
//!
//!     fn fetch_package(&self, package: &str) -> Result<PathBuf, String> {
//!         self.tuf.fetch_target(&format!("targets/{:?}/pkg.crate", package))
//!             .map_err(|e| format!("{:?}", e))
//!     }
//! }
//!
//! fn main() {
//!     let url = Url::parse("http://crates.io/").unwrap();
//!     let cache = PathBuf::from("/var/lib/my-updater/");
//!     let mut updater = MyUpdater::new(url, cache).unwrap();
//!     updater.update_lists().unwrap();
//!     let path_to_crate = updater.fetch_package("some_crate/0.1.0").unwrap();
//!     println!("Crate available at {}", path_to_crate.to_string_lossy());
//! }
//!
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
