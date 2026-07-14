//! HTTP repository support for TUF using Hyper.
//!
//! # Example
//!
//! ```no_run
//! use http::Uri;
//! use hyper_util::client::legacy::Client;
//! use hyper_util::rt::TokioExecutor;
//! use tuf::pouf::Pouf1;
//! use tuf_hyper::HttpRepositoryBuilder;
//!
//! let client = Client::builder(TokioExecutor::new()).build_http();
//! let repository = HttpRepositoryBuilder::<_, Pouf1>::new(
//!     Uri::from_static("https://example.com/tuf"),
//!     client,
//! )
//! .user_agent("tuf-client/1.0")
//! .build();
//! ```

#![deny(missing_docs)]
#![allow(clippy::collapsible_if, clippy::type_complexity)]

mod enforce_minimum_bitrate;
mod repository;

pub use crate::repository::{HttpRepository, HttpRepositoryBuilder};
