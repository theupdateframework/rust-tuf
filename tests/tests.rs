extern crate tempdir;
extern crate tuf;
extern crate url;

use std::fs;
use tempdir::TempDir;
use tuf::{Tuf, Config};
use url::Url;

#[test]
fn init() {
    let tempdir = TempDir::new("rust-tuf").expect("couldn't make temp dir");

    for file in vec!["root", "targets", "timestamp", "snapshot"].iter() {
        fs::copy(format!("./tests/repo-1/meta/{}.json", file),
                 tempdir.path().join(format!("{}.json", file)))
            .expect("copy failed");
    }

    let config = Config::build()
        .url(Url::parse("http://localhost:8080").expect("bad url"))
        .local_path(tempdir.into_path())
        .finish()
        .expect("bad config");
    let _ = Tuf::new(config).expect("failed to initialize TUF");
}
