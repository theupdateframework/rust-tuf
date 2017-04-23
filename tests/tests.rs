extern crate data_encoding;
extern crate tempdir;
extern crate tuf;
extern crate url;

use data_encoding::HEXLOWER;
use std::fs::{self, DirBuilder};
use tempdir::TempDir;
use tuf::{Tuf, Config};
use tuf::meta::{Key, KeyValue, KeyType};
use url::Url;

#[test]
fn init() {
    let tempdir = TempDir::new("rust-tuf").expect("couldn't make temp dir");

    for dir in vec!["metadata/latest", "metadata/archive", "targets"].iter() {
        DirBuilder::new()
            .recursive(true)
            .create(tempdir.path().join(dir))
            .expect(&format!("couldn't create path {}:", dir));
    }

    for file in vec!["root.json",
                     "targets.json",
                     "timestamp.json",
                     "snapshot.json"]
        .iter() {
        fs::copy(format!("./tests/tuf-test-vectors/vectors/001/{}", file),
                 tempdir.path().join("metadata").join("latest").join(file))
            .expect(&format!("copy failed: {}", file));
    }

    fs::copy("./tests/tuf-test-vectors/vectors/001/targets/file.txt",
             tempdir.path().join("targets").join("file.txt"))
            .expect(&format!("copy failed for target"));

    let root_keys = vec![Key {
                             typ: KeyType::Ed25519,
                             value: KeyValue(HEXLOWER.decode(
                                     include_str!("./tuf-test-vectors/vectors/001/keys/1.root-1.pub")
                                     .replace("\n", "")
                                     .as_ref())
                                     .expect("key value not hex")),
                         }];

    let config = Config::build()
        .url(Url::parse("http://localhost:8080").expect("bad url"))
        .local_path(tempdir.into_path())
        .finish()
        .expect("bad config");

    let t = Tuf::from_root_keys(root_keys, config).expect("failed to initialize TUF");

    assert_eq!(t.list_targets(), vec!["targets/file.txt".to_string()]);

    t.verify_target("targets/file.txt").expect("failed to verify target");
}
