extern crate rustc_serialize;
extern crate tempdir;
extern crate tuf;
extern crate url;

use rustc_serialize::hex::FromHex;
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

    for file in vec!["metadata/latest/root.json",
                     "metadata/latest/targets.json",
                     "metadata/latest/timestamp.json",
                     "metadata/latest/snapshot.json",
                     "targets/big-file.txt",
                     "targets/hack-eryone.sh"]
        .iter() {
        fs::copy(format!("./tests/repo-1/{}", file),
                 tempdir.path().join(file))
            .expect(&format!("copy failed: {}", file));
    }

    let root_keys = vec![Key {
                             typ: KeyType::Ed25519,
                             value: KeyValue(include_str!("./repo-1/keys/root.pub")
                                 .from_hex()
                                 .expect("key value not hex")),
                         }];

    let config = Config::build()
        .url(Url::parse("http://localhost:8080").expect("bad url"))
        .local_path(tempdir.into_path())
        .finish()
        .expect("bad config");

    let t = Tuf::from_root_keys(root_keys, config).expect("failed to initialize TUF");

    assert_eq!(t.list_targets(),
               vec!["big-file.txt".to_string(), "hack-eryone.sh".to_string()]);

    t.verify_target("hack-eryone.sh").expect("failed to verify target");
}
