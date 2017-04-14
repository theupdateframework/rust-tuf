extern crate tempdir;
extern crate tuf;
extern crate url;

use std::fs::{self, DirBuilder};
use tempdir::TempDir;
use tuf::{Tuf, Config};
use url::Url;

#[test]
fn init() {
    let tempdir = TempDir::new("rust-tuf").expect("couldn't make temp dir");

    for dir in vec!["meta", "targets"].iter() {
        DirBuilder::new()
            .recursive(true)
            .create(tempdir.path().join(dir))
            .expect(&format!("couldn't create path {}:", dir));
    }

    for file in vec!["meta/root.json",
                     "meta/targets.json",
                     "meta/timestamp.json",
                     "meta/snapshot.json",
                     "targets/hack-eryone.sh"]
        .iter() {
        fs::copy(format!("./tests/repo-1/{}", file),
                 tempdir.path().join(file))
            .expect(&format!("copy failed: {}", file));
    }

    let config = Config::build()
        .url(Url::parse("http://localhost:8080").expect("bad url"))
        .local_path(tempdir.into_path())
        .finish()
        .expect("bad config");
    let t = Tuf::new(config).expect("failed to initialize TUF");

    assert_eq!(t.list_targets(),
               vec!["big-file.txt".to_string(), "hack-eryone.sh".to_string()]);

    t.verify_target("hack-eryone.sh").expect("failed to verify target");
}
