//! Test Interopability with other TUF Clients
//!
//! This tests how rust-tuf's compatibility with other TUF clients. Currently the only test is to
//! verify key rotation works correctly, but this will eventually be extended to cover other
//! scenarios.
//!
//! Each client should generate metadata that follows this scheme:
//!
//!     tests/interop/
//!     |- $client/
//!        |- consistent-snapshot-false/
//!           |- 0/
//!              |- repository/
//!                 |- targets/
//!                    |- $hash.0
//!                 |- root.json
//!                 |- timestamp.json
//!                 |- ...
//!           |- 1/
//!              |- repository/
//!                 |- targets/
//!                    |- $hash.0
//!                    |- $hash.1
//!           |- ...
//!        |- consistent-snapshot-true
//!           |- 0/
//!              |- ...
//!
//! Specifically, in each client directory, it has two broad categories - one to verify rust-tuf
//! works with `consistent_snapshot` being `false`, and one with `consistent_snapshot` being
//! `true`. Inside each directory is an ordered series of repositories. The test will initialize,
//! and then use each "step" directory as the remote server, to simulate the metadata transforming
//! over time. Finally, each repository should also contain a single target that corresponds to the
//! step name, that just contains the name of the step. This is used to verify that we can still
//! download targets at each step of the test.

use futures_executor::block_on;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tuf::client::{Client, Config};
use tuf::crypto::KeyId;
use tuf::interchange::Json;
use tuf::metadata::{
    MetadataPath, MetadataVersion, Role, RootMetadata, SignedMetadata, TargetPath,
};
use tuf::repository::{
    EphemeralRepository, FileSystemRepository, FileSystemRepositoryBuilder, Repository,
};
use tuf::Result;

#[test]
fn fuchsia_go_tuf_consistent_snapshot_false() {
    test_key_rotation(
        Path::new("tests")
            .join("interop")
            .join("fuchsia-go-tuf-5527fe")
            .join("consistent-snapshot-false"),
    );
}

#[test]
fn fuchsia_go_tuf_consistent_snapshot_true() {
    test_key_rotation(
        Path::new("tests")
            .join("interop")
            .join("fuchsia-go-tuf-5527fe")
            .join("consistent-snapshot-true"),
    );
}

#[test]
fn fuchsia_go_tuf_transition_m4_consistent_snapshot_false() {
    test_key_rotation(
        Path::new("tests")
            .join("interop")
            .join("fuchsia-go-tuf-transition-M4")
            .join("consistent-snapshot-false"),
    );
}

#[test]
fn fuchsia_go_tuf_transition_m4_consistent_snapshot_true() {
    test_key_rotation(
        Path::new("tests")
            .join("interop")
            .join("fuchsia-go-tuf-transition-M4")
            .join("consistent-snapshot-true"),
    )
}

fn test_key_rotation(dir: PathBuf) {
    block_on(async {
        let mut suite = TestKeyRotation::new(dir);
        suite.run_tests().await;
    })
}

/// TestKeyRotation is the main driver for running the key rotation tests.
struct TestKeyRotation {
    /// The paths to each test step directory.
    test_steps: Vec<PathBuf>,

    /// The local repository used to store the local metadata.
    local: EphemeralRepository<Json>,

    /// The targets we expect each step of the repository to contain. It will contain a target for
    /// each step we've processed, named for the first step it appeared in.
    expected_targets: BTreeMap<TargetPath, String>,
}

impl TestKeyRotation {
    fn new(test_dir: PathBuf) -> Self {
        let mut test_steps = Vec::new();

        for entry in test_dir.read_dir().unwrap() {
            let entry = entry.unwrap();

            if entry.file_type().unwrap().is_dir() {
                test_steps.push(entry.path());
            }
        }

        // Make sure the steps are in order, or else the expected_targets will be incorrect.
        test_steps.sort();

        TestKeyRotation {
            test_steps,
            local: EphemeralRepository::<Json>::new(),
            expected_targets: BTreeMap::new(),
        }
    }

    async fn run_tests(&mut self) {
        let mut init = true;
        let mut key_ids = Vec::new();

        for step_dir in self.test_steps.clone() {
            // Extract the keys from the first step.
            if init {
                init = false;
                key_ids = extract_keys(&step_dir).await;
            }

            self.run_test_step(&key_ids, step_dir).await;
        }
    }

    async fn run_test_step(&mut self, key_ids: &[KeyId], dir: PathBuf) {
        let remote = init_remote(&dir).unwrap();

        // Connect to the client with our initial keys.
        let mut client = Client::with_pinned_root_keyids(
            Config::default(),
            &MetadataVersion::Number(1),
            1,
            key_ids,
            &self.local,
            remote,
        )
        .await
        .expect("client to open");

        // Update our TUF metadata. The first time should report there is new metadata, the second
        // time should not.
        assert_eq!(client.update().await, Ok(true));
        assert_eq!(client.update().await, Ok(false));

        // Add the expected target to our target list.
        let file_name = dir.file_name().unwrap().to_str().unwrap().to_string();
        let target_path = TargetPath::new(file_name.clone()).unwrap();
        self.expected_targets.insert(target_path, file_name);

        // fetch all the targets and check they have the correct content
        for (target_path, expected) in self.expected_targets.iter() {
            let mut buf = Vec::new();
            assert_eq!(
                client.fetch_target_to_writer(&target_path, &mut buf).await,
                Ok(())
            );
            assert_eq!(&String::from_utf8(buf).unwrap(), expected);
        }
    }
}

/// Extract the initial key ids from the first step.
async fn extract_keys(dir: &Path) -> Vec<KeyId> {
    let remote = init_remote(dir).unwrap();

    let root_path = MetadataPath::from_role(&Role::Root);
    let metadata: SignedMetadata<_, RootMetadata> = remote
        .fetch_metadata(&root_path, &MetadataVersion::Number(1), None, None)
        .await
        .unwrap();

    metadata.as_ref().root().key_ids().iter().cloned().collect()
}

fn init_remote(dir: &Path) -> Result<FileSystemRepository<Json>> {
    FileSystemRepositoryBuilder::new(dir)
        .metadata_prefix(Path::new("repository"))
        .targets_prefix(Path::new("repository").join("targets"))
        .build()
}
