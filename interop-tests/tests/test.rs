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

use assert_matches::assert_matches;
use futures_executor::block_on;
use futures_util::io::AsyncReadExt;
use interop_tests::JsonPretty;
use pretty_assertions::assert_eq;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tuf::client::{Client, Config};
use tuf::crypto::PublicKey;
use tuf::metadata::{MetadataPath, MetadataVersion, RawSignedMetadata, RootMetadata, TargetPath};
use tuf::pouf::{Pouf, Pouf1};
use tuf::repository::{
    EphemeralRepository, FileSystemRepository, FileSystemRepositoryBuilder, RepositoryProvider,
};

#[test]
fn fuchsia_go_tuf_consistent_snapshot_false() {
    test_key_rotation::<Pouf1>(
        Path::new("tests")
            .join("fuchsia-go-tuf-5527fe")
            .join("consistent-snapshot-false"),
    );
}

#[test]
fn fuchsia_go_tuf_consistent_snapshot_true() {
    test_key_rotation::<Pouf1>(
        Path::new("tests")
            .join("fuchsia-go-tuf-5527fe")
            .join("consistent-snapshot-true"),
    );
}

#[test]
fn fuchsia_go_tuf_transition_m4_consistent_snapshot_false() {
    test_key_rotation::<Pouf1>(
        Path::new("tests")
            .join("fuchsia-go-tuf-transition-M4")
            .join("consistent-snapshot-false"),
    );
}

#[test]
fn fuchsia_go_tuf_transition_m4_consistent_snapshot_true() {
    test_key_rotation::<Pouf1>(
        Path::new("tests")
            .join("fuchsia-go-tuf-transition-M4")
            .join("consistent-snapshot-true"),
    );
}

// Tests to catch changes to the way we generate metadata.
#[test]
fn rust_tuf_identity_consistent_snapshot_false() {
    test_key_rotation::<JsonPretty>(
        Path::new("tests")
            .join("metadata")
            .join("consistent-snapshot-false"),
    );
}

#[test]
fn rust_tuf_identity_consistent_snapshot_true() {
    test_key_rotation::<JsonPretty>(
        Path::new("tests")
            .join("metadata")
            .join("consistent-snapshot-true"),
    );
}

fn test_key_rotation<D>(dir: PathBuf)
where
    D: Pouf,
{
    block_on(async {
        let mut suite = TestKeyRotation::<D>::new(dir);
        suite.run_tests().await;
    })
}

/// TestKeyRotation is the main driver for running the key rotation tests.
struct TestKeyRotation<D>
where
    D: Pouf,
{
    /// The paths to each test step directory.
    test_steps: Vec<PathBuf>,

    /// The local repository used to store the local metadata.
    local: EphemeralRepository<D>,

    /// The targets we expect each step of the repository to contain. It will contain a target for
    /// each step we've processed, named for the first step it appeared in.
    expected_targets: BTreeMap<TargetPath, String>,
}

impl<D> TestKeyRotation<D>
where
    D: Pouf,
{
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
            local: EphemeralRepository::new(),
            expected_targets: BTreeMap::new(),
        }
    }

    async fn run_tests(&mut self) {
        let mut init = true;
        let mut public_keys = Vec::new();

        for step_dir in self.test_steps.clone() {
            // Extract the keys from the first step.
            if init {
                init = false;
                public_keys = extract_keys::<D>(&step_dir).await;
            }

            self.run_test_step(&public_keys, step_dir).await;
        }
    }

    async fn run_test_step(&mut self, public_keys: &[PublicKey], dir: PathBuf) {
        let remote = init_remote(&dir);

        // Connect to the client with our initial keys.
        let mut client = Client::with_trusted_root_keys(
            Config::default(),
            MetadataVersion::Number(1),
            1,
            public_keys,
            &mut self.local,
            remote,
        )
        .await
        .expect("client to open");

        // Update our TUF metadata. The first time should report there is new metadata, the second
        // time should not.
        assert_matches!(client.update().await, Ok(true));
        assert_matches!(client.update().await, Ok(false));

        // Add the expected target to our target list.
        let file_name = dir.file_name().unwrap().to_str().unwrap().to_string();
        let target_path = TargetPath::new(file_name.clone()).unwrap();
        self.expected_targets.insert(target_path, file_name);

        // fetch all the targets and check they have the correct content
        for (target_path, expected) in self.expected_targets.iter() {
            let mut buf = Vec::new();
            let rdr = client.fetch_target(target_path).await.unwrap();
            futures_util::io::copy(rdr, &mut buf).await.unwrap();
            assert_eq!(&String::from_utf8(buf).unwrap(), expected);
        }
    }
}

/// Extract the initial key ids from the first step.
async fn extract_keys<D>(dir: &Path) -> Vec<PublicKey>
where
    D: Pouf,
{
    let remote = init_remote::<D>(dir);

    let root_path = MetadataPath::root();

    let mut buf = Vec::new();
    let mut reader = remote
        .fetch_metadata(&root_path, MetadataVersion::Number(1))
        .await
        .unwrap();
    reader.read_to_end(&mut buf).await.unwrap();
    let metadata = RawSignedMetadata::<D, RootMetadata>::new(buf)
        .parse_untrusted()
        .unwrap()
        .assume_valid()
        .unwrap();

    metadata.root_keys().cloned().collect()
}

fn init_remote<D>(dir: &Path) -> FileSystemRepository<D>
where
    D: Pouf,
{
    FileSystemRepositoryBuilder::new(dir)
        .metadata_prefix(Path::new("repository"))
        .targets_prefix(Path::new("repository").join("targets"))
        .build()
}

#[test]
fn test_metadata_generation_does_not_change_consistent_snapshot_false() {
    block_on(async {
        let dir = tempfile::TempDir::new().unwrap();
        interop_tests::generate_repos(
            &Path::new("tests").join("metadata").join("keys.json"),
            dir.path(),
            false,
        )
        .await
        .unwrap();

        compare_dirs(
            &Path::new("tests")
                .join("metadata")
                .join("consistent-snapshot-false"),
            dir.path(),
        );
    });
}

#[test]
fn test_metadata_generation_does_not_change_consistent_snapshot_true() {
    block_on(async {
        let dir = tempfile::TempDir::new().unwrap();
        interop_tests::generate_repos(
            &Path::new("tests").join("metadata").join("keys.json"),
            dir.path(),
            true,
        )
        .await
        .unwrap();

        compare_dirs(
            &Path::new("tests")
                .join("metadata")
                .join("consistent-snapshot-true"),
            dir.path(),
        );
    });
}

fn compare_dirs(expected: &Path, actual: &Path) {
    assert!(expected.exists());
    assert!(actual.exists());

    let expected_entries = interop_tests::read_dir_files(expected);
    let actual_entries = interop_tests::read_dir_files(actual);

    assert_eq!(
        expected_entries.keys().collect::<Vec<_>>(),
        actual_entries.keys().collect::<Vec<_>>()
    );

    for key in expected_entries.keys() {
        assert_eq!(expected_entries.get(key), actual_entries.get(key));
    }
}
