extern crate data_encoding;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json as json;
extern crate tempdir;
extern crate tuf;

use data_encoding::HEXLOWER;
use std::fs::{self, File, DirBuilder};
use std::io::Read;
use std::path::PathBuf;
use tempdir::TempDir;
use tuf::{Tuf, Config, Error};
use tuf::meta::{Key, KeyValue, KeyType};
use tuf::util;


fn load_vector_meta() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("tuf-test-vectors")
        .join("vectors")
        .join("vector-meta.json");
    let mut file = File::open(path).expect("couldn't open vector meta");
    let mut buf = String::new();
    file.read_to_string(&mut buf).expect("couldn't read vector meta");
    buf
}

#[derive(Deserialize)]
struct VectorMeta {
    repo: String,
    error: Option<String>,
    root_keys: Vec<RootKeyData>,
}

#[derive(Deserialize)]
struct RootKeyData {
    path: String,
    #[serde(rename = "type")]
    typ: String,
}

fn run_test_vector(test_path: &str) {
    let tempdir = TempDir::new("rust-tuf").expect("couldn't make temp dir");

    let vectors: Vec<VectorMeta> = json::from_str(&load_vector_meta())
        .expect("couldn't deserializd meta");

    let test_vector = vectors.iter()
        .filter(|v| v.repo == test_path)
        .collect::<Vec<&VectorMeta>>()
        .pop()
        .expect(format!("No repo named {}", test_path).as_str());

    let vector_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("tuf-test-vectors")
        .join("vectors")
        .join(test_vector.repo.clone());

    println!("The test vector path is: {}",
             vector_path.to_string_lossy().into_owned());

    for dir in vec![PathBuf::from("metadata").join("current"),
                    PathBuf::from("metadata").join("archive"),
                    PathBuf::from("targets")]
        .iter() {
        DirBuilder::new()
            .recursive(true)
            .create(tempdir.path().join(dir))
            .expect(&format!("couldn't create path {}:", dir.to_string_lossy()));
    }

    for file in vec!["1.root.json",
                     "2.root.json",
                     "root.json",
                     "targets.json",
                     "timestamp.json",
                     "snapshot.json"]
        .iter() {
        // TODO make sure these copies succeed
        let copy_path = vector_path.join("repo").join(file);
        fs::copy(copy_path.to_string_lossy().into_owned(),
                 tempdir.path().join("metadata").join("current").join(file));
        //.expect(&format!("copy failed: {}", file));
    }

    let copy_path = vector_path.join("repo").join("targets").join("file.txt");
    fs::copy(copy_path.to_string_lossy().into_owned(),
             tempdir.path().join("targets").join("file.txt"))
        .expect(&format!("copy failed for target"));

    let root_keys = test_vector.root_keys
        .iter()
        .map(|k| {
            let file_path = vector_path.join("keys").join(k.path.clone());
            let mut file = File::open(file_path).expect("couldn't open file");
            let mut key = String::new();
            file.read_to_string(&mut key).expect("couldn't read key");

            match k.typ.as_ref() {
                "ed25519" => {
                    let val = HEXLOWER.decode(key.replace("\n", "").as_ref())
                        .expect("key value not hex");
                    Key {
                        typ: KeyType::Ed25519,
                        value: KeyValue(val),
                    }
                }
                x => panic!("unknown key type: {}", x),
            }
        })
        .collect();

    let config = Config::build()
        .url(util::path_to_url(tempdir.path()).expect("couldn't make url"))
        .local_path(tempdir.into_path())
        .finish()
        .expect("bad config");

    match (Tuf::from_root_keys(root_keys, config), &test_vector.error) {
        (Ok(ref tuf), &None) => {
            assert_eq!(tuf.list_targets(), vec!["targets/file.txt".to_string()]);
            assert_eq!(tuf.verify_target("targets/file.txt"), Ok(()));
        }

        (Ok(ref tuf), &Some(ref err)) if err == &"TargetHashMismatch".to_string() => {
            assert_eq!(tuf.verify_target("targets/file.txt"),
                       Err(Error::TargetHashMismatch));
        }

        (Ok(ref tuf), &Some(ref err)) if err == &"OversizedTarget".to_string() => {
            assert_eq!(tuf.verify_target("targets/file.txt"),
                       Err(Error::OversizedTarget));
        }

        (Err(Error::ExpiredMetadata(ref role)), &Some(ref err))
            if err.starts_with("ExpiredMetadata::") => {
            assert!(err.to_lowercase()
                        .ends_with(role.to_string().as_str()),
                    format!("Role: {}, err: {}", role, err))
        }

        (Err(Error::UnmetThreshold(ref role)), &Some(ref err))
            if err.starts_with("UnmetThreshold::") => {
            assert!(err.to_lowercase()
                        .ends_with(role.to_string().as_str()),
                    format!("Role: {}, err: {}", role, err))
        }

        (Err(Error::MetadataHashMismatch(ref role)), &Some(ref err))
            if err.starts_with("MetadataHashMismatch::") => {
            assert!(err.to_lowercase()
                        .ends_with(role.to_string().as_str()),
                    format!("Role: {}, err: {}", role, err))
        }

        (Err(Error::OversizedMetadata(ref role)), &Some(ref err))
            if err.starts_with("OversizedMetadata::") => {
            assert!(err.to_lowercase()
                        .ends_with(role.to_string().as_str()),
                    format!("Role: {}, err: {}", role, err))
        }

        // we're using a json error because the threshold is checked in the deserializer
        // this may need to change in the future
        (Err(Error::Json(ref msg)), &Some(ref err)) if err.starts_with("IllegalThreshold::") => {
            let role = err.split("::").last().unwrap();

            assert!(msg.contains("threshold"),
                    format!("Role: {}, err: {}", role, err));
            assert!(err.to_lowercase()
                        .contains(role.to_lowercase().as_str()),
                    format!("Role: {}, err: {}", role, err))
        }

        x => panic!("Unexpected failures: {:?}", x),
    }
}

#[test]
fn vector_001() {
    run_test_vector("001")
}

#[test]
fn vector_002() {
    run_test_vector("002")
}

#[ignore]
fn vector_003() {
    run_test_vector("003")
}

#[ignore]
fn vector_004() {
    run_test_vector("004")
}

#[test]
fn vector_005() {
    run_test_vector("005")
}

#[ignore]
fn vector_006() {
    run_test_vector("006")
}

#[test]
fn vector_007() {
    run_test_vector("007")
}

#[test]
fn vector_008() {
    run_test_vector("008")
}

#[test]
fn vector_009() {
    run_test_vector("009")
}

#[test]
fn vector_010() {
    run_test_vector("010")
}

#[test]
fn vector_011() {
    run_test_vector("011")
}

#[test]
fn vector_012() {
    run_test_vector("012")
}

#[test]
fn vector_013() {
    run_test_vector("013")
}

#[test]
fn vector_014() {
    run_test_vector("014")
}

#[test]
fn vector_015() {
    run_test_vector("015")
}

#[test]
fn vector_016() {
    run_test_vector("016")
}

#[test]
fn vector_017() {
    run_test_vector("017")
}

#[test]
fn vector_018() {
    run_test_vector("018")
}

#[test]
fn vector_019() {
    run_test_vector("019")
}

#[test]
fn vector_020() {
    run_test_vector("020")
}

#[test]
fn vector_021() {
    run_test_vector("021")
}

#[test]
fn vector_022() {
    run_test_vector("022")
}

#[test]
fn vector_023() {
    run_test_vector("023")
}

#[test]
fn vector_024() {
    run_test_vector("024")
}

#[test]
fn vector_025() {
    run_test_vector("025")
}

#[test]
fn vector_026() {
    run_test_vector("026")
}

#[ignore]
fn vector_027() {
    run_test_vector("027")
}

#[ignore]
fn vector_028() {
    run_test_vector("028")
}
