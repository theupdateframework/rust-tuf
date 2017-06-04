extern crate data_encoding;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json as json;
extern crate tempdir;
extern crate tuf;

use data_encoding::HEXLOWER;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use tempdir::TempDir;
use tuf::{Tuf, Config, Error, RemoteRepo};
use tuf::meta::{Key, KeyValue, KeyType};


fn load_vector_meta() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("tuf-test-vectors")
        .join("tuf")
        .join("vector-meta.json");
    let mut file = File::open(path).expect("couldn't open vector meta");
    let mut buf = String::new();
    file.read_to_string(&mut buf).expect("couldn't read vector meta");
    buf
}

#[derive(Deserialize)]
struct VectorMeta {
    vectors: Vec<VectorMetaEntry>,
}

#[derive(Deserialize)]
struct VectorMetaEntry {
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
    let temp_dir = TempDir::new("rust-tuf").expect("couldn't make temp dir");
    let temp_path = temp_dir.into_path();

    println!("Temp dir is: {:?}", temp_path);

    let vector_meta: VectorMeta = json::from_str(&load_vector_meta())
        .expect("couldn't deserializd meta");

    let test_vector = vector_meta.vectors
        .iter()
        .filter(|v| v.repo == test_path)
        .collect::<Vec<&VectorMetaEntry>>()
        .pop()
        .expect(format!("No repo named {}", test_path).as_str());

    let vector_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("tuf-test-vectors")
        .join("tuf")
        .join(test_vector.repo.clone());

    println!("The test vector path is: {}",
             vector_path.to_string_lossy().into_owned());

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
        .remote(RemoteRepo::File(vector_path.join("repo")))
        .local_path(temp_path.clone())
        .finish()
        .expect("bad config");

    match (Tuf::from_root_keys(root_keys, config), &test_vector.error) {
        (Ok(ref tuf), &None) => {
            // first time pulls remote
            assert_eq!(tuf.fetch_target("targets/file.txt").map(|_| ()), Ok(()));
            assert!(temp_path.join("targets").join("targets").join("file.txt").exists());
            // second time pulls local
            assert_eq!(tuf.fetch_target("targets/file.txt").map(|_| ()), Ok(()));
        }

        (Ok(ref tuf), &Some(ref err)) if err == &"TargetHashMismatch".to_string() => {
            assert_eq!(tuf.fetch_target("targets/file.txt").map(|_| ()),
                       Err(Error::UnavailableTarget));
        }

        (Ok(ref tuf), &Some(ref err)) if err == &"OversizedTarget".to_string() => {
            assert_eq!(tuf.fetch_target("targets/file.txt").map(|_| ()),
                       Err(Error::UnavailableTarget));
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

        (Err(Error::NonUniqueSignatures(ref role)), &Some(ref err)) if err.starts_with("NonUniqueSignatures::") => {
            assert!(err.to_lowercase()
                        .ends_with(role.to_string().as_str()),
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

// TODO 003
// TODO 004

#[test]
fn vector_005() {
    run_test_vector("005")
}

// TODO 006

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

// TODO 027
// TODO 028

#[test]
fn vector_029() {
    run_test_vector("029")
}

#[test]
fn vector_030() {
    run_test_vector("030")
}

#[test]
fn vector_031() {
    run_test_vector("031")
}

#[test]
fn vector_032() {
    run_test_vector("032")
}

#[test]
fn vector_033() {
    run_test_vector("033")
}

#[test]
fn vector_034() {
    run_test_vector("034")
}

// TODO 035
// TODO 036

#[test]
fn vector_037() {
    run_test_vector("037")
}

#[test]
fn vector_038() {
    run_test_vector("038")
}

#[test]
fn vector_039() {
    run_test_vector("039")
}

#[test]
fn vector_040() {
    run_test_vector("040")
}

// TODO 041
// TODO 042
// TODO 043
// TODO 044

#[test]
fn vector_045() {
    run_test_vector("045")
}

#[test]
fn vector_046() {
    run_test_vector("046")
}
