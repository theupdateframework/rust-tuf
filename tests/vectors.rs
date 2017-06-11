extern crate data_encoding;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json as json;
extern crate tempdir;
extern crate tuf;
extern crate url;

use data_encoding::HEXLOWER;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use tempdir::TempDir;
use tuf::{Tuf, Config, Error, RemoteRepo};
use tuf::meta::{Key, KeyValue, KeyType};
use url::Url;


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

enum TestType {
    File,
    Http
}

fn run_test_vector(test_path: &str, test_type: TestType) {
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

    let config = match test_type {
        TestType::File => Config::build()
            .remote(RemoteRepo::File(vector_path.join("repo"))),
        TestType::Http => Config::build()
            .remote(RemoteRepo::Http(Url::parse(
                        &format!("http://localhost:8080/{}/repo", test_path)).expect("bad url"))),
    }.local_path(temp_path.clone())
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

        (Ok(ref tuf), &Some(ref err)) if err == &"UnavailableTarget".to_string() => {
            assert_eq!(tuf.fetch_target("targets/file.txt").map(|_| ()),
                       Err(Error::UnavailableTarget));
        }

        (Ok(ref tuf), &Some(ref err))
            if err == &"UnmetThreshold::Delegation".to_string() => {
            assert_eq!(tuf.fetch_target("targets/file.txt").map(|_| ()), Err(Error::UnavailableTarget));
        }

        x => panic!("Unexpected failures: {:?}", x),
    }
}


macro_rules! test_cases {
    ($name: expr, $md: ident) => {
        mod $md {
            use $crate::{run_test_vector, TestType};

            #[test]
            fn file_test() {
                run_test_vector($name, TestType::File)
            }

            // TODO no idea how windows shell scipting works
            #[cfg(not(windows))]
            #[test]
            fn http_test() {
                run_test_vector($name, TestType::Http)
            }
        }
    }
}

test_cases!("001", _001);
test_cases!("002", _002);
// test_cases!("003", _003);
// test_cases!("004", _004);
test_cases!("005", _005);
// test_cases!("006", _006);
test_cases!("007", _007);
test_cases!("008", _008);
test_cases!("009", _009);
test_cases!("010", _010);
test_cases!("011", _011);
test_cases!("012", _012);
test_cases!("013", _013);
test_cases!("014", _014);
test_cases!("015", _015);
test_cases!("016", _016);
test_cases!("017", _017);
test_cases!("018", _018);
test_cases!("019", _019);
test_cases!("020", _020);
test_cases!("021", _021);
test_cases!("022", _022);
test_cases!("023", _023);
test_cases!("024", _024);
test_cases!("025", _025);
test_cases!("026", _026);
// test_cases!("027", _027);
// test_cases!("028", _028);
test_cases!("029", _029);
test_cases!("030", _030);
test_cases!("031", _031);
test_cases!("032", _032);
test_cases!("033", _033);
test_cases!("034", _034);
// test_cases!("035", _035);
// test_cases!("036", _036);
test_cases!("037", _037);
test_cases!("038", _038);
test_cases!("039", _039);
test_cases!("040", _040);
// test_cases!("041", _041);
// test_cases!("042", _042);
// test_cases!("043", _043);
// test_cases!("044", _044);
test_cases!("045", _045);
test_cases!("046", _046);
test_cases!("047", _047);
test_cases!("048", _048);
test_cases!("049", _049);
test_cases!("050", _050);
test_cases!("051", _051);
test_cases!("052", _052);
test_cases!("053", _053);
test_cases!("054", _054);
test_cases!("055", _055);
