extern crate chrono;
#[macro_use]
extern crate maplit;
extern crate tuf;

use chrono::offset::Utc;
use chrono::prelude::*;
use tuf::client::{Client, Config, PathTranslator};
use tuf::crypto::{HashAlgorithm, KeyId, PrivateKey, SignatureScheme};
use tuf::interchange::{DataInterchange, Json};
use tuf::metadata::{
    MetadataDescription, MetadataPath, MetadataVersion, RootMetadataBuilder, SignedMetadata,
    SnapshotMetadata, TargetDescription, TargetPath, TargetsMetadata, TimestampMetadata,
    VirtualTargetPath,
};
use tuf::repository::{EphemeralRepository, Repository};
use tuf::Result;

// Ironically, this is far from simple, but it's as simple as it can be made.

const ED25519_1_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-4.pk8.der");

struct MyPathTranslator {}

impl PathTranslator for MyPathTranslator {
    fn real_to_virtual(&self, path: &TargetPath) -> Result<VirtualTargetPath> {
        VirtualTargetPath::new(path.value().to_owned().replace("-", "/"))
    }

    fn virtual_to_real(&self, path: &VirtualTargetPath) -> Result<TargetPath> {
        TargetPath::new(path.value().to_owned().replace("/", "-"))
    }
}

#[test]
fn with_translator() {
    let mut remote = EphemeralRepository::<Json>::new();
    let config = Config::default();
    let root_key_ids = init_server(&mut remote, &config).unwrap();
    init_client(&root_key_ids, remote, config).unwrap();
}

#[test]
fn without_translator() {
    let mut remote = EphemeralRepository::<Json>::new();
    let config = Config::build()
        .path_translator(MyPathTranslator {})
        .finish()
        .unwrap();
    let root_key_ids = init_server(&mut remote, &config).unwrap();
    init_client(&root_key_ids, remote, config).unwrap();
}

fn init_client<T>(
    root_key_ids: &[KeyId],
    remote: EphemeralRepository<Json>,
    config: Config<T>,
) -> Result<()>
where
    T: PathTranslator,
{
    let local = EphemeralRepository::<Json>::new();
    let mut client = Client::with_root_pinned(root_key_ids, config, local, remote)?;
    match client.update_local() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
    let _ = client.update_remote()?;
    client.fetch_target(&TargetPath::new("foo-bar".into())?)
}

fn init_server<T>(remote: &mut EphemeralRepository<Json>, config: &Config<T>) -> Result<Vec<KeyId>>
where
    T: PathTranslator,
{
    // in real life, you wouldn't want these keys on the same machine ever
    let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)?;
    let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519)?;
    let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519)?;
    let timestamp_key = PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519)?;

    //// build the root ////

    let signed = RootMetadataBuilder::new()
        .root_key(root_key.public().clone())
        .snapshot_key(snapshot_key.public().clone())
        .targets_key(targets_key.public().clone())
        .timestamp_key(timestamp_key.public().clone())
        .signed::<Json>(&root_key)
        .unwrap();

    remote.store_metadata(
        &MetadataPath::new("root".into())?,
        &MetadataVersion::Number(1),
        &signed,
    )?;
    remote.store_metadata(
        &MetadataPath::new("root".into())?,
        &MetadataVersion::None,
        &signed,
    )?;

    //// build the targets ////

    let target_file: &[u8] = b"things fade, alternatives exclude";
    let target_path = TargetPath::new("foo-bar".into())?;
    let target_description = TargetDescription::from_reader(target_file, &[HashAlgorithm::Sha256])?;
    let _ = remote.store_target(target_file, &target_path);

    let target_map =
        hashmap!(config.path_translator().real_to_virtual(&target_path)? => target_description);
    let targets = TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), target_map, None)?;

    let signed = SignedMetadata::<Json, _>::new(targets, &targets_key)?;

    remote.store_metadata(
        &MetadataPath::new("targets".into())?,
        &MetadataVersion::Number(1),
        &signed,
    )?;
    remote.store_metadata(
        &MetadataPath::new("targets".into())?,
        &MetadataVersion::None,
        &signed,
    )?;

    let targets_bytes = Json::canonicalize(&Json::serialize(&signed)?)?;

    //// build the snapshot ////
    let meta_map = hashmap! {
        MetadataPath::new("targets".into())? =>
            MetadataDescription::from_reader(&*targets_bytes, 1, &[HashAlgorithm::Sha256])?,
    };
    let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map)?;

    let signed = SignedMetadata::<Json, _>::new(snapshot, &snapshot_key)?;

    remote.store_metadata(
        &MetadataPath::new("snapshot".into())?,
        &MetadataVersion::Number(1),
        &signed,
    )?;
    remote.store_metadata(
        &MetadataPath::new("snapshot".into())?,
        &MetadataVersion::None,
        &signed,
    )?;

    let snapshot_bytes = Json::canonicalize(&Json::serialize(&signed)?)?;

    //// build the timestamp ////
    let snap = MetadataDescription::from_reader(&*snapshot_bytes, 1, &[HashAlgorithm::Sha256])?;
    let timestamp = TimestampMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), snap)?;

    let signed = SignedMetadata::<Json, _>::new(timestamp, &timestamp_key)?;

    remote.store_metadata(
        &MetadataPath::new("timestamp".into())?,
        &MetadataVersion::Number(1),
        &signed,
    )?;
    remote.store_metadata(
        &MetadataPath::new("timestamp".into())?,
        &MetadataVersion::None,
        &signed,
    )?;

    Ok(vec![root_key.key_id().clone()])
}
