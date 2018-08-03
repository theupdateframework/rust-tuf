extern crate chrono;
extern crate tuf;

use tuf::client::{Client, Config, PathTranslator};
use tuf::crypto::{HashAlgorithm, KeyId, PrivateKey, SignatureScheme};
use tuf::interchange::Json;
use tuf::metadata::{
    MetadataPath, MetadataVersion, RootMetadataBuilder, SnapshotMetadataBuilder, TargetPath,
    TargetsMetadataBuilder, TimestampMetadataBuilder, VirtualTargetPath,
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
    let _ = client.update()?;
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
        .signed::<Json>(&root_key)?;

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
    let _ = remote.store_target(target_file, &target_path);

    let targets = TargetsMetadataBuilder::new()
        .insert_target_from_reader(
            config.path_translator().real_to_virtual(&target_path)?,
            target_file,
            &[HashAlgorithm::Sha256],
        )?
        .signed::<Json>(&targets_key)?;

    remote.store_metadata(
        &MetadataPath::new("targets".into())?,
        &MetadataVersion::Number(1),
        &targets,
    )?;
    remote.store_metadata(
        &MetadataPath::new("targets".into())?,
        &MetadataVersion::None,
        &targets,
    )?;

    //// build the snapshot ////

    let snapshot = SnapshotMetadataBuilder::new()
        .insert_metadata(&targets, &[HashAlgorithm::Sha256])?
        .signed::<Json>(&snapshot_key)?;

    remote.store_metadata(
        &MetadataPath::new("snapshot".into())?,
        &MetadataVersion::Number(1),
        &snapshot,
    )?;
    remote.store_metadata(
        &MetadataPath::new("snapshot".into())?,
        &MetadataVersion::None,
        &snapshot,
    )?;

    //// build the timestamp ////

    let timestamp = TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])?
        .signed::<Json>(&timestamp_key)?;

    remote.store_metadata(
        &MetadataPath::new("timestamp".into())?,
        &MetadataVersion::Number(1),
        &timestamp,
    )?;
    remote.store_metadata(
        &MetadataPath::new("timestamp".into())?,
        &MetadataVersion::None,
        &timestamp,
    )?;

    Ok(vec![root_key.key_id().clone()])
}
