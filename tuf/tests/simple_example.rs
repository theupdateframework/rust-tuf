use futures_executor::block_on;
use tuf::client::{Client, Config};
use tuf::crypto::{self, Ed25519PrivateKey, HashAlgorithm, PrivateKey, PublicKey};
use tuf::interchange::Json;
use tuf::metadata::{
    MetadataPath, MetadataVersion, RootMetadataBuilder, SnapshotMetadataBuilder, TargetDescription,
    TargetPath, TargetsMetadataBuilder, TimestampMetadataBuilder,
};
use tuf::repository::{EphemeralRepository, RepositoryStorage};
use tuf::Result;

// Ironically, this is far from simple, but it's as simple as it can be made.

const ED25519_1_PK8: &[u8] = include_bytes!("./ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &[u8] = include_bytes!("./ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &[u8] = include_bytes!("./ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &[u8] = include_bytes!("./ed25519/ed25519-4.pk8.der");

#[test]
fn consistent_snapshot_false() {
    block_on(async {
        let config = Config::default();

        run_tests(config, false).await
    })
}

#[test]
fn consistent_snapshot_true() {
    block_on(async {
        let config = Config::default();

        run_tests(config, true).await
    })
}

async fn run_tests(config: Config, consistent_snapshots: bool) {
    let mut remote = EphemeralRepository::new();
    let root_public_keys = init_server(&mut remote, consistent_snapshots)
        .await
        .unwrap();

    init_client(&root_public_keys, remote, config)
        .await
        .unwrap();
}

async fn init_client(
    root_public_keys: &[PublicKey],
    remote: EphemeralRepository<Json>,
    config: Config,
) -> Result<()> {
    let local = EphemeralRepository::new();
    let mut client = Client::with_trusted_root_keys(
        config,
        &MetadataVersion::Number(1),
        1,
        root_public_keys,
        local,
        remote,
    )
    .await?;
    let _ = client.update().await?;
    let target_path = TargetPath::new("foo-bar".into())?;
    client.fetch_target_to_local(&target_path).await
}

async fn init_server(
    remote: &mut EphemeralRepository<Json>,
    consistent_snapshot: bool,
) -> Result<Vec<PublicKey>> {
    // in real life, you wouldn't want these keys on the same machine ever
    let root_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8)?;
    let snapshot_key = Ed25519PrivateKey::from_pkcs8(ED25519_2_PK8)?;
    let targets_key = Ed25519PrivateKey::from_pkcs8(ED25519_3_PK8)?;
    let timestamp_key = Ed25519PrivateKey::from_pkcs8(ED25519_4_PK8)?;

    //// build the root ////

    let signed = RootMetadataBuilder::new()
        .consistent_snapshot(consistent_snapshot)
        .root_key(root_key.public().clone())
        .snapshot_key(snapshot_key.public().clone())
        .targets_key(targets_key.public().clone())
        .timestamp_key(timestamp_key.public().clone())
        .signed::<Json>(&root_key)?;

    let root_path = MetadataPath::new("root")?;
    remote
        .store_metadata(
            &root_path,
            &MetadataVersion::Number(1),
            &mut signed.to_raw().unwrap().as_bytes(),
        )
        .await?;
    remote
        .store_metadata(
            &root_path,
            &MetadataVersion::None,
            &mut signed.to_raw().unwrap().as_bytes(),
        )
        .await?;

    //// build the targets ////

    let target_file: &[u8] = b"things fade, alternatives exclude";
    let target_description = TargetDescription::from_slice(target_file, &[HashAlgorithm::Sha256])?;

    let target_path = TargetPath::new("foo-bar".into())?;

    // According to TUF section 5.5.2, when consistent snapshot is enabled, target files should be
    // stored at `$HASH.FILENAME.EXT`. Otherwise it is stored at `FILENAME.EXT`.
    if consistent_snapshot {
        let hashes = crypto::retain_supported_hashes(target_description.hashes());
        let (_, value) = hashes.first().unwrap();
        let hash_prefixed_path = target_path.with_hash_prefix(value)?;
        let _ = remote
            .store_target(&hash_prefixed_path, &mut &*target_file)
            .await;
    } else {
        let _ = remote.store_target(&target_path, &mut &*target_file).await;
    };

    let targets = TargetsMetadataBuilder::new()
        .insert_target_description(target_path, target_description)
        .signed::<Json>(&targets_key)?;

    let targets_path = &MetadataPath::new("targets")?;
    remote
        .store_metadata(
            targets_path,
            &MetadataVersion::Number(1),
            &mut targets.to_raw().unwrap().as_bytes(),
        )
        .await?;
    remote
        .store_metadata(
            targets_path,
            &MetadataVersion::None,
            &mut targets.to_raw().unwrap().as_bytes(),
        )
        .await?;

    //// build the snapshot ////

    let snapshot = SnapshotMetadataBuilder::new()
        .insert_metadata(&targets, &[HashAlgorithm::Sha256])?
        .signed::<Json>(&snapshot_key)?;

    let snapshot_path = MetadataPath::new("snapshot")?;
    remote
        .store_metadata(
            &snapshot_path,
            &MetadataVersion::Number(1),
            &mut snapshot.to_raw().unwrap().as_bytes(),
        )
        .await?;
    remote
        .store_metadata(
            &snapshot_path,
            &MetadataVersion::None,
            &mut snapshot.to_raw().unwrap().as_bytes(),
        )
        .await?;

    //// build the timestamp ////

    let timestamp = TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])?
        .signed::<Json>(&timestamp_key)?;

    let timestamp_path = MetadataPath::new("timestamp")?;
    remote
        .store_metadata(
            &timestamp_path,
            &MetadataVersion::Number(1),
            &mut timestamp.to_raw().unwrap().as_bytes(),
        )
        .await?;
    remote
        .store_metadata(
            &timestamp_path,
            &MetadataVersion::None,
            &mut timestamp.to_raw().unwrap().as_bytes(),
        )
        .await?;

    Ok(vec![root_key.public().clone()])
}
