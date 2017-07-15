extern crate chrono;
extern crate tuf;

use chrono::prelude::*;
use chrono::offset::Utc;
use std::collections::{HashSet, HashMap};
use tuf::{Tuf, Error};
use tuf::client::{Client, Config};
use tuf::crypto::{PrivateKey, SignatureScheme, KeyId, HashAlgorithm};
use tuf::interchange::JsonDataInterchange;
use tuf::metadata::{RoleDefinition, RootMetadata, Role, MetadataVersion, MetadataPath,
                    SignedMetadata, TargetDescription, TargetPath, TargetsMetadata,
                    MetadataDescription, SnapshotMetadata, TimestampMetadata};
use tuf::repository::{EphemeralRepository, Repository};

// Ironically, this is far from simple, but it's as simple as it can be made.

const ED25519_1_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-4.pk8.der");

#[test]
fn main() {
    let mut remote = EphemeralRepository::<JsonDataInterchange>::new();
    let root_key_ids = init_server(&mut remote).unwrap();
    init_client(root_key_ids, remote).unwrap();
}

fn init_client(
    root_key_ids: Vec<KeyId>,
    mut remote: EphemeralRepository<JsonDataInterchange>,
) -> Result<(), Error> {
    let local = EphemeralRepository::<JsonDataInterchange>::new();
    let config = Config::build().finish()?;
    let root = remote.fetch_metadata(
        &Role::Root,
        &MetadataPath::from_role(&Role::Root),
        &MetadataVersion::None,
        config.max_root_size(),
        None,
    )?;

    let tuf = Tuf::<JsonDataInterchange>::from_root_pinned(root, &root_key_ids)?;
    let mut client = Client::new(tuf, config, local, remote)?;
    match client.update_local() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
    let _ = client.update_remote()?;
    client.fetch_target(&TargetPath::new("grendel".into())?)
}

fn init_server(remote: &mut EphemeralRepository<JsonDataInterchange>) -> Result<Vec<KeyId>, Error> {
    // in real life, you wouldn't want these keys on the same machine ever
    let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8)?;
    let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8)?;
    let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8)?;
    let timestamp_key = PrivateKey::from_pkcs8(ED25519_4_PK8)?;

    //// build the root ////

    let keys = vec![
        root_key.public().clone(),
        snapshot_key.public().clone(),
        targets_key.public().clone(),
        timestamp_key.public().clone(),
    ];

    let mut key_ids = HashSet::new();
    key_ids.insert(root_key.key_id().clone());
    let root_def = RoleDefinition::new(1, key_ids)?;

    let mut key_ids = HashSet::new();
    key_ids.insert(snapshot_key.key_id().clone());
    let snapshot_def = RoleDefinition::new(1, key_ids)?;

    let mut key_ids = HashSet::new();
    key_ids.insert(targets_key.key_id().clone());
    let targets_def = RoleDefinition::new(1, key_ids)?;

    let mut key_ids = HashSet::new();
    key_ids.insert(timestamp_key.key_id().clone());
    let timestamp_def = RoleDefinition::new(1, key_ids)?;

    let root = RootMetadata::new(
        1,
        Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
        false,
        keys,
        root_def,
        snapshot_def,
        targets_def,
        timestamp_def,
    )?;

    let signed = SignedMetadata::<JsonDataInterchange, RootMetadata>::new(
        &root,
        &root_key,
        SignatureScheme::Ed25519,
    )?;

    remote.store_metadata(
        &Role::Root,
        &MetadataPath::new("root".into())?,
        &MetadataVersion::Number(1),
        &signed,
    )?;
    remote.store_metadata(
        &Role::Root,
        &MetadataPath::new("root".into())?,
        &MetadataVersion::None,
        &signed,
    )?;

    //// build the targets ////

    let target_file: &[u8] = b"things fade, alternatives exclude";
    let target_path = TargetPath::new("grendel".into())?;
    let target_description = TargetDescription::from_reader(target_file, &[HashAlgorithm::Sha256])?;
    let _ = remote.store_target(target_file, &target_path, &target_description);

    let mut target_map = HashMap::new();
    let _ = target_map.insert(target_path, target_description);
    let targets = TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), target_map, None)?;

    let signed = SignedMetadata::<JsonDataInterchange, TargetsMetadata>::new(
        &targets,
        &targets_key,
        SignatureScheme::Ed25519,
    )?;

    remote.store_metadata(
        &Role::Targets,
        &MetadataPath::new("targets".into())?,
        &MetadataVersion::Number(1),
        &signed,
    )?;
    remote.store_metadata(
        &Role::Targets,
        &MetadataPath::new("targets".into())?,
        &MetadataVersion::None,
        &signed,
    )?;

    //// build the snapshot ////
    let mut meta_map = HashMap::new();
    let path = MetadataPath::new("targets".into())?;
    let desc = MetadataDescription::new(1)?;
    let _ = meta_map.insert(path, desc);
    let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map)?;

    let signed = SignedMetadata::<JsonDataInterchange, SnapshotMetadata>::new(
        &snapshot,
        &snapshot_key,
        SignatureScheme::Ed25519,
    )?;

    remote.store_metadata(
        &Role::Snapshot,
        &MetadataPath::new("snapshot".into())?,
        &MetadataVersion::Number(1),
        &signed,
    )?;
    remote.store_metadata(
        &Role::Snapshot,
        &MetadataPath::new("snapshot".into())?,
        &MetadataVersion::None,
        &signed,
    )?;

    //// build the timestamp ////
    let mut meta_map = HashMap::new();
    let path = MetadataPath::new("snapshot".into())?;
    let desc = MetadataDescription::new(1)?;
    let _ = meta_map.insert(path, desc);
    let timestamp = TimestampMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map)?;

    let signed = SignedMetadata::<JsonDataInterchange, TimestampMetadata>::new(
        &timestamp,
        &timestamp_key,
        SignatureScheme::Ed25519,
    )?;

    remote.store_metadata(
        &Role::Timestamp,
        &MetadataPath::new("timestamp".into())?,
        &MetadataVersion::Number(1),
        &signed,
    )?;
    remote.store_metadata(
        &Role::Timestamp,
        &MetadataPath::new("timestamp".into())?,
        &MetadataVersion::None,
        &signed,
    )?;

    Ok(vec![root_key.key_id().clone()])
}
