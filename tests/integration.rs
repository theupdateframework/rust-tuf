extern crate chrono;
extern crate tuf;

use chrono::prelude::*;
use chrono::offset::Utc;
use std::collections::{HashSet, HashMap};
use tuf::Tuf;
use tuf::crypto::{PrivateKey, SignatureScheme};
use tuf::interchange::JsonDataInterchange;
use tuf::metadata::{RoleDefinition, RootMetadata, MetadataPath, SignedMetadata, TargetDescription,
                    TargetPath, TargetsMetadata, MetadataDescription, SnapshotMetadata,
                    TimestampMetadata, Delegation, Delegations};

const ED25519_1_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-4.pk8.der");
const ED25519_5_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-5.pk8.der");

#[test]
fn simple_delegation() {
    let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
    let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8).unwrap();
    let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8).unwrap();
    let timestamp_key = PrivateKey::from_pkcs8(ED25519_4_PK8).unwrap();
    let delegation_key = PrivateKey::from_pkcs8(ED25519_5_PK8).unwrap();

    //// build the root ////
    let keys = vec![
        root_key.public().clone(),
        snapshot_key.public().clone(),
        targets_key.public().clone(),
        timestamp_key.public().clone(),
    ];

    let mut key_ids = HashSet::new();
    key_ids.insert(root_key.key_id().clone());
    let root_def = RoleDefinition::new(1, key_ids).unwrap();

    let mut key_ids = HashSet::new();
    key_ids.insert(snapshot_key.key_id().clone());
    let snapshot_def = RoleDefinition::new(1, key_ids).unwrap();

    let mut key_ids = HashSet::new();
    key_ids.insert(targets_key.key_id().clone());
    let targets_def = RoleDefinition::new(1, key_ids).unwrap();

    let mut key_ids = HashSet::new();
    key_ids.insert(timestamp_key.key_id().clone());
    let timestamp_def = RoleDefinition::new(1, key_ids).unwrap();

    let root = RootMetadata::new(
        1,
        Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
        false,
        keys,
        root_def,
        snapshot_def,
        targets_def,
        timestamp_def,
    ).unwrap();

    let signed = SignedMetadata::<JsonDataInterchange, RootMetadata>::new(
        &root,
        &root_key,
        SignatureScheme::Ed25519,
    ).unwrap();

    let mut tuf =
        Tuf::<JsonDataInterchange>::from_root_pinned(signed, &[root_key.key_id().clone()]).unwrap();

    //// build the timestamp ////
    let mut meta_map = HashMap::new();
    let path = MetadataPath::new("snapshot".into()).unwrap();
    let desc = MetadataDescription::new(1).unwrap();
    let _ = meta_map.insert(path, desc);
    let timestamp = TimestampMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map)
        .unwrap();

    let signed = SignedMetadata::<JsonDataInterchange, TimestampMetadata>::new(
        &timestamp,
        &timestamp_key,
        SignatureScheme::Ed25519,
    ).unwrap();

    tuf.update_timestamp(signed).unwrap();

    //// build the snapshot ////
    let mut meta_map = HashMap::new();
    let path = MetadataPath::new("targets".into()).unwrap();
    let desc = MetadataDescription::new(1).unwrap();
    let _ = meta_map.insert(path, desc);
    let path = MetadataPath::new("delegation".into()).unwrap();
    let desc = MetadataDescription::new(1).unwrap();
    let _ = meta_map.insert(path, desc);
    let snapshot = SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map)
        .unwrap();

    let signed = SignedMetadata::<JsonDataInterchange, SnapshotMetadata>::new(
        &snapshot,
        &snapshot_key,
        SignatureScheme::Ed25519,
    ).unwrap();

    tuf.update_snapshot(signed).unwrap();

    //// build the targets ////
    let delegations = Delegations::new(
        vec![delegation_key.public().clone()],
        vec![
            Delegation::new(
                MetadataPath::new("delegation".into()).unwrap(),
                false,
                1,
                vec![delegation_key.key_id().clone()]
                    .iter()
                    .cloned()
                    .collect(),
                vec![TargetPath::new("foo".into()).unwrap()]
                    .iter()
                    .cloned()
                    .collect()
            ).unwrap(),
        ],
    ).unwrap();
    let targets = TargetsMetadata::new(
        1,
        Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
        HashMap::new(),
        Some(delegations),
    ).unwrap();

    let signed = SignedMetadata::<JsonDataInterchange, TargetsMetadata>::new(
        &targets,
        &targets_key,
        SignatureScheme::Ed25519,
    ).unwrap();

    tuf.update_targets(signed).unwrap();

    //// build the delegation ////
    let target_file: &[u8] = b"bar";
    let target_path = TargetPath::new("foo".into()).unwrap();
    let target_description = TargetDescription::from_reader(target_file).unwrap();

    let mut target_map = HashMap::new();
    let _ = target_map.insert(target_path, target_description);
    let delegation =
        TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), target_map, None).unwrap();

    let signed = SignedMetadata::<JsonDataInterchange, TargetsMetadata>::new(
        &delegation,
        &delegation_key,
        SignatureScheme::Ed25519,
    ).unwrap();

    tuf.update_delegation(&MetadataPath::new("delegation".into()).unwrap(), signed)
        .unwrap();

    assert_eq!(
        tuf.available_targets().unwrap().iter().next(),
        Some(&TargetPath::new("foo".into()).unwrap())
    );

    assert!(tuf.target_description(&TargetPath::new("foo".into()).unwrap()).is_ok());
}
