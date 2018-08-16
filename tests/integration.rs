extern crate chrono;
#[macro_use]
extern crate maplit;
extern crate tuf;

use chrono::offset::Utc;
use chrono::prelude::*;
use std::collections::HashMap;
use tuf::crypto::{HashAlgorithm, PrivateKey, SignatureScheme};
use tuf::interchange::Json;
use tuf::metadata::{
    Delegation, Delegations, MetadataDescription, MetadataPath, RootMetadataBuilder,
    SignedMetadata, SnapshotMetadata, TargetDescription, TargetsMetadata, TimestampMetadata,
    VirtualTargetPath,
};
use tuf::Tuf;

const ED25519_1_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-4.pk8.der");
const ED25519_5_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-5.pk8.der");
const ED25519_6_PK8: &'static [u8] = include_bytes!("./ed25519/ed25519-6.pk8.der");

#[test]
fn simple_delegation() {
    let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
    let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519).unwrap();
    let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519).unwrap();
    let timestamp_key = PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519).unwrap();
    let delegation_key = PrivateKey::from_pkcs8(ED25519_5_PK8, SignatureScheme::Ed25519).unwrap();

    //// build the root ////

    let signed = RootMetadataBuilder::new()
        .root_key(root_key.public().clone())
        .snapshot_key(snapshot_key.public().clone())
        .targets_key(targets_key.public().clone())
        .timestamp_key(timestamp_key.public().clone())
        .signed::<Json>(&root_key)
        .unwrap();

    let mut tuf = Tuf::<Json>::from_root_pinned(signed, &[root_key.key_id().clone()]).unwrap();

    //// build the timestamp ////
    let snap = MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap();
    let timestamp = TimestampMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), snap).unwrap();

    let signed =
        SignedMetadata::<Json, _>::new(timestamp, &timestamp_key).unwrap();

    tuf.update_timestamp(signed).unwrap();

    //// build the snapshot ////
    let meta_map = hashmap! {
        MetadataPath::new("targets".into()).unwrap() =>
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
        MetadataPath::new("delegation".into()).unwrap() =>
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
    };
    let snapshot =
        SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map).unwrap();

    let signed = SignedMetadata::<Json, _>::new(snapshot, &snapshot_key).unwrap();

    tuf.update_snapshot(signed).unwrap();

    //// build the targets ////
    let delegations = Delegations::new(
        &hashset![delegation_key.public().clone()],
        vec![
            Delegation::new(
                MetadataPath::new("delegation".into()).unwrap(),
                false,
                1,
                vec![delegation_key.key_id().clone()]
                    .iter()
                    .cloned()
                    .collect(),
                vec![VirtualTargetPath::new("foo".into()).unwrap()]
                    .iter()
                    .cloned()
                    .collect(),
            ).unwrap(),
        ],
    ).unwrap();
    let targets = TargetsMetadata::new(
        1,
        Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
        HashMap::new(),
        Some(delegations),
    ).unwrap();

    let signed = SignedMetadata::<Json, _>::new(targets, &targets_key).unwrap();

    tuf.update_targets(signed).unwrap();

    //// build the delegation ////
    let target_file: &[u8] = b"bar";
    let target_map = hashmap! {
        VirtualTargetPath::new("foo".into()).unwrap() =>
            TargetDescription::from_reader(target_file, &[HashAlgorithm::Sha256]).unwrap(),
    };
    let delegation =
        TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), target_map, None).unwrap();

    let signed =
        SignedMetadata::<Json, _>::new(delegation, &delegation_key).unwrap();

    tuf.update_delegation(&MetadataPath::new("delegation".into()).unwrap(), signed)
        .unwrap();

    assert!(
        tuf.target_description(&VirtualTargetPath::new("foo".into()).unwrap())
            .is_ok()
    );
}

#[test]
fn nested_delegation() {
    let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
    let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519).unwrap();
    let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519).unwrap();
    let timestamp_key = PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519).unwrap();
    let delegation_a_key = PrivateKey::from_pkcs8(ED25519_5_PK8, SignatureScheme::Ed25519).unwrap();
    let delegation_b_key = PrivateKey::from_pkcs8(ED25519_6_PK8, SignatureScheme::Ed25519).unwrap();

    //// build the root ////

    let signed = RootMetadataBuilder::new()
        .root_key(root_key.public().clone())
        .snapshot_key(snapshot_key.public().clone())
        .targets_key(targets_key.public().clone())
        .timestamp_key(timestamp_key.public().clone())
        .signed::<Json>(&root_key)
        .unwrap();

    let mut tuf = Tuf::<Json>::from_root_pinned(signed, &[root_key.key_id().clone()]).unwrap();

    //// build the timestamp ////
    let snap = MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap();
    let timestamp = TimestampMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), snap).unwrap();

    let signed =
        SignedMetadata::<Json, _>::new(timestamp, &timestamp_key).unwrap();

    tuf.update_timestamp(signed).unwrap();

    //// build the snapshot ////
    let meta_map = hashmap! {
        MetadataPath::new("targets".into()).unwrap() =>
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
        MetadataPath::new("delegation-a".into()).unwrap() =>
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
        MetadataPath::new("delegation-b".into()).unwrap() =>
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
    };
    let snapshot =
        SnapshotMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), meta_map).unwrap();

    let signed = SignedMetadata::<Json, _>::new(snapshot, &snapshot_key).unwrap();

    tuf.update_snapshot(signed).unwrap();

    //// build the targets ////
    let delegations = Delegations::new(
        &hashset![delegation_a_key.public().clone()],
        vec![
            Delegation::new(
                MetadataPath::new("delegation-a".into()).unwrap(),
                false,
                1,
                vec![delegation_a_key.key_id().clone()]
                    .iter()
                    .cloned()
                    .collect(),
                vec![VirtualTargetPath::new("foo".into()).unwrap()]
                    .iter()
                    .cloned()
                    .collect(),
            ).unwrap(),
        ],
    ).unwrap();
    let targets = TargetsMetadata::new(
        1,
        Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
        HashMap::new(),
        Some(delegations),
    ).unwrap();

    let signed = SignedMetadata::<Json, _>::new(targets, &targets_key).unwrap();

    tuf.update_targets(signed).unwrap();

    //// build delegation A ////
    let delegations = Delegations::new(
        &hashset![delegation_b_key.public().clone()],
        vec![
            Delegation::new(
                MetadataPath::new("delegation-b".into()).unwrap(),
                false,
                1,
                vec![delegation_b_key.key_id().clone()]
                    .iter()
                    .cloned()
                    .collect(),
                vec![VirtualTargetPath::new("foo".into()).unwrap()]
                    .iter()
                    .cloned()
                    .collect(),
            ).unwrap(),
        ],
    ).unwrap();
    let delegation = TargetsMetadata::new(
        1,
        Utc.ymd(2038, 1, 1).and_hms(0, 0, 0),
        HashMap::new(),
        Some(delegations),
    ).unwrap();

    let signed =
        SignedMetadata::<Json, _>::new(delegation, &delegation_a_key).unwrap();

    tuf.update_delegation(&MetadataPath::new("delegation-a".into()).unwrap(), signed)
        .unwrap();

    //// build delegation B ////
    let target_file: &[u8] = b"bar";
    let target_map = hashmap! {
        VirtualTargetPath::new("foo".into()).unwrap() =>
            TargetDescription::from_reader(target_file, &[HashAlgorithm::Sha256]).unwrap(),
    };

    let delegation =
        TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), target_map, None).unwrap();

    let signed =
        SignedMetadata::<Json, _>::new(delegation, &delegation_b_key).unwrap();

    tuf.update_delegation(&MetadataPath::new("delegation-b".into()).unwrap(), signed)
        .unwrap();

    assert!(
        tuf.target_description(&VirtualTargetPath::new("foo".into()).unwrap())
            .is_ok()
    );
}
