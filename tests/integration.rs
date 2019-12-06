use maplit::hashmap;
use tuf::crypto::{HashAlgorithm, PrivateKey, SignatureScheme};
use tuf::interchange::Json;
use tuf::metadata::{
    Delegation, Delegations, MetadataDescription, MetadataPath, RootMetadataBuilder,
    SnapshotMetadataBuilder, TargetsMetadataBuilder, TimestampMetadataBuilder, VirtualTargetPath,
};
use std::iter::once;
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

    let root = RootMetadataBuilder::new()
        .root_key(root_key.public().clone())
        .snapshot_key(snapshot_key.public().clone())
        .targets_key(targets_key.public().clone())
        .timestamp_key(timestamp_key.public().clone())
        .signed::<Json>(&root_key)
        .unwrap();

    let mut tuf =
        Tuf::<Json>::from_root_with_trusted_keys(root, 1, once(root_key.public())).unwrap();

    //// build the snapshot and timestamp ////

    let snapshot = SnapshotMetadataBuilder::new()
        .insert_metadata_description(
            MetadataPath::new("targets").unwrap(),
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
        )
        .insert_metadata_description(
            MetadataPath::new("delegation").unwrap(),
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
        )
        .signed::<Json>(&snapshot_key)
        .unwrap();

    let timestamp = TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
        .unwrap()
        .signed::<Json>(&timestamp_key)
        .unwrap();

    tuf.update_timestamp(timestamp).unwrap();
    tuf.update_snapshot(snapshot).unwrap();

    //// build the targets ////
    let delegations = Delegations::new(
        hashmap! { delegation_key.public().key_id().clone() => delegation_key.public().clone() },
        vec![Delegation::new(
            MetadataPath::new("delegation").unwrap(),
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
        )
        .unwrap()],
    )
    .unwrap();
    let targets = TargetsMetadataBuilder::new()
        .delegations(delegations)
        .signed::<Json>(&targets_key)
        .unwrap();

    tuf.update_targets(targets).unwrap();

    //// build the delegation ////
    let target_file: &[u8] = b"bar";
    let delegation = TargetsMetadataBuilder::new()
        .insert_target_from_reader(
            VirtualTargetPath::new("foo".into()).unwrap(),
            target_file,
            &[HashAlgorithm::Sha256],
        )
        .unwrap()
        .signed::<Json>(&delegation_key)
        .unwrap();

    tuf.update_delegation(&MetadataPath::new("delegation").unwrap(), delegation)
        .unwrap();

    assert!(tuf
        .target_description(&VirtualTargetPath::new("foo".into()).unwrap())
        .is_ok());
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

    let root = RootMetadataBuilder::new()
        .root_key(root_key.public().clone())
        .snapshot_key(snapshot_key.public().clone())
        .targets_key(targets_key.public().clone())
        .timestamp_key(timestamp_key.public().clone())
        .signed::<Json>(&root_key)
        .unwrap();

    let mut tuf =
        Tuf::<Json>::from_root_with_trusted_keys(root, 1, once(root_key.public())).unwrap();

    //// build the snapshot and timestamp ////

    let snapshot = SnapshotMetadataBuilder::new()
        .insert_metadata_description(
            MetadataPath::new("targets").unwrap(),
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
        )
        .insert_metadata_description(
            MetadataPath::new("delegation-a").unwrap(),
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
        )
        .insert_metadata_description(
            MetadataPath::new("delegation-b").unwrap(),
            MetadataDescription::from_reader(&*vec![0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
        )
        .signed::<Json>(&snapshot_key)
        .unwrap();

    let timestamp = TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
        .unwrap()
        .signed::<Json>(&timestamp_key)
        .unwrap();

    tuf.update_timestamp(timestamp).unwrap();
    tuf.update_snapshot(snapshot).unwrap();

    //// build the targets ////

    let delegations = Delegations::new(
        hashmap! {
            delegation_b_key.public().key_id().clone() => delegation_a_key.public().clone(),
        },
        vec![Delegation::new(
            MetadataPath::new("delegation-a").unwrap(),
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
        )
        .unwrap()],
    )
    .unwrap();
    let targets = TargetsMetadataBuilder::new()
        .delegations(delegations)
        .signed::<Json>(&targets_key)
        .unwrap();

    tuf.update_targets(targets).unwrap();

    //// build delegation A ////

    let delegations = Delegations::new(
        hashmap! { delegation_b_key.public().key_id().clone() => delegation_b_key.public().clone() },
        vec![Delegation::new(
            MetadataPath::new("delegation-b").unwrap(),
            false,
            1,
            vec![delegation_b_key.key_id().clone()].iter().cloned().collect(),
            vec![VirtualTargetPath::new("foo".into()).unwrap()].iter().cloned().collect(),
        )
        .unwrap()],
    )
    .unwrap();

    let delegation = TargetsMetadataBuilder::new()
        .delegations(delegations)
        .signed::<Json>(&delegation_a_key)
        .unwrap();

    tuf.update_delegation(&MetadataPath::new("delegation-a").unwrap(), delegation)
        .unwrap();

    //// build delegation B ////

    let target_file: &[u8] = b"bar";

    let delegation = TargetsMetadataBuilder::new()
        .insert_target_from_reader(
            VirtualTargetPath::new("foo".into()).unwrap(),
            target_file,
            &[HashAlgorithm::Sha256],
        )
        .unwrap()
        .signed::<Json>(&delegation_b_key)
        .unwrap();

    tuf.update_delegation(&MetadataPath::new("delegation-b").unwrap(), delegation)
        .unwrap();

    assert!(tuf
        .target_description(&VirtualTargetPath::new("foo".into()).unwrap())
        .is_ok());
}
