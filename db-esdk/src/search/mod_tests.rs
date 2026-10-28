// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The configuration checks of the reference implementation's `Beacon.dfy` and
//! `BeaconPartition.dfy`: each invalid beacon version, and the error it is rejected with.

use std::collections::HashMap;

use crate::search::config::{BeaconStyle, BeaconVersionBuilder, StandardBeacon};
use crate::search::test_fixtures::*;
use crate::types::CryptoAction;

fn lotsa_plus(extra: StandardBeacon) -> BeaconVersionBuilder {
    let mut std = vec![
        std2(),
        std4(),
        std6(),
        name_title_beacon(),
        name_b(),
        title_b(),
    ];
    std.push(extra);
    lotsa().set_standard_beacons(Some(std))
}

fn styled(name: &str, bits: u8, style: BeaconStyle) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .style(style)
        .build()
        .unwrap()
}

fn partitioned(partitions: u8) -> StandardBeacon {
    StandardBeacon::builder()
        .name("std2")
        .bits(24)
        .number_of_partitions(partitions)
        .build()
        .unwrap()
}

fn store() -> FakeKeyStore {
    FakeKeyStore::new("KeyStoreDdbTable")
}

fn rejects(actions: HashMap<String, CryptoAction>, version: BeaconVersionBuilder, message: &str) {
    assert_eq!(val_msg(search_info(actions, version)), message);
}

#[test]
fn bad_prefix() {
    let too_bad = standard("TooBad", 32, None);
    let bad_prefix = compound(
        "BadPrefix",
        vec![name_part(), title_part(), encrypted_part("TooBad", "T")],
        vec![],
        None,
    );
    let version = version_with(
        &store(),
        single_source("foo"),
        vec![name_b(), title_b(), too_bad],
    )
    .set_compound_beacons(Some(vec![bad_prefix]));
    rejects(
        full_actions(),
        version,
        "Compound beacon BadPrefix defines part Title with prefix T_ which is incompatible with part TooBad which has a prefix of T.",
    );
}

#[test]
fn unused_part_only() {
    rejects(
        actions_plus("badBeacon"),
        lotsa_plus(styled("badBeacon", 24, BeaconStyle::part_only())),
        "PartOnly beacon badBeacon MUST be used in a compound beacon.",
    );
}

#[test]
fn compound_with_unknown_part() {
    let unknown = compound(
        "NameUnknown",
        vec![name_part(), encrypted_part("Unknown", "U_")],
        vec![],
        None,
    );
    let version = lotsa().set_compound_beacons(Some(vec![
        name_title(),
        year_name(),
        mixed(),
        just_signed(),
        unknown,
    ]));
    rejects(
        full_actions(),
        version,
        "Compound beacon NameUnknown refers to standard beacon Unknown which is not configured.",
    );
}

#[test]
fn set_in_compound() {
    let compound_set = compound(
        "compoundSet",
        vec![name_part(), encrypted_part("setBeacon", "S_")],
        vec![],
        None,
    );
    let version = lotsa_plus(styled("setBeacon", 24, BeaconStyle::as_set())).set_compound_beacons(
        Some(vec![
            name_title(),
            year_name(),
            mixed(),
            just_signed(),
            compound_set,
        ]),
    );
    rejects(
        actions_plus("setBeacon"),
        version,
        "Compound beacon compoundSet uses setBeacon which is an AsSet beacon, and therefore cannot be used in a Compound Beacon.",
    );
}

#[test]
fn shared_to_compound() {
    rejects(
        actions_plus("shareBeacon"),
        lotsa_plus(styled("shareBeacon", 24, BeaconStyle::shared("NameTitle"))),
        "Beacon shareBeacon is shared to NameTitle but NameTitle is a compound beacon.",
    );
}

#[test]
fn chained_share() {
    let version = version_with(
        &store(),
        single_source("foo"),
        vec![
            std2(),
            styled("shareBeacon", 24, BeaconStyle::shared("std2")),
            styled("std4", 24, BeaconStyle::shared("shareBeacon")),
        ],
    );
    rejects(
        actions_plus("shareBeacon"),
        version,
        "Beacon std4 is shared to shareBeacon which is in turn shared to std2. Share chains are not allowed.",
    );
}

#[test]
fn self_share() {
    let version = version_with(
        &store(),
        single_source("foo"),
        vec![
            std2(),
            styled("shareBeacon", 24, BeaconStyle::shared("shareBeacon")),
        ],
    );
    rejects(
        actions_plus("shareBeacon"),
        version,
        "Beacon shareBeacon is shared to itself.",
    );
}

#[test]
fn shared_to_nonexistent() {
    rejects(
        actions_plus("shareBeacon"),
        lotsa_plus(styled(
            "shareBeacon",
            24,
            BeaconStyle::shared("DoesNotExist"),
        )),
        "Beacon shareBeacon is shared to DoesNotExist which is not defined.",
    );
}

#[test]
fn shared_bad_length() {
    rejects(
        actions_plus("shareBeacon"),
        lotsa_plus(styled("shareBeacon", 23, BeaconStyle::shared("std2"))),
        "Beacon shareBeacon is shared to std2 but shareBeacon has length 23 and std2 has length 24.",
    );
}

#[test]
fn global_part_not_exist() {
    rejects(
        full_actions(),
        lotsa().encrypted_parts(encrypted_part("NotExist", "Q_")),
        "Global Parts List refers to standard beacon NotExist which is not configured.",
    );
}

#[test]
fn duplicate_global_parts() {
    rejects(
        full_actions(),
        lotsa()
            .set_compound_beacons(None)
            .set_signed_parts(Some(vec![year(), month(), year()])),
        "Duplicate part name Year in Global Parts List.",
    );
    rejects(
        full_actions(),
        lotsa()
            .set_compound_beacons(None)
            .set_encrypted_parts(Some(vec![name_part(), title_part(), name_part()])),
        "Duplicate part name Name in Global Parts List.",
    );
    rejects(
        full_actions(),
        lotsa()
            .set_compound_beacons(None)
            .set_encrypted_parts(Some(vec![
                name_part(),
                title_part(),
                encrypted_part("std6", "N_"),
            ])),
        "Duplicate prefix N_ in Global Parts List.",
    );
}

#[test]
fn duplicate_global_vs_local() {
    rejects(
        full_actions(),
        lotsa().encrypted_parts(name_part()),
        "Compound beacon NameTitle defines encrypted part Name which is already defined as a global part.",
    );
    rejects(
        full_actions(),
        lotsa().signed_parts(month()),
        "Compound beacon Mixed defines signed part Month which is already defined as a global part.",
    );
}

#[test]
fn compound_without_constructor_or_local_parts() {
    let compound_default = crate::search::config::CompoundBeacon::builder()
        .name("compoundDefault")
        .split(".")
        .build()
        .unwrap();
    rejects(
        full_actions(),
        lotsa()
            .set_compound_beacons(Some(vec![compound_default]))
            .signed_parts(month())
            .set_encrypted_parts(Some(vec![name_part(), title_part()])),
        "Compound beacon compoundDefault defines no constructors, and also no local parts. Cannot make a default constructor from global parts.",
    );
}

#[tokio::test]
async fn compound_mixing_global_and_local_parts() {
    let mixed = compound(
        "Mixed",
        vec![title_part()],
        vec![month()],
        Some(vec![
            constructor(&[("Name", true), ("Year", true)]),
            constructor(&[("Title", true), ("Month", false)]),
        ]),
    );
    let version = lotsa()
        .set_compound_beacons(Some(vec![mixed]))
        .signed_parts(year())
        .encrypted_parts(name_part());
    let info = search_info(full_actions(), version).unwrap();
    let attrs = info
        .version
        .generate_encrypted_beacons(
            &simple_item(),
            &crate::search::beacon::MaybeKeyId::DontUse,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        attrs["aws_dbe_b_Mixed"],
        s(&format!("N_{NAME_BEACON}.Y_1984"))
    );
}

#[test]
fn invalid_default_number_of_partitions() {
    for (max, default) in [(Some(5), 5), (Some(5), 10), (None, 3)] {
        let version = version_with(&store(), single_source("foo"), vec![std2()])
            .set_maximum_number_of_partitions(max)
            .default_number_of_partitions(default);
        rejects(
            full_actions(),
            version,
            &format!(
                "Invalid defaultNumberOfPartitions specified, {default}, must be 0 < defaultNumberOfPartitions < maximumNumberOfPartitions."
            ),
        );
    }
}

#[test]
fn constrained_partitions_must_be_below_the_maximum() {
    for partitions in [5, 10] {
        let version = version_with(
            &store(),
            single_source("foo"),
            vec![partitioned(partitions)],
        )
        .maximum_number_of_partitions(5);
        rejects(
            full_actions(),
            version,
            &format!(
                "Constrained numberOfPartitions for  std2 is {partitions} but it must be less than the maximumNumberOfPartitions 5"
            ),
        );
    }
    let version = version_with(&store(), single_source("foo"), vec![partitioned(3)])
        .maximum_number_of_partitions(10);
    assert!(search_info(full_actions(), version).is_ok());
}

#[test]
fn boundary_partition_values() {
    let version = version_with(&store(), single_source("foo"), vec![partitioned(253)])
        .maximum_number_of_partitions(255);
    rejects(
        full_actions(),
        version,
        "Invalid maximumNumberOfPartitions specified, 255, must be 0 < maximumNumberOfPartitions <= 255.",
    );
    let version = version_with(&store(), single_source("foo"), vec![partitioned(253)])
        .maximum_number_of_partitions(254);
    let info = search_info(full_actions(), version).unwrap();
    assert_eq!(info.version.max_partitions, 254);
}

#[test]
fn beacon_names() {
    // An empty beacon name is rejected.
    let version = version_with(&store(), single_source("foo"), vec![standard("", 24, None)]);
    let actions: HashMap<String, CryptoAction> =
        [(String::new(), CryptoAction::EncryptAndSign)].into();
    assert_eq!(
        val_msg(search_info(actions, version)),
        "a beacon or virtual field path must not be empty"
    );

    // A long name is accepted.
    let long = "a".repeat(80);
    let beacon = StandardBeacon::builder()
        .name(long.clone())
        .bits(24)
        .number_of_partitions(3)
        .build()
        .unwrap();
    let version =
        version_with(&store(), single_source("foo"), vec![beacon]).maximum_number_of_partitions(10);
    let actions: HashMap<String, CryptoAction> =
        [(long.clone(), CryptoAction::EncryptAndSign)].into();
    let info = search_info(actions, version).unwrap();
    assert_eq!(
        info.version.beacons[&long].beacon_name(),
        format!("aws_dbe_b_{long}")
    );
}
