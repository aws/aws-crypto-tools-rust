// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests of the beacon values a checked beacon version computes for an item.
//! The vectors are from `Beacon.dfy`, computed with the beacon key `[1,2,3,4,5]`.

use super::*;
use crate::search::config::tests::{
    compound, convert_with, encrypted_part, fake_key_store, lotsa_beacons, multi_source,
    simple_item, standard, styled, table_with, validation_message, year,
};
use crate::search::config::{BeaconStyle, BeaconVersionBuilder};
use crate::types::CryptoAction;

// Beacon values of `SimpleItem` under the beacon key `[1,2,3,4,5]`, from BeaconTestFixtures.dfy.
const STD2_BEACON: &str = "ac6f5d";
const NAME_BEACON: &str = "7d9bfa40";
const TITLE_BEACON: &str = "e4feb833";
const STD4_BEACON: &str = "0e9064";
const STD6_BEACON: &str = "2d99222";
const NAME_TITLE_BEACON: &str = "4c577d7";

fn s(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_owned())
}

fn item(pairs: &[(&str, AttributeValue)]) -> Item {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), v.clone()))
        .collect()
}

fn strings(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

/// The encrypted beacons of `SimpleItem` under `GetLotsaBeacons`, from `TestBeaconValues`.
fn expected_encrypted_beacons() -> Item {
    item(&[
        ("aws_dbe_b_Mixed", s(&format!("N_{NAME_BEACON}.Y_1984"))),
        ("aws_dbe_b_Name", s(NAME_BEACON)),
        (
            "aws_dbe_b_NameTitle",
            s(&format!("N_{NAME_BEACON}.T_{TITLE_BEACON}")),
        ),
        ("aws_dbe_b_NameTitleField", s(NAME_TITLE_BEACON)),
        ("aws_dbe_b_std2", s(STD2_BEACON)),
        ("aws_dbe_b_Title", s(TITLE_BEACON)),
        ("aws_dbe_b_std6", s(STD6_BEACON)),
        ("aws_dbe_b_std4", s(STD4_BEACON)),
        ("aws_dbe_b_YearName", s(&format!("Y_1984.N_{NAME_BEACON}"))),
    ])
}

fn convert_version(version: BeaconVersionBuilder) -> BeaconVersionInfo {
    convert_with(&[], version).unwrap().version
}

#[tokio::test]
async fn beacon_values() {
    let (store, requested) = fake_key_store();
    let bv = convert_version(lotsa_beacons(store));

    let signed = bv.generate_signed_beacons(&simple_item(), 0).unwrap();
    assert_eq!(signed, item(&[("JustSigned", s("Y_1984.M_May"))]));

    let encrypted = bv
        .generate_encrypted_beacons(&simple_item(), &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_eq!(encrypted, expected_encrypted_beacons());
    // The single key store's key id.
    assert_eq!(*requested.lock().unwrap(), ["foo"]);

    // A changed value changes only the beacons computed from it.
    let mut changed = simple_item();
    changed.insert("std4".to_owned(), s("abd"));
    let changed = bv
        .generate_encrypted_beacons(&changed, &MaybeKeyId::DontUse, 0)
        .await
        .unwrap();
    assert_ne!(changed["aws_dbe_b_std4"], s(STD4_BEACON));
    let mut rest = changed;
    rest.remove("aws_dbe_b_std4");
    let mut expected = expected_encrypted_beacons();
    expected.remove("aws_dbe_b_std4");
    assert_eq!(rest, expected);
}

#[tokio::test]
async fn an_item_without_the_fields_has_no_beacons() {
    let (store, _) = fake_key_store();
    let bv = convert_version(lotsa_beacons(store));
    let empty = Item::new();
    assert!(bv.generate_signed_beacons(&empty, 0).unwrap().is_empty());
    assert!(
        bv.generate_encrypted_beacons(&empty, &MaybeKeyId::DontUse, 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(bv.generate_plain_beacons(&empty, 0).unwrap().is_empty());
    assert!(bv.virtual_field_values(&empty).unwrap().is_empty());
    assert!(bv.compound_beacon_values(&empty, 0).unwrap().is_empty());
}

#[tokio::test]
async fn plain_values() {
    let (store, requested) = fake_key_store();
    let bv = convert_version(lotsa_beacons(store));
    let item_ = simple_item();

    // The plaintext each beacon is computed from, by beacon attribute name.
    assert_eq!(
        bv.generate_plain_beacons(&item_, 0).unwrap(),
        item(&[
            ("JustSigned", s("Y_1984.M_May")),
            ("aws_dbe_b_Mixed", s("N_MyName.Y_1984")),
            ("aws_dbe_b_Name", s("MyName")),
            ("aws_dbe_b_NameTitle", s("N_MyName.T_MyTitle")),
            ("aws_dbe_b_NameTitleField", s("MyName__mytitle")),
            ("aws_dbe_b_Title", s("MyTitle")),
            ("aws_dbe_b_YearName", s("Y_1984.N_MyName")),
            ("aws_dbe_b_std2", AttributeValue::N("1.23".to_owned())),
            ("aws_dbe_b_std4", s("abc")),
            ("aws_dbe_b_std6", s("666")),
        ])
    );
    assert_eq!(
        bv.virtual_field_values(&item_).unwrap(),
        strings(&[("NameTitleField", "MyName__mytitle")])
    );
    assert_eq!(
        bv.compound_beacon_values(&item_, 0).unwrap(),
        strings(&[
            ("JustSigned", "Y_1984.M_May"),
            ("Mixed", "N_MyName.Y_1984"),
            ("NameTitle", "N_MyName.T_MyTitle"),
            ("YearName", "Y_1984.N_MyName"),
        ])
    );
    // Plaintext values need no beacon key.
    assert!(requested.lock().unwrap().is_empty());
}

#[tokio::test]
async fn part_only_beacon_is_not_stored() {
    // TestPartOnlyNotStored.
    let my_item = item(&[("std2", s("abc")), ("partOnly", s("def"))]);
    let compound_part = compound(
        "compoundPart",
        Some(vec![encrypted_part("partOnly", "S_")]),
        None,
        None,
    );
    let with_part = |part_beacon| {
        let (store, _) = fake_key_store();
        let version = lotsa_beacons(store)
            .standard_beacons(part_beacon)
            .compound_beacons(compound_part.clone());
        convert_with(&[("partOnly", CryptoAction::EncryptAndSign)], version)
            .unwrap()
            .version
    };

    let bv = with_part(standard("partOnly", 23, None));
    assert_eq!(
        bv.generate_encrypted_beacons(&my_item, &MaybeKeyId::DontUse, 0)
            .await
            .unwrap(),
        item(&[
            ("aws_dbe_b_std2", s("51e1da")),
            ("aws_dbe_b_partOnly", s("405a51")),
            ("aws_dbe_b_compoundPart", s("S_405a51")),
        ])
    );

    let bv = with_part(styled("partOnly", 23, BeaconStyle::part_only()));
    assert!(bv.beacons["partOnly"].is_part_only());

    //= spec/searchable-encryption/beacons.md#partonly-initialization
    //= type=test
    //# The Standard Beacon MUST NOT be stored in the item for a PartOnly beacon.
    assert_eq!(
        bv.generate_encrypted_beacons(&my_item, &MaybeKeyId::DontUse, 0)
            .await
            .unwrap(),
        item(&[
            ("aws_dbe_b_std2", s("51e1da")),
            ("aws_dbe_b_compoundPart", s("S_405a51")),
        ])
    );
    let plain = bv.generate_plain_beacons(&my_item, 0).unwrap();
    assert!(!plain.contains_key("aws_dbe_b_partOnly"));
    assert_eq!(plain["aws_dbe_b_compoundPart"], s("S_def"));
}

#[tokio::test]
async fn multi_key_store_uses_the_item_key_id() {
    let (store, requested) = fake_key_store();
    let bv = convert_version(lotsa_beacons(store).key_source(multi_source("TheKeyField")));

    let encrypted = bv
        .generate_encrypted_beacons(&simple_item(), &MaybeKeyId::Id("bk-1".to_owned()), 0)
        .await
        .unwrap();
    // The fake key store returns the same beacon key for every id.
    assert_eq!(encrypted, expected_encrypted_beacons());
    assert_eq!(*requested.lock().unwrap(), ["bk-1"]);

    assert!(matches!(
        bv.get_key_map(&MaybeKeyId::ShouldHave).await.unwrap(),
        MaybeKeyMap::ShouldHaveKeys
    ));
    assert_eq!(
        validation_message(
            bv.generate_encrypted_beacons(&simple_item(), &MaybeKeyId::DontUse, 0)
                .await
        ),
        "Fixed KeyID must not be supplied with a MultiKeyStore"
    );
}

#[tokio::test]
async fn single_key_store_takes_no_key_id() {
    let (store, requested) = fake_key_store();
    let bv = convert_version(lotsa_beacons(store));
    assert_eq!(
        validation_message(
            bv.generate_encrypted_beacons(&simple_item(), &MaybeKeyId::Id("x".to_owned()), 0)
                .await
        ),
        "KeyID should not be supplied with a SingleKeyStore"
    );
    assert!(requested.lock().unwrap().is_empty());

    let MaybeKeyMap::Keys(keys) = bv.get_key_map(&MaybeKeyId::DontUse).await.unwrap() else {
        panic!("no keys");
    };
    // One 64-byte HMAC key per standard beacon.
    let names: Vec<&str> = keys.keys().map(String::as_str).collect();
    assert_eq!(names, bv.standard_names);
    assert!(keys.values().all(|k| k.len() == 64));
}

#[tokio::test]
async fn signed_beacon_name_must_not_be_configured() {
    // A fully signed compound beacon `name`, on a table with `extra` actions and unauthenticated settings.
    let case = |name: &str,
                extra: &[(&str, CryptoAction)],
                unsigned: Option<&str>,
                unsigned_prefix: Option<&str>| {
        let (store, _) = fake_key_store();
        let version = lotsa_beacons(store)
            .compound_beacons(compound(name, None, Some(vec![year()]), None))
            .build()
            .unwrap();
        let mut table = table_with(extra, version);
        table.builder = table
            .builder
            .set_allowed_unsigned_attributes(unsigned.map(|u| vec![u.to_owned()]))
            .set_allowed_unsigned_attribute_prefix(unsigned_prefix.map(str::to_owned));
        validation_message(table.convert())
    };
    let cases = [
        (
            case("Sig", &[("Sig", CryptoAction::SignOnly)], None, None),
            "Sig not allowed as a CompoundBeacon because it is already an unencrypted attribute.",
        ),
        (
            case("Sig", &[("Sig", CryptoAction::EncryptAndSign)], None, None),
            "Sig not allowed as a CompoundBeacon because a fully signed beacon cannot have the same name as an existing attribute.",
        ),
        (
            case("Sig", &[], Some("Sig"), None),
            "Sig not allowed as a CompoundBeacon because it is already an allowed unauthenticated attribute.",
        ),
        (
            case("un_Sig", &[], None, Some("un_")),
            "un_Sig not allowed as a CompoundBeacon because it begins with the allowed unauthenticated prefix.",
        ),
    ];
    for (got, want) in cases {
        //= spec/searchable-encryption/beacons.md#signed-beacons
        //= type=test
        //# Initialization MUST fail if `NAME` is explicitly configured with an
        //# [attribute actions](../dynamodb-encryption-client/ddb-item-encryptor.md#attribute-actions) or
        //# [unauthenticated attributes](../dynamodb-encryption-client/ddb-item-encryptor.md#unauthenticated-attributes),
        //# or begins with the [unauthenticated attribute prefix](../dynamodb-encryption-client/ddb-item-encryptor.md#unauthenticated-attribute-prefix).
        assert_eq!(got, want);
    }
}

#[tokio::test]
async fn signed_beacon_is_written_sign_only() {
    use aws_crypto_mpl::aws_sdk_dynamodb::operation::get_item::{GetItemInput, GetItemOutput};
    use aws_crypto_mpl::aws_sdk_dynamodb::operation::put_item::PutItemInput;

    let (store, _) = fake_key_store();
    let table = table_with(
        &[("foo", CryptoAction::SignOnly)],
        lotsa_beacons(store).build().unwrap(),
    )
    .builder
    .build()
    .unwrap();
    let transforms = crate::transforms::Transforms::builder()
        .table_encryption_configs("Foo", table)
        .build()
        .unwrap();
    let mut plaintext = simple_item();
    plaintext.insert("foo".to_owned(), s("pk"));
    let written = transforms
        .put_item_input(
            PutItemInput::builder()
                .table_name("Foo")
                .set_item(Some(plaintext))
                .build()
                .unwrap(),
        )
        .await
        .unwrap()
        .item
        .unwrap();
    // JustSigned is written in plaintext: it is not encrypted.
    assert_eq!(written["JustSigned"], s("Y_1984.M_May"));

    let read = |item: Item| {
        let transforms = transforms.clone();
        async move {
            transforms
                .get_item_output(
                    GetItemOutput::builder().set_item(Some(item)).build(),
                    &GetItemInput::builder()
                        .table_name("Foo")
                        .set_key(Some(HashMap::new()))
                        .build()
                        .unwrap(),
                )
                .await
        }
    };
    let untouched = read(written.clone()).await.unwrap().item.unwrap();
    assert_eq!(untouched["JustSigned"], s("Y_1984.M_May"));

    let mut tampered = written;
    tampered.insert("JustSigned".to_owned(), s("Y_1985.M_May"));
    let err = read(tampered).await.unwrap_err();

    //= spec/searchable-encryption/beacons.md#signed-beacons
    //= type=test
    //= reason=JustSigned is written in plaintext, yet changing it fails signature verification
    //# `NAME` MUST be automatically configured with an attribute action of SIGN_ONLY.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}
