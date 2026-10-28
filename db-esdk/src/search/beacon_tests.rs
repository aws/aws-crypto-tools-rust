// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests ported from the reference implementation's `Beacon.dfy` and `BeaconPartition.dfy`.

use aws_smithy_types::Blob;

use super::*;
use crate::ddb::Item;
use crate::search::config::{BeaconStyle, StandardBeacon};
use crate::search::filter::ExprContext;
use crate::search::info::SearchInfo;
use crate::search::term_loc::TermLoc;
use crate::search::test_fixtures::*;

fn std_info(name: &str, length: u8, partitions: u8) -> StandardInfo {
    StandardInfo {
        name: name.to_owned(),
        beacon_name: format!("aws_dbe_b_{name}"),
        length,
        loc: TermLoc::attribute(name),
        part_only: false,
        as_set: false,
        share: None,
        number_of_partitions: partitions,
    }
}

/// The reference's `GetBeaconValue`: the beacon of string `value` for beacon `name`.
fn beacon_value(name: &str, value: &str, length: u8) -> String {
    let keys = hmac_keys(&[name], &BEACON_KEY);
    std_info(name, length, 1).hash_str(value, &keys, 0).unwrap()
}

fn values(pairs: &[(&str, AttributeValue)]) -> HashMap<String, AttributeValue> {
    item(pairs)
}

fn filter(expr: &str, vals: HashMap<String, AttributeValue>) -> ExprContext {
    ExprContext {
        key_expr: None,
        filter_expr: Some(expr.to_owned()),
        values: Some(vals),
        names: None,
    }
}

async fn beaconize(info: &SearchInfo, ctx: &ExprContext) -> Result<ExprContext, Error> {
    info.version.beaconize(ctx, &MaybeKeyId::DontUse, 0).await
}

async fn encrypted(info: &SearchInfo, item: &Item, partition: u8) -> Result<Item, Error> {
    info.version
        .generate_encrypted_beacons(item, &MaybeKeyId::DontUse, partition)
        .await
}

#[test]
fn hmac_and_partitioned_hash() {
    let b = std_info("foo", 8, 5);
    let key = [1, 2];
    assert_eq!(
        basic_hash(&[1, 2, 3], &key, 64).unwrap(),
        "2793938b26e9527e"
    );
    assert_eq!(b.hash(&[1, 2, 3], &key, 0).unwrap(), "7e");
    assert_eq!(
        basic_hash(&[1, 2, 3, 1], &key, 64).unwrap(),
        "2a64f214bc00211d"
    );
    assert_eq!(b.hash(&[1, 2, 3], &key, 1).unwrap(), "1d");
    assert_eq!(
        basic_hash(&[1, 2, 3, 2], &key, 64).unwrap(),
        "359790223113a9ef"
    );
    assert_eq!(b.hash(&[1, 2, 3], &key, 2).unwrap(), "ef");
    assert_eq!(basic_hash(&[], &key, 8).unwrap(), "80");
    assert_eq!(b.hash(&[], &key, 0).unwrap(), "80");
    assert_eq!(basic_hash(b"123", &key, 8).unwrap(), "61");
}

#[test]
fn partition_is_constrained_to_the_beacons_partitions() {
    let key = [1, 2];
    // Partition 6 of a 5-partition beacon is partition 1.
    assert_eq!(
        std_info("foo", 8, 5).hash(&[1, 2, 3], &key, 6).unwrap(),
        "1d"
    );
    // Partition 5 of a 5-partition beacon is partition 0, which appends no byte.
    assert_eq!(
        std_info("foo", 8, 5).hash(&[1, 2, 3], &key, 5).unwrap(),
        "7e"
    );
}

#[test]
fn bytes_to_hex_truncates_to_the_rightmost_bits() {
    let bytes = [1, 2, 3, 4, 5, 6, 7, 0xb7];
    let expected = ["1", "3", "7", "7", "17", "37", "37", "b7"];
    for (bits, want) in (1..=8).zip(expected) {
        assert_eq!(bytes_to_hex(bytes, bits), want, "bits {bits}");
    }
    assert_eq!(bytes_to_hex(bytes, 9), "1b7");
    assert_eq!(bytes_to_hex(bytes, 12), "7b7");
    assert_eq!(bytes_to_hex(bytes, 64), "01020304050607b7");
}

#[test]
fn one_beacon_value() {
    assert_eq!(beacon_value("std2", "1.23", 24), STD2_BEACON);
    assert_eq!(beacon_value("Name", "MyName", 32), NAME_BEACON);
    assert_eq!(beacon_value("Title", "MyTitle", 32), TITLE_BEACON);
    assert_eq!(beacon_value("std4", "abc", 24), STD4_BEACON);
    assert_eq!(beacon_value("std6", "666", 26), STD6_BEACON);
    assert_eq!(
        beacon_value("NameTitleField", "MyName__mytitle", 28),
        NAME_TITLE_BEACON
    );
    assert_eq!(beacon_value("Name", "", 32), EMPTY_NAME_BEACON);
    assert_eq!(beacon_value("Title", "", 32), EMPTY_TITLE_BEACON);
}

#[test]
fn spec_beacon_fixture_matches_reference_vectors() {
    assert_eq!(spec_beacon("Name", b"MyName", 32), NAME_BEACON);
    assert_eq!(spec_beacon("std2", b"1.23", 24), STD2_BEACON);
}

#[test]
fn hash_str_without_a_key_fails() {
    let keys = hmac_keys(&["other"], &BEACON_KEY);
    let err = std_info("Name", 32, 1).hash_str("x", &keys, 0);
    assert_eq!(val_msg(err), "no HMAC key for beacon Name");
}

#[test]
fn shared_beacon_uses_the_other_beacons_key() {
    let mut b = std_info("partOnly", 24, 1);
    b.share = Some("std2".to_owned());
    assert_eq!(b.key_name(), "std2");
    let keys = hmac_keys(&["std2"], &BEACON_KEY);
    assert_eq!(b.hash_str("abc", &keys, 0).unwrap(), "51e1da");
}

#[tokio::test]
async fn beacon_values() {
    let info = lotsa_info();
    let signed = info
        .version
        .generate_signed_beacons(&simple_item(), 0)
        .unwrap();
    assert_eq!(signed, item(&[("JustSigned", s("Y_1984.M_May"))]));
    let attrs = encrypted(&info, &simple_item(), 0).await.unwrap();
    let expected = item(&[
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
    ]);
    assert_eq!(attrs, expected);
}

#[tokio::test]
async fn plain_beacons_are_the_unhashed_values() {
    let info = lotsa_info();
    let plain = info
        .version
        .generate_plain_beacons(&simple_item(), 0)
        .unwrap();
    assert_eq!(plain["aws_dbe_b_Mixed"], s("N_MyName.Y_1984"));
    assert_eq!(plain["aws_dbe_b_NameTitle"], s("N_MyName.T_MyTitle"));
    assert_eq!(plain["aws_dbe_b_NameTitleField"], s("MyName__mytitle"));
    assert_eq!(plain["aws_dbe_b_std2"], n("1.23"));
    assert_eq!(plain["aws_dbe_b_std6"], s("666"));
    assert_eq!(plain["JustSigned"], s("Y_1984.M_May"));
}

#[tokio::test]
async fn numbers_normalize() {
    let info = lotsa_info();
    let mut odd = simple_item();
    odd.insert("std2".to_owned(), n("000001.23000000"));
    let attrs = encrypted(&info, &odd, 0).await.unwrap();
    assert_eq!(attrs["aws_dbe_b_std2"], s(STD2_BEACON));
}

#[tokio::test]
async fn compound_part_containing_split_fails() {
    let info = lotsa_info();
    let mut bad = simple_item();
    bad.insert("Name".to_owned(), s("A.B"));
    let err = encrypted(&info, &bad, 0).await;
    assert_eq!(
        val_msg(err),
        "Part Name for beacon Mixed has value 'A.B' which contains the split character .'."
    );
}

#[tokio::test]
async fn compound_queries() {
    let info = lotsa_info();
    let expect_ok = [
        ("N_MyName.Y_1984", format!("N_{NAME_BEACON}.Y_1984")),
        ("N_MyName", format!("N_{NAME_BEACON}")),
        ("Y_1984", "Y_1984".to_owned()),
        ("M_bar", "M_bar".to_owned()),
    ];
    for (value, want) in expect_ok {
        let ctx = filter("Mixed = :mixed", values(&[(":mixed", s(value))]));
        let out = beaconize(&info, &ctx).await.unwrap();
        assert_eq!(out.values.unwrap()[":mixed"], s(&want), "{value}");
    }
    // Title parts hash: `T_` and 8 hex digits, the signed part unchanged.
    let title_foo = format!("T_{}", spec_beacon("Title", b"foo", 32));
    for (value, want) in [
        ("T_foo", title_foo.clone()),
        ("T_foo.M_bar", format!("{title_foo}.M_bar")),
    ] {
        let ctx = filter("Mixed = :mixed", values(&[(":mixed", s(value))]));
        let out = beaconize(&info, &ctx).await.unwrap();
        assert_eq!(out.values.unwrap()[":mixed"], s(&want), "{value}");
    }

    for (value, parsed) in [
        ("N_MyName.N_MyName", "N_N_"),
        ("Y_1984.N_MyName", "Y_N_"),
        ("M_bar.T_foo", "M_T_"),
    ] {
        let ctx = filter("Mixed = :mixed", values(&[(":mixed", s(value))]));
        let err = beaconize(&info, &ctx).await;
        assert_eq!(
            val_msg(err),
            format!(
                "Compound Beacon value '{value}' cannot be constructed from any available constructor for Mixed value parsed as {parsed} available constructors are N_Y_, T_[M_]."
            )
        );
    }
}

#[tokio::test]
async fn query_beacons() {
    let info = lotsa_info();
    let ctx = filter(
        "std2 = :std2 AND std4 = :std4 AND :std6 = std6 AND Name = :Name AND Mixed = :Mixed \
         AND :NameTitle = NameTitle AND NameTitle = :NameTitleN AND NameTitle = :NameTitleT AND NameTitle = :NameTitleTN \
         AND NameTitleField = :NameTitleField And Title = :Title AND YearName = :YearName",
        query_values(),
    );
    let out = beaconize(&info, &ctx).await.unwrap();
    assert_eq!(out.values, Some(expected_query_values()));
    assert_eq!(out.names, None);
}

fn query_values() -> HashMap<String, AttributeValue> {
    values(&[
        (":std2", n("1.23")),
        (":std4", s("abc")),
        (":std6", s("666")),
        (":Name", s("MyName")),
        (":Title", s("MyTitle")),
        (":Mixed", s("N_MyName.Y_1984")),
        (":NameTitle", s("N_MyName.T_MyTitle")),
        (":NameTitleN", s("N_MyName")),
        (":NameTitleT", s("T_MyTitle")),
        (":NameTitleTN", s("N_MyName.T_MyTitle")),
        (":NameTitleField", s("MyName__mytitle")),
        (":YearName", s("Y_1984.N_MyName")),
    ])
}

fn expected_query_values() -> HashMap<String, AttributeValue> {
    let nt = format!("N_{NAME_BEACON}.T_{TITLE_BEACON}");
    values(&[
        (":Mixed", s(&format!("N_{NAME_BEACON}.Y_1984"))),
        (":Name", s(NAME_BEACON)),
        (":NameTitle", s(&nt)),
        (":NameTitleTN", s(&nt)),
        (":NameTitleN", s(&format!("N_{NAME_BEACON}"))),
        (":NameTitleT", s(&format!("T_{TITLE_BEACON}"))),
        (":NameTitleField", s(NAME_TITLE_BEACON)),
        (":std2", s(STD2_BEACON)),
        (":Title", s(TITLE_BEACON)),
        (":std6", s(STD6_BEACON)),
        (":std4", s(STD4_BEACON)),
        (":YearName", s(&format!("Y_1984.N_{NAME_BEACON}"))),
    ])
}

#[tokio::test]
async fn query_mixed_table_beacon_partitions() {
    // std4 has 5 partitions of the table's 10; partition 0 adds no byte, so values match.
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let std4_partitioned = StandardBeacon::builder()
        .name("std4")
        .bits(24)
        .location("std4")
        .number_of_partitions(5)
        .build()
        .unwrap();
    let version = lotsa_with(&store, single_source("foo"))
        .set_standard_beacons(Some(vec![
            std2(),
            std4_partitioned,
            std6(),
            name_title_beacon(),
            name_b(),
            title_b(),
        ]))
        .maximum_number_of_partitions(10);
    let info = search_info(full_actions(), version).unwrap();
    let ctx = filter(
        "std2 = :std2 AND std4 = :std4 AND :std6 = std6 AND Name = :Name AND Mixed = :Mixed \
         AND :NameTitle = NameTitle AND NameTitle = :NameTitleN AND NameTitle = :NameTitleT AND NameTitle = :NameTitleTN \
         AND NameTitleField = :NameTitleField And Title = :Title AND YearName = :YearName",
        query_values(),
    );
    let out = beaconize(&info, &ctx).await.unwrap();
    assert_eq!(out.values, Some(expected_query_values()));
}

fn part_only_version(style: Option<BeaconStyle>) -> SearchInfo {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let part = StandardBeacon::builder()
        .name("partOnly")
        .bits(23)
        .set_style(style)
        .build()
        .unwrap();
    let mut std = vec![
        std2(),
        std4(),
        std6(),
        name_title_beacon(),
        name_b(),
        title_b(),
    ];
    std.push(part);
    let compound_part = compound(
        "compoundPart",
        vec![encrypted_part("partOnly", "S_")],
        vec![],
        None,
    );
    let version = lotsa_with(&store, single_source("foo"))
        .set_standard_beacons(Some(std))
        .set_compound_beacons(Some(vec![
            name_title(),
            year_name(),
            mixed(),
            just_signed(),
            compound_part,
        ]));
    search_info(actions_plus("partOnly"), version).unwrap()
}

#[tokio::test]
async fn part_only_not_stored() {
    let my_item = item(&[("std2", s("abc")), ("partOnly", s("def"))]);
    let ctx = filter("partOnly = :val", values(&[(":val", s("foo"))]));

    let info = part_only_version(None);
    let attrs = encrypted(&info, &my_item, 0).await.unwrap();
    assert_eq!(
        attrs,
        item(&[
            ("aws_dbe_b_std2", s("51e1da")),
            ("aws_dbe_b_partOnly", s("405a51")),
            ("aws_dbe_b_compoundPart", s("S_405a51")),
        ])
    );
    let out = beaconize(&info, &ctx).await.unwrap();
    assert_eq!(
        out.filter_expr.as_deref(),
        Some("aws_dbe_b_partOnly = :val")
    );

    let info = part_only_version(Some(BeaconStyle::part_only()));
    let attrs = encrypted(&info, &my_item, 0).await.unwrap();
    assert_eq!(
        attrs,
        item(&[
            ("aws_dbe_b_std2", s("51e1da")),
            ("aws_dbe_b_compoundPart", s("S_405a51")),
        ])
    );
    let err = beaconize(&info, &ctx).await;
    assert_eq!(
        val_msg(err),
        "Field partOnly is encrypted, and has a PartOnly beacon, and so can only be used as part of a compound beacon."
    );
}

fn with_extra(extra: StandardBeacon) -> SearchInfo {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let name = extra.name().to_owned();
    let mut std = vec![
        std2(),
        std4(),
        std6(),
        name_title_beacon(),
        name_b(),
        title_b(),
    ];
    std.push(extra);
    let version = lotsa_with(&store, single_source("foo")).set_standard_beacons(Some(std));
    search_info(actions_plus(&name), version).unwrap()
}

fn styled(name: &str, style: Option<BeaconStyle>) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(24)
        .set_style(style)
        .build()
        .unwrap()
}

#[tokio::test]
async fn share_same_beacon() {
    let my_item = item(&[("std2", s("abc")), ("partOnly", s("abc"))]);

    let info = with_extra(styled("partOnly", None));
    let attrs = encrypted(&info, &my_item, 0).await.unwrap();
    assert_eq!(
        attrs,
        item(&[
            ("aws_dbe_b_std2", s("51e1da")),
            ("aws_dbe_b_partOnly", s("928d9b")),
        ])
    );

    let info = with_extra(styled("partOnly", Some(BeaconStyle::shared("std2"))));
    let attrs = encrypted(&info, &my_item, 0).await.unwrap();
    assert_eq!(
        attrs,
        item(&[
            ("aws_dbe_b_std2", s("51e1da")),
            ("aws_dbe_b_partOnly", s("51e1da")),
        ])
    );
    let ctx = filter(
        "partOnly = :pVal AND std2 = :sVal",
        values(&[(":pVal", s("foo")), (":sVal", s("foo"))]),
    );
    let out = beaconize(&info, &ctx).await.unwrap();
    assert_eq!(
        out.values,
        Some(values(&[(":pVal", s("4379a7")), (":sVal", s("4379a7"))]))
    );
}

fn ss(v: &[&str]) -> AttributeValue {
    AttributeValue::Ss(v.iter().map(|x| (*x).to_owned()).collect())
}

#[tokio::test]
async fn beacon_set_query() {
    let info = with_extra(styled("setAttr", Some(BeaconStyle::as_set())));
    let ctx = filter(
        "setAttr = :setVal",
        values(&[(":setVal", ss(&["abc", "def", "ghi"]))]),
    );
    let out = beaconize(&info, &ctx).await.unwrap();
    assert_eq!(
        out.values,
        Some(values(&[(":setVal", ss(&["43c4d8", "2f3278", "f1972e"]))]))
    );

    // A scalar compared to a set beacon is hashed as one element.
    let ctx = filter("setAttr = :setVal", values(&[(":setVal", s("abc"))]));
    let out = beaconize(&info, &ctx).await.unwrap();
    assert_eq!(out.values, Some(values(&[(":setVal", s("43c4d8"))])));

    let ctx = filter(
        "setAttr = :setVal",
        values(&[(":setVal", AttributeValue::L(vec![]))]),
    );
    let err = beaconize(&info, &ctx).await;
    assert_eq!(
        val_msg(err),
        "Beacon setAttr has style AsSet, but attribute has type L."
    );
}

#[tokio::test]
async fn set_not_set() {
    let info = with_extra(styled("partOnly", Some(BeaconStyle::as_set())));
    let my_item = item(&[("std2", s("abc")), ("partOnly", ss(&["abc", "def", "ghi"]))]);
    let attrs = encrypted(&info, &my_item, 0).await.unwrap();
    assert_eq!(
        attrs,
        item(&[
            ("aws_dbe_b_std2", s("51e1da")),
            ("aws_dbe_b_partOnly", ss(&["928d9b", "405a51", "9c6c2e"])),
        ])
    );

    let bad = item(&[("std2", s("abc")), ("partOnly", s("abc"))]);
    let err = encrypted(&info, &bad, 0).await;
    assert_eq!(
        val_msg(err),
        "Beacon partOnly has style AsSet, but attribute has type S."
    );
}

#[tokio::test]
async fn set_beacon_removes_duplicate_values() {
    let info = with_extra(styled("nums", Some(BeaconStyle::as_set())));
    // "1" and "1.0" normalize to the same number, so they have the same beacon.
    let my_item = item(&[(
        "nums",
        AttributeValue::Ns(vec!["1".to_owned(), "1.0".to_owned(), "2".to_owned()]),
    )]);
    let attrs = encrypted(&info, &my_item, 0).await.unwrap();
    let AttributeValue::Ss(set) = &attrs["aws_dbe_b_nums"] else {
        panic!("expected a string set, got {attrs:?}");
    };
    assert_eq!(set.len(), 2);
    assert_ne!(set[0], set[1]);

    let bins = item(&[(
        "nums",
        AttributeValue::Bs(vec![Blob::new(vec![1]), Blob::new(vec![2])]),
    )]);
    let attrs = encrypted(&info, &bins, 0).await.unwrap();
    assert!(matches!(&attrs["aws_dbe_b_nums"], AttributeValue::Ss(v) if v.len() == 2));
}

#[tokio::test]
async fn shared_set() {
    let info = with_extra(styled("partOnly", Some(BeaconStyle::shared_set("std2"))));
    let my_item = item(&[("std2", s("abc")), ("partOnly", ss(&["abc", "def", "ghi"]))]);
    let attrs = encrypted(&info, &my_item, 0).await.unwrap();
    assert_eq!(
        attrs,
        item(&[
            ("aws_dbe_b_std2", s("51e1da")),
            ("aws_dbe_b_partOnly", ss(&["51e1da", "39ef85", "3ff06a"])),
        ])
    );
}

#[tokio::test]
async fn contains_with_a_set_value_hashes_each_element() {
    let info = lotsa_info();
    let b = &info.version.beacons["std4"];
    let keys = info
        .version
        .get_key_map(&MaybeKeyId::DontUse)
        .await
        .unwrap();
    let out = b
        .get_beacon_value(&ss(&["abc"]), &keys, true, true, 0)
        .unwrap();
    assert_eq!(out, ss(&[STD4_BEACON]));
    let out = b.get_beacon_value(&s("abc"), &keys, true, true, 0).unwrap();
    assert_eq!(out, s(STD4_BEACON));
}

#[tokio::test]
async fn beacon_value_without_keys() {
    let info = lotsa_info();
    let std = &info.version.beacons["std2"];
    let cmp = &info.version.beacons["NameTitle"];

    // No keys: the value is compared as-is.
    let out = std
        .get_beacon_value(&s("x"), &MaybeKeyMap::DontUseKeys, true, false, 0)
        .unwrap();
    assert_eq!(out, s("x"));

    let err = std.get_beacon_value(&s("x"), &MaybeKeyMap::ShouldHaveKeys, true, false, 0);
    assert_eq!(
        val_msg(err),
        "Need KeyId because of beacon std2 but no KeyId found in query"
    );
    let err = cmp.get_beacon_value(&s("N_MyName"), &MaybeKeyMap::ShouldHaveKeys, true, false, 0);
    assert_eq!(
        val_msg(err),
        "Need KeyId for beacon Name but no KeyId found in query."
    );
    // A signed-only value needs no key.
    let cmp = &info.version.beacons["YearName"];
    let out = cmp
        .get_beacon_value(&s("Y_1984"), &MaybeKeyMap::ShouldHaveKeys, true, false, 0)
        .unwrap();
    assert_eq!(out, s("Y_1984"));

    let empty = MaybeKeyMap::Keys(HmacKeyMap::new());
    let err = std.get_beacon_value(&s("x"), &empty, true, false, 0);
    assert_eq!(val_msg(err), "Internal error. Beacon std2 has no key.");
}

#[tokio::test]
async fn item_beacon_without_keys() {
    let info = lotsa_info();
    let vf = &info.version.virtual_fields;
    let std = &info.version.beacons["std2"];
    let err = std.attr_hash(&simple_item(), vf, &MaybeKeyMap::ShouldHaveKeys, 0);
    assert_eq!(
        val_msg(err),
        "Need key for beacon std2 but no keyId found in query."
    );
    let empty = MaybeKeyMap::Keys(HmacKeyMap::new());
    let err = std.attr_hash(&simple_item(), vf, &empty, 0);
    assert_eq!(val_msg(err), "Internal error. Beacon std2 has no key!");
    // An item without the field has no beacon.
    let none = std
        .attr_hash(&item(&[]), vf, &MaybeKeyMap::DontUseKeys, 0)
        .unwrap();
    assert_eq!(none, None);
}

#[tokio::test]
async fn compound_query_value_errors() {
    let info = lotsa_info();
    let keys = info
        .version
        .get_key_map(&MaybeKeyId::DontUse)
        .await
        .unwrap();
    let cmp = &info.version.beacons["NameTitle"];

    let err = cmp.get_beacon_value(&n("1"), &keys, true, false, 0);
    assert_eq!(
        val_msg(err),
        "CompoundBeacon NameTitle can only be queried as a string, not as N"
    );
    let err = cmp.get_beacon_value(&s("X_1"), &keys, true, false, 0);
    assert_eq!(
        val_msg(err),
        "Value X_1 for beacon NameTitle does not match the prefix of any configured part."
    );

    // For a prefix query, a trailing bare prefix is kept as-is.
    let out = cmp
        .get_beacon_value(&s("N_MyName.T_"), &keys, false, false, 0)
        .unwrap();
    assert_eq!(out, s(&format!("N_{NAME_BEACON}.T_")));
    // For equality, the empty title is hashed.
    let out = cmp
        .get_beacon_value(&s("N_MyName.T_"), &keys, true, false, 0)
        .unwrap();
    assert_eq!(out, s(&format!("N_{NAME_BEACON}.T_{EMPTY_TITLE_BEACON}")));
}

#[test]
fn part_value_with_split_fails() {
    let info = lotsa_info();
    let Beacon::Compound(cmp) = &info.version.beacons["NameTitle"] else {
        panic!("NameTitle is a compound beacon");
    };
    let part = &cmp.parts[0];
    let err = cmp.part_value_calc("a.b", &MaybeKeyMap::DontUseKeys, part, 0);
    assert_eq!(
        val_msg(err),
        "Value 'a.b' for beacon part Name contains the split character '.'."
    );
}

#[test]
fn less_than_comparable() {
    let info = lotsa_info();
    let Beacon::Compound(cmp) = &info.version.beacons["Mixed"] else {
        panic!("Mixed is a compound beacon");
    };
    // Signed pieces, then at most one encrypted piece that is only its prefix.
    assert!(cmp.is_less_than_comparable(&[]).unwrap());
    assert!(cmp.is_less_than_comparable(&["Y_1984", "M_May"]).unwrap());
    assert!(cmp.is_less_than_comparable(&["Y_1984", "N_"]).unwrap());
    assert!(!cmp.is_less_than_comparable(&["Y_1984", "N_x"]).unwrap());
    assert!(!cmp.is_less_than_comparable(&["N_", "T_"]).unwrap());
    let err = cmp.is_less_than_comparable(&["Q_1"]);
    assert_eq!(
        val_msg(err),
        "Value Q_1 for beacon Mixed does not match the prefix of any configured part."
    );
}

#[test]
fn lcm() {
    assert_eq!(lcm_partition(1, 5, 10), 5);
    assert_eq!(lcm_partition(5, 1, 10), 5);
    assert_eq!(lcm_partition(3, 3, 10), 3);
    assert_eq!(lcm_partition(3, 5, 16), 15);
    assert_eq!(lcm_partition(3, 5, 6), 6);
    assert_eq!(lcm_partition(4, 6, 20), 12);
    assert_eq!(lcm_partition(3, 10, 10), 10);
    assert_eq!(lcm_partition(10, 3, 10), 10);
    assert_eq!(lcm_seq([1, 3, 5, 3], 16), 15);
    assert_eq!(lcm_seq([], 16), 1);
    assert_eq!(lcm_seq([2, 3, 5], 16), 16);
}

fn partitioned(name: &str, bits: u8, partitions: u8) -> StandardBeacon {
    StandardBeacon::builder()
        .name(name)
        .bits(bits)
        .number_of_partitions(partitions)
        .build()
        .unwrap()
}

#[test]
fn number_of_queries() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let cases = [
        (vec![std2()], None, 1),
        (vec![partitioned("std2", 24, 5)], Some(6), 5),
        (vec![partitioned("std2", 24, 25)], Some(26), 25),
        (vec![partitioned("std2", 24, 64)], Some(128), 64),
    ];
    let vals = values(&[(":std2", n("1.23"))]);
    for (std, max, want) in cases {
        let version =
            version_with(&store, single_source("foo"), std).set_maximum_number_of_partitions(max);
        let info = search_info(full_actions(), version).unwrap();
        let got = info
            .version
            .get_num_queries(Some("std2 = :std2"), Some(&vals))
            .unwrap();
        assert_eq!(got, want, "max {max:?}");
    }
}

#[test]
fn number_of_queries_with_multiple_beacons() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let std4_partitioned = StandardBeacon::builder()
        .name("std4")
        .bits(24)
        .location("std4")
        .number_of_partitions(5)
        .build()
        .unwrap();
    let vals = values(&[(":std4", s("abc")), (":std2", n("1.23"))]);
    for (max, want) in [(16, 15), (6, 6)] {
        let version = version_with(
            &store,
            single_source("foo"),
            vec![partitioned("std2", 24, 3), std4_partitioned.clone()],
        )
        .maximum_number_of_partitions(max);
        let info = search_info(full_actions(), version).unwrap();
        let got = info
            .version
            .get_num_queries(Some("std4 = :std4 AND std2 = :std2"), Some(&vals))
            .unwrap();
        assert_eq!(got, want, "max {max}");
    }
}

#[test]
fn number_of_queries_for_compound_beacons() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let version = version_with(
        &store,
        single_source("foo"),
        vec![partitioned("Name", 32, 3), partitioned("Title", 32, 5)],
    )
    .set_compound_beacons(Some(vec![name_title()]))
    .maximum_number_of_partitions(16);
    let info = search_info(full_actions(), version).unwrap();
    for (value, want) in [("N_MyName.T_MyTitle", 15), ("N_MyName", 3)] {
        let vals = values(&[(":nt", s(value))]);
        let got = info
            .version
            .get_num_queries(Some("NameTitle = :nt"), Some(&vals))
            .unwrap();
        assert_eq!(got, want, "{value}");
    }
    // A value no constructor builds takes one query.
    assert_eq!(info.version.beacons["NameTitle"].num_queries(16, "X_1"), 1);
}

#[test]
fn default_partition_inheritance() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let version = version_with(&store, single_source("foo"), vec![std2()])
        .maximum_number_of_partitions(10)
        .default_number_of_partitions(3);
    let info = search_info(full_actions(), version).unwrap();
    let vals = values(&[(":std2", n("1.23"))]);
    let got = info
        .version
        .get_num_queries(Some("std2 = :std2"), Some(&vals))
        .unwrap();
    assert_eq!(got, 3);
}

#[tokio::test]
async fn beacon_partition_encoding() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let version = lotsa_with(&store, single_source("foo"))
        .maximum_number_of_partitions(10)
        .default_number_of_partitions(5);
    let info = search_info(full_actions(), version).unwrap();
    let attrs0 = encrypted(&info, &simple_item(), 0).await.unwrap();
    let attrs1 = encrypted(&info, &simple_item(), 1).await.unwrap();
    // Partition 0 appends no byte, so it matches the unpartitioned beacon.
    assert_eq!(attrs0["aws_dbe_b_Name"], s(NAME_BEACON));
    assert_ne!(attrs1["aws_dbe_b_Name"], attrs0["aws_dbe_b_Name"]);
    // Partition 6 of a 5-partition beacon is partition 1.
    let attrs6 = encrypted(&info, &simple_item(), 6).await.unwrap();
    assert_eq!(attrs6["aws_dbe_b_Name"], attrs1["aws_dbe_b_Name"]);
}

#[tokio::test]
async fn unicode_and_empty_values() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let cafe = "caf\u{e9}";
    let version = version_with(&store, single_source("foo"), vec![standard(cafe, 24, None)]);
    let mut actions = HashMap::new();
    actions.insert(cafe.to_owned(), crate::types::CryptoAction::EncryptAndSign);
    let info = search_info(actions, version).unwrap();
    let attrs = encrypted(&info, &item(&[(cafe, s(cafe))]), 0)
        .await
        .unwrap();
    assert_eq!(
        attrs[&format!("aws_dbe_b_{cafe}")],
        s(&spec_beacon(cafe, cafe.as_bytes(), 24))
    );

    let info = lotsa_info();
    let mut empty = simple_item();
    empty.insert("Name".to_owned(), s(""));
    let attrs = encrypted(&info, &empty, 0).await.unwrap();
    assert_eq!(attrs["aws_dbe_b_Name"], s(EMPTY_NAME_BEACON));

    let mut unicode = simple_item();
    unicode.insert("Name".to_owned(), s("\u{540D}\u{524D}"));
    let attrs = encrypted(&info, &unicode, 0).await.unwrap();
    assert_eq!(
        attrs["aws_dbe_b_Name"],
        s(&spec_beacon("Name", "\u{540D}\u{524D}".as_bytes(), 32))
    );
}

#[tokio::test]
async fn missing_beacon_attribute_with_partitions() {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let version =
        version_with(&store, single_source("foo"), vec![name_b()]).maximum_number_of_partitions(5);
    let info = search_info(full_actions(), version).unwrap();
    let it = item(&[("std2", n("1.23")), ("Title", s("MyTitle"))]);
    let attrs = encrypted(&info, &it, 2).await.unwrap();
    assert!(attrs.is_empty(), "{attrs:?}");
}

#[test]
fn beacon_names() {
    let info = lotsa_info();
    let std = &info.version.beacons["std2"];
    assert_eq!((std.name(), std.beacon_name()), ("std2", "aws_dbe_b_std2"));
    assert_eq!(std.num_queries(10, ""), 1);
    let signed = &info.version.beacons["JustSigned"];
    assert_eq!(
        (signed.name(), signed.beacon_name()),
        ("JustSigned", "JustSigned")
    );
}

#[test]
fn attribute_type_names() {
    use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue as A;
    let cases = [
        (A::S(String::new()), "S"),
        (A::N("1".to_owned()), "N"),
        (A::B(Blob::new(vec![])), "B"),
        (A::Ss(vec![]), "SS"),
        (A::Ns(vec![]), "NS"),
        (A::Bs(vec![]), "BS"),
        (A::M(HashMap::new()), "M"),
        (A::L(vec![]), "L"),
        (A::Null(true), "NULL"),
        (A::Bool(true), "BOOL"),
    ];
    for (v, want) in cases {
        assert_eq!(attr_type_to_str(&v), want);
    }
}
