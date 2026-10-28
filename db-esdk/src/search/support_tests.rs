// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests ported from the reference implementation's `DDBSupport.dfy`
//! and the partition tests of `BeaconPartition.dfy`.

use std::sync::{Arc, Mutex};

use super::*;
use crate::search::config::StandardBeacon;
use crate::search::partition::{GetPartitionNumberOutput, PartitionSelector};
use crate::search::test_fixtures::*;

fn std2_name_title(max: Option<u8>) -> SearchInfo {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let version = version_with(
        &store,
        single_source("foo"),
        vec![std2(), name_b(), title_b()],
    )
    .set_maximum_number_of_partitions(max);
    search_info(full_actions(), version).unwrap()
}

fn vals(pairs: &[(&str, AttributeValue)]) -> Values {
    item(pairs)
}

#[test]
fn add_signed_beacons() {
    let info = lotsa_info();
    let out = info.add_signed_beacons(simple_item(), 0).unwrap();
    let mut expected = simple_item();
    expected.insert("aws_dbe_v_1".to_owned(), s(" "));
    expected.insert("JustSigned".to_owned(), s("Y_1984.M_May"));
    assert_eq!(out, expected);
}

#[test]
fn supplied_signed_beacon_must_match() {
    let info = lotsa_info();
    let mut same = simple_item();
    same.insert("JustSigned".to_owned(), s("Y_1984.M_May"));
    assert_eq!(
        info.add_signed_beacons(same, 0).unwrap()["JustSigned"],
        s("Y_1984.M_May")
    );
    let mut other = simple_item();
    other.insert("JustSigned".to_owned(), s("Y_1.M_x"));
    assert_eq!(
        val_msg(info.add_signed_beacons(other, 0)),
        "Signed beacons have generated values different from supplied values."
    );
}

#[test]
fn unconfigured_key_field_is_removed() {
    let mut it = simple_item();
    it.insert("TheKeyField".to_owned(), s("k1"));

    // TheKeyField is SIGN_ONLY: it is kept.
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let info = search_info(
        full_actions(),
        lotsa_with(&store, multi_source("TheKeyField")),
    )
    .unwrap();
    assert!(info.is_multi_key());
    let out = info.add_signed_beacons(it.clone(), 0).unwrap();
    assert_eq!(out["TheKeyField"], s("k1"));

    // TheKeyField has no action: it only names the beacon key, and is not written.
    let mut actions = full_actions();
    actions.remove("TheKeyField");
    let info = search_info(actions, lotsa_with(&store, multi_source("TheKeyField"))).unwrap();
    let out = info.add_signed_beacons(it, 0).unwrap();
    assert!(!out.contains_key("TheKeyField"));
    assert_eq!(out["JustSigned"], s("Y_1984.M_May"));

    assert!(!lotsa_info().is_multi_key());
}

/// A selector that returns `partition` and records the input it was given.
#[derive(Clone)]
struct Fixed {
    partition: u8,
    seen: Arc<Mutex<Option<GetPartitionNumberInput>>>,
}

#[aws_crypto_mpl::async_trait]
impl PartitionSelector for Fixed {
    async fn get_partition_number(
        &self,
        input: GetPartitionNumberInput,
    ) -> Result<GetPartitionNumberOutput, Error> {
        *self.seen.lock().unwrap() = Some(input);
        GetPartitionNumberOutput::builder()
            .partition_number(self.partition)
            .build()
    }
}

struct Failing;

#[aws_crypto_mpl::async_trait]
impl PartitionSelector for Failing {
    async fn get_partition_number(
        &self,
        _input: GetPartitionNumberInput,
    ) -> Result<GetPartitionNumberOutput, Error> {
        Err(crate::error::crypt_err("selector failed"))
    }
}

fn with_selector(selector: impl PartitionSelector + 'static, max: u8) -> SearchInfo {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let version = version_with(&store, single_source("foo"), vec![std2()])
        .maximum_number_of_partitions(max)
        .partition_selector(selector);
    search_info(full_actions(), version).unwrap()
}

#[tokio::test]
async fn get_partition_asks_the_selector() {
    let seen = Arc::new(Mutex::new(None));
    let info = with_selector(
        Fixed {
            partition: 3,
            seen: seen.clone(),
        },
        5,
    );
    let it = item(&[("std2", s("x"))]);
    assert_eq!(info.get_partition(&it, "Foo").await.unwrap(), 3);
    let input = seen.lock().unwrap().take().unwrap();
    assert_eq!(input.item(), &it);
    assert_eq!(input.number_of_partitions(), 5);
    assert_eq!(input.logical_table_name(), "Foo");
}

#[tokio::test]
async fn single_partition_skips_the_selector() {
    let seen = Arc::new(Mutex::new(None));
    let info = with_selector(
        Fixed {
            partition: 3,
            seen: seen.clone(),
        },
        1,
    );
    assert_eq!(info.get_partition(&simple_item(), "Foo").await.unwrap(), 0);
    assert!(seen.lock().unwrap().is_none());
}

#[tokio::test]
async fn selector_result_out_of_range_fails() {
    let info = with_selector(
        Fixed {
            partition: 5,
            seen: Arc::default(),
        },
        5,
    );
    assert_eq!(
        val_msg(info.get_partition(&simple_item(), "Foo").await),
        "Partition Selector returned 5 which should have been no more than 5"
    );
}

#[tokio::test]
async fn selector_error_is_returned_as_is() {
    let info = with_selector(Failing, 5);
    let err = info.get_partition(&simple_item(), "Foo").await.unwrap_err();
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
    assert_eq!(err.message(), "selector failed");
}

fn extract(info: &SearchInfo, values: Option<Values>) -> Result<(Option<Values>, u8), Error> {
    info.extract_partition(None, Some("Name = :val"), None, values, &full_actions())
}

#[test]
fn invalid_partition_on_query() {
    let info = std2_name_title(Some(5));
    assert_eq!(
        val_msg(extract(&info, Some(vals(&[(PARTITION_NAME, n("5"))])))),
        ":aws_dbe_partition specified in FilterExpression was 5 must be less than the number of partitions: 5"
    );
    assert_eq!(
        val_msg(extract(
            &lotsa_info(),
            Some(vals(&[(PARTITION_NAME, n("0"))]))
        )),
        "If no partitions are configured, do not specify :aws_dbe_partition"
    );
    assert_eq!(
        val_msg(extract(&info, None)),
        "When numberOfPartitions is greater than one, Values must contain :aws_dbe_partition"
    );
    // The key condition alone also reads an encrypted field.
    assert_eq!(
        val_msg(info.extract_partition(Some("Name = :val"), None, None, None, &full_actions())),
        "When numberOfPartitions is greater than one, Values must contain :aws_dbe_partition"
    );
}

#[test]
fn invalid_partition_type() {
    let info = std2_name_title(Some(5));
    for v in [s("2"), AttributeValue::Bool(true)] {
        assert_eq!(
            val_msg(extract(&info, Some(vals(&[(PARTITION_NAME, v)])))),
            "Value of :aws_dbe_partition is not numeric (i.e. 'N')"
        );
    }
    for v in ["-1", "2147483647"] {
        assert_eq!(
            val_msg(extract(&info, Some(vals(&[(PARTITION_NAME, n(v))])))),
            "Value of :aws_dbe_partition out of range.",
            "{v}"
        );
    }
    assert!(matches!(
        extract(&info, Some(vals(&[(PARTITION_NAME, n("1.5"))]))),
        Err(Error::Validation(_))
    ));
}

#[test]
fn partition_value_is_extracted() {
    let info = std2_name_title(Some(5));
    let (rest, p) = extract(
        &info,
        Some(vals(&[(PARTITION_NAME, n("3")), (":val", s("x"))])),
    )
    .unwrap();
    assert_eq!((rest, p), (Some(vals(&[(":val", s("x"))])), 3));
    let (rest, p) = extract(&info, Some(vals(&[(PARTITION_NAME, n("4"))]))).unwrap();
    assert_eq!((rest, p), (None, 4));

    // Without encrypted fields, no partition is needed.
    let plain = info
        .extract_partition(None, Some("Year = :y"), None, None, &full_actions())
        .unwrap();
    assert_eq!(plain, (None, 0));
    // Without partitions, values pass through.
    let v = Some(vals(&[(":val", s("x"))]));
    assert_eq!(extract(&lotsa_info(), v.clone()).unwrap(), (v, 0));
}

fn multi_info() -> SearchInfo {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    search_info(
        full_actions(),
        lotsa_with(&store, multi_source("TheKeyField")),
    )
    .unwrap()
}

const BRANCH_KEY: &str = "0ad21413-51aa-42e1-9c3d-6a4b1edf7e10";

#[tokio::test]
async fn multi_key_queries() {
    let info = multi_info();
    let actions = full_actions();

    let out = info
        .query_input_for_beacons(
            &actions,
            Some("TheKeyField = :value".to_owned()),
            None,
            None,
            Some(vals(&[(":value", s(BRANCH_KEY))])),
        )
        .await
        .unwrap();
    assert_eq!(out.key_expr.as_deref(), Some("TheKeyField = :value"));
    assert_eq!(out.values, Some(vals(&[(":value", s(BRANCH_KEY))])));

    let both = vals(&[(":value", s(BRANCH_KEY)), (":other", s("junk"))]);
    let out = info
        .query_input_for_beacons(
            &actions,
            Some("TheKeyField = :value AND std2 = :other".to_owned()),
            None,
            None,
            Some(both.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        out.key_expr.as_deref(),
        Some("TheKeyField = :value AND aws_dbe_b_std2 = :other")
    );
    assert_eq!(
        out.values,
        Some(vals(&[
            (":value", s(BRANCH_KEY)),
            (":other", s(&spec_beacon("std2", b"junk", 24))),
        ]))
    );

    let err = info
        .query_input_for_beacons(
            &actions,
            Some("std2 = :other".to_owned()),
            None,
            None,
            Some(both.clone()),
        )
        .await;
    assert_eq!(
        val_msg(err),
        "Need KeyId because of beacon std2 but no KeyId found in query"
    );

    let names: HashMap<String, String> = [
        ("#beacon".to_owned(), "std2".to_owned()),
        ("#keyfield".to_owned(), "TheKeyField".to_owned()),
    ]
    .into();
    let out = info
        .query_input_for_beacons(
            &actions,
            Some("#keyfield = :value AND #beacon = :other".to_owned()),
            None,
            Some(names),
            Some(both),
        )
        .await
        .unwrap();
    assert_eq!(
        out.values.unwrap()[":other"],
        s(&spec_beacon("std2", b"junk", 24))
    );
}

fn std2_partitions(beacon_partitions: u8, max: u8) -> SearchInfo {
    let store = FakeKeyStore::new("KeyStoreDdbTable");
    let std2 = StandardBeacon::builder()
        .name("std2")
        .bits(24)
        .number_of_partitions(beacon_partitions)
        .build()
        .unwrap();
    let version =
        version_with(&store, single_source("foo"), vec![std2]).maximum_number_of_partitions(max);
    search_info(full_actions(), version).unwrap()
}

#[tokio::test]
async fn query_partition_must_be_below_the_number_of_queries() {
    let info = std2_partitions(2, 5);
    let err = info
        .query_input_for_beacons(
            &full_actions(),
            Some("std2 = :v".to_owned()),
            None,
            None,
            Some(vals(&[(":v", n("1.23")), (PARTITION_NAME, n("3"))])),
        )
        .await;
    assert_eq!(
        val_msg(err),
        "Partition number was 3 but should have been less than number of queries : 2"
    );
}

#[tokio::test]
async fn query_covers_each_beacon_partition() {
    // std2 has 2 of the table's 5 partitions; a filter on it ORs both of its values.
    let info = std2_partitions(2, 5);
    let out = info
        .query_input_for_beacons(
            &full_actions(),
            None,
            Some("std2 = :v".to_owned()),
            None,
            Some(vals(&[(":v", n("1.23")), (PARTITION_NAME, n("0"))])),
        )
        .await
        .unwrap();
    assert_eq!(
        out.filter_expr.as_deref(),
        Some("(aws_dbe_b_std2 = :v) OR (aws_dbe_b_std2 = :vAA)")
    );
    assert_eq!(
        out.values,
        Some(vals(&[
            (":v", s(&spec_beacon("std2", b"1.23", 24))),
            (":vAA", s(&spec_beacon("std2", b"1.23\x01", 24))),
        ]))
    );
}

#[tokio::test]
async fn scan_rewrites_the_filter() {
    let info = lotsa_info();
    let out = info
        .scan_input_for_beacons(
            Some("std2 = :v".to_owned()),
            None,
            Some(vals(&[(":v", n("1.23"))])),
        )
        .await
        .unwrap();
    assert_eq!(out.key_expr, None);
    assert_eq!(out.filter_expr.as_deref(), Some("aws_dbe_b_std2 = :v"));
    assert_eq!(out.values, Some(vals(&[(":v", s(STD2_BEACON))])));

    let err = info
        .scan_input_for_beacons(
            Some("std2 = :v".to_owned()),
            None,
            Some(vals(&[(":v", n("1.23")), (PARTITION_NAME, n("0"))])),
        )
        .await;
    assert_eq!(
        val_msg(err),
        "A value for :aws_dbe_partition must not be specified for Scan operations."
    );
}

#[tokio::test]
async fn get_encrypted_beacons_uses_the_partition() {
    let info = std2_partitions(2, 5);
    let it = item(&[("std2", n("1.23"))]);
    let p1 = info
        .get_encrypted_beacons(&it, &MaybeKeyId::DontUse, 1)
        .await
        .unwrap();
    assert_eq!(
        p1,
        item(&[("aws_dbe_b_std2", s(&spec_beacon("std2", b"1.23\x01", 24)))])
    );
}
