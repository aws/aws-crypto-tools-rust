// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The transforms of a table with a search configuration, ported from the Dafny
//! `PutItemTransform.dfy` (`TestPutItemInputMulti*`) with the beacons of
//! `BeaconTestFixtures.GetLotsaBeacons`, plus the beacon paths of Query, Scan,
//! and `ResolveAttributes` that the Dafny transform tests leave out.

mod transforms_support;

use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::PutItemInput;
use aws_db_esdk::aws_sdk_dynamodb::operation::query::{QueryInput, QueryOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::scan::{ScanInput, ScanOutput};
use aws_db_esdk::aws_sdk_dynamodb::types::{AttributeValue, ComparisonOperator, Condition};
use aws_db_esdk::keyring::{
    GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    ItemKeyBranchKeySupplier, ItemKeySupplier, MultiKeyring,
};
use aws_db_esdk::search::SearchConfig;
use aws_db_esdk::transforms::{ResolveAttributesInput, Transforms};
use aws_db_esdk::types::PlaintextOverride;
use aws_db_esdk::{TableConfig, async_trait};
use transforms_support::{
    Item, NAME_BEACON, STD2_BEACON, STD4_BEACON, STD6_BEACON, TITLE_BEACON, beacon_transforms,
    expect_validation, fake_key_store, item, lotsa_beacons, multi_actions,
    multi_transforms_hierarchical, multi_transforms_static, s, simple_item, static_keyring,
    transforms,
};

fn put_input(it: Item) -> PutItemInput {
    PutItemInput::builder()
        .table_name("foo")
        .set_item(Some(it))
        .build()
        .unwrap()
}

async fn put(t: &Transforms, it: Item) -> Item {
    t.put_item_input(put_input(it)).await.unwrap().item.unwrap()
}

fn beacon(it: &Item, name: &str) -> String {
    match &it[&format!("aws_dbe_b_{name}")] {
        AttributeValue::S(v) => v.clone(),
        other => panic!("aws_dbe_b_{name} is not a string: {other:?}"),
    }
}

fn query_name(name: &str) -> QueryInput {
    QueryInput::builder()
        .table_name("foo")
        .key_condition_expression("Name = :n")
        .expression_attribute_values(":n", s(name))
        .build()
        .unwrap()
}

/// `simple_item` as read back: the fully signed compound beacon `JustSigned` is a
/// real, plaintext attribute, so it is not removed with the `aws_dbe_` beacons.
fn simple_item_read() -> Item {
    let mut it = simple_item();
    it.insert("JustSigned".into(), s("Y_1984.M_May"));
    it
}

/// `simple_item` under the multi-tenant table, with its branch key id in `TheKeyField`.
fn multi_item(key: &str) -> Item {
    let mut it = simple_item();
    it.insert("TheKeyField".into(), s(key));
    it
}

// --- PutItem ---

#[tokio::test]
async fn put_item_adds_the_lotsa_beacons() {
    let out = put(&beacon_transforms(), simple_item()).await;
    assert_eq!(beacon(&out, "std2"), STD2_BEACON);
    assert_eq!(beacon(&out, "std4"), STD4_BEACON);
    assert_eq!(beacon(&out, "std6"), STD6_BEACON);
    assert_eq!(beacon(&out, "Name"), NAME_BEACON);
    assert_eq!(beacon(&out, "Title"), TITLE_BEACON);
    // A fully signed compound beacon is written in plaintext.
    assert_eq!(out["JustSigned"], s("Y_1984.M_May"));
    // The encrypted attributes are binary; the signed ones are unchanged.
    assert!(matches!(out["Name"], AttributeValue::B(_)));
    assert_eq!(out["Year"], simple_item()["Year"]);
}

/// `TestPutItemInputMulti`: a multi-tenant table needs a hierarchical keyring.
#[tokio::test]
async fn put_item_input_multi_fail() {
    for o in [
        None,
        Some(PlaintextOverride::ForbidPlaintextWriteForbidPlaintextRead),
        Some(PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead),
    ] {
        expect_validation(
            multi_transforms_static(o)
                .put_item_input(put_input(multi_item("id")))
                .await,
            "In multi-tenant mode, keyProviderId must be aws-kms-hierarchy",
        );
    }
}

/// `TestPutItemInputMultiForceAllow`: a plaintext write is not encrypted, so it needs no key.
#[tokio::test]
async fn put_item_input_multi_force_allow() {
    let t = multi_transforms_static(Some(
        PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead,
    ));
    let out = put(&t, multi_item("id")).await;
    assert_eq!(out, multi_item("id"));
}

#[tokio::test]
async fn put_item_multi_hierarchical_beacons_use_the_item_key() {
    let t = multi_transforms_hierarchical("id1").await;
    let out = put(&t, multi_item("id1")).await;
    // The fake key store gives every branch key id the same beacon key.
    //= spec/dynamodb-encryption-client/ddb-support.md#getencryptedbeacons
    //= type=test
    //= reason=NAME_BEACON is an HMAC under the key store's beacon key, so the beacon key was fetched
    //# To obtain [Beacon Key Materials] GetEncryptedBeacons
    //# MUST call [Get beacon key after encrypt](../searchable-encryption/search-config.md#get-beacon-key-after-encrypt).
    assert_eq!(beacon(&out, "Name"), NAME_BEACON);
    assert!(matches!(out["aws_dbe_head"], AttributeValue::B(_)));
}

// --- Query ---

#[tokio::test]
async fn query_input_beaconizes_encrypted_field() {
    let out = beacon_transforms()
        .query_input(query_name("MyName"))
        .await
        .unwrap();
    assert_eq!(
        out.key_condition_expression.as_deref(),
        Some("aws_dbe_b_Name = :n")
    );
    assert_eq!(
        out.expression_attribute_values.unwrap()[":n"],
        s(NAME_BEACON)
    );
}

#[tokio::test]
async fn query_output_filters_beacon_false_positives() {
    let t = beacon_transforms();
    let mine = put(&t, simple_item()).await;
    let mut other = simple_item();
    other.insert("bar".into(), s("key2"));
    other.insert("Name".into(), s("OtherName"));
    let other = put(&t, other).await;
    // DynamoDB would only return `mine`; pretend `other` is a beacon collision.
    let output = QueryOutput::builder()
        .items(mine)
        .items(other)
        .count(2)
        .build();
    let out = t.query_output(output, &query_name("MyName")).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-support.md#removebeacons
    //= type=test
    //# RemoveBeacons MUST remove any attributes whose name begins with `aws_dbe_`,
    //# and leave all other attributes unchanged.
    //
    //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
    //= type=test
    //# Any items that do not match MUST be discarded.
    assert_eq!(out.items, Some(vec![simple_item_read()]));

    //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
    //= type=test
    //# The `Count` field, MUST be updated to reflect the new item count.
    assert_eq!(out.count, 1);
}

#[tokio::test]
async fn query_input_rejects_key_conditions() {
    let condition = Condition::builder()
        .comparison_operator(ComparisonOperator::Eq)
        .attribute_value_list(s("MyName"))
        .build()
        .unwrap();
    let input = QueryInput::builder()
        .table_name("foo")
        .key_conditions("Name", condition)
        .build()
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-support.md#queryinputforbeacons
    //= type=test
    //# The KeyConditions property MUST NOT be defined on [QueryInput](#queryinput).
    expect_validation(
        beacon_transforms().query_input(input).await,
        "Legacy parameter 'KeyConditions' not supported in Query with Encryption",
    );
}

#[tokio::test]
async fn query_output_filter_error_fails_the_query() {
    let t = beacon_transforms();
    let mine = put(&t, simple_item()).await;
    // DynamoDB compared beacons; the plaintext re-filter cannot read `:y` as a number.
    let input = QueryInput::builder()
        .table_name("foo")
        .key_condition_expression("Name = :n")
        .filter_expression("Year < :y")
        .expression_attribute_values(":n", s("MyName"))
        .expression_attribute_values(":y", AttributeValue::N("foo".into()))
        .build()
        .unwrap();
    let output = QueryOutput::builder().items(mine).count(1).build();

    //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
    //= type=test
    //# For this reason,
    //# any error encountered during filtering MUST result in a failure of the query operation.
    expect_validation(
        t.query_output(output, &input).await,
        "Number needs digits either before or after the decimal point. when parsing 'foo'.",
    );
}

#[tokio::test]
async fn get_number_of_queries_with_beacons() {
    let t = beacon_transforms();
    assert_eq!(
        t.get_number_of_queries(&query_name("MyName"))
            .await
            .unwrap(),
        1
    );
    expect_validation(
        t.get_number_of_queries(
            &QueryInput::builder()
                .table_name("foo")
                .key_condition_expression("a".repeat(4097))
                .build()
                .unwrap(),
        )
        .await,
        "KeyConditionExpression exceeds maximum length of 4096 characters.",
    );
}

/// Picks the branch key from the partition key: `key` is tenant `id1`, any other is `id2`.
struct TenantSupplier;

#[async_trait]
impl ItemKeySupplier for TenantSupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdFromItemKeyInput,
    ) -> Result<GetBranchKeyIdOutput, aws_db_esdk::mpl::Error> {
        match input.item_key().get("bar") {
            Some(AttributeValue::S(v)) if v == "key" => Ok("id1".into()),
            _ => Ok("id2".into()),
        }
    }
}

/// A multi-tenant table whose keyring can decrypt the items of both tenants.
async fn two_tenant_transforms() -> Transforms {
    let keyring = HierarchicalKeyring::builder()
        .key_store(fake_key_store())
        .branch_key_id_supplier(ItemKeyBranchKeySupplier::new(TenantSupplier))
        .ttl(Duration::from_secs(3600))
        .build()
        .await
        .unwrap();
    let search = SearchConfig::builder()
        .write_version(1)
        .versions(lotsa_beacons(true))
        .build()
        .unwrap();
    let config = multi_actions(TableConfig::builder())
        .logical_table_name("foo")
        .partition_key_name("bar")
        .allowed_unsigned_attributes("plain")
        .keyring(keyring)
        .search(search)
        .build()
        .unwrap();
    Transforms::builder()
        .table_encryption_configs("foo", config)
        .build()
        .unwrap()
}

/// An item whose data key is under another tenant's branch key is dropped, even when its
/// attributes match the query.
#[tokio::test]
async fn query_output_multi_drops_items_of_other_tenants() {
    let t = two_tenant_transforms().await;
    let mine = put(&t, multi_item("id1")).await;
    // `TheKeyField` claims tenant `id1`, but the supplier encrypts it under `id2`.
    let mut theirs = multi_item("id1");
    theirs.insert("bar".into(), s("key2"));
    let theirs = put(&t, theirs).await;
    let mut mine_read = multi_item("id1");
    mine_read.insert("JustSigned".into(), s("Y_1984.M_May"));
    let input = QueryInput::builder()
        .table_name("foo")
        .key_condition_expression("Name = :n AND TheKeyField = :k")
        .expression_attribute_values(":n", s("MyName"))
        .expression_attribute_values(":k", s("id1"))
        .build()
        .unwrap();
    let output = QueryOutput::builder().items(mine).items(theirs).build();
    let out = t.query_output(output, &input).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
    //= type=test
    //= reason=Only the id1 item is kept, so the expected id is the query's TheKeyField value
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source) for the configured table
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# you MUST construct an `expected beacon key id` equal to the [Beacon Key Id](../searchable-encryption/search-config.md#beacon-key-materials)
    //# on materials obtained from [Get beacon key for query](../searchable-encryption/search-config.md#get-beacon-key-for-query)
    //# These [Beacon Key Materials](../searchable-encryption/search-config.md#beacon-key-materials)
    //# SHOULD then be discarded.
    //
    //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
    //= type=test
    //# Using the constructed `expected beacon key id`,
    //# for each item the result
    //# the [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header)
    //# MUST match the `expected beacon key id`.
    //
    //= spec/dynamodb-encryption-client/ddb-support.md#queryoutputforbeacons
    //= type=test
    //# If [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header)
    //# fails or an item does not match it MUST be discarded.
    assert_eq!(out.items, Some(vec![mine_read]));
}

/// An item whose header has two encrypted data keys has no single beacon key id:
/// the query fails instead of discarding the item, as in the reference implementation.
#[tokio::test]
async fn query_output_multi_fails_on_an_item_with_two_data_keys() {
    let hierarchical = HierarchicalKeyring::builder()
        .key_store(fake_key_store())
        .branch_key_id("id1")
        .ttl(Duration::from_secs(3600))
        .build()
        .await
        .unwrap();
    let keyring = MultiKeyring::builder()
        .generator(hierarchical)
        .child_keyrings(static_keyring())
        .build()
        .unwrap();
    // Writing with search refuses two data keys, so write the item without it.
    let config = multi_actions(TableConfig::builder())
        .logical_table_name("foo")
        .partition_key_name("bar")
        .allowed_unsigned_attributes("plain")
        .keyring(keyring)
        .build()
        .unwrap();
    let writer = Transforms::builder()
        .table_encryption_configs("foo", config)
        .build()
        .unwrap();
    let two_keys = put(&writer, multi_item("id1")).await;
    let input = QueryInput::builder()
        .table_name("foo")
        .key_condition_expression("Name = :n AND TheKeyField = :k")
        .expression_attribute_values(":n", s("MyName"))
        .expression_attribute_values(":k", s("id1"))
        .build()
        .unwrap();
    let output = QueryOutput::builder().items(two_keys).build();
    expect_validation(
        multi_transforms_hierarchical("id1")
            .await
            .query_output(output, &input)
            .await,
        "Query result has more than one Encrypted Data Key",
    );
}

// --- Scan ---

#[tokio::test]
async fn scan_beaconizes_and_filters() {
    let t = beacon_transforms();
    let input = ScanInput::builder()
        .table_name("foo")
        .filter_expression("Title = :t")
        .expression_attribute_values(":t", s("MyTitle"))
        .build()
        .unwrap();
    let rewritten = t.scan_input(input.clone()).await.unwrap();
    assert_eq!(
        rewritten.filter_expression.as_deref(),
        Some("aws_dbe_b_Title = :t")
    );
    assert_eq!(
        rewritten.expression_attribute_values.unwrap()[":t"],
        s(TITLE_BEACON)
    );

    let mut other = simple_item();
    other.insert("Title".into(), s("OtherTitle"));
    let output = ScanOutput::builder()
        .items(put(&t, simple_item()).await)
        .items(put(&t, other).await)
        .count(2)
        .build();
    let out = t.scan_output(output, &input).await.unwrap();
    assert_eq!(out.items, Some(vec![simple_item_read()]));
    assert_eq!(out.count, 1);
}

// --- ResolveAttributes ---

fn resolve_input(table: &str, it: Item) -> ResolveAttributesInput {
    ResolveAttributesInput::builder()
        .table_name(table)
        .item(it)
        .build()
        .unwrap()
}

#[tokio::test]
async fn resolve_attributes_with_search() {
    let out = beacon_transforms()
        .resolve_attributes(resolve_input("foo", simple_item()))
        .await
        .unwrap();
    assert_eq!(
        out.virtual_fields(),
        &[("NameTitleField".to_owned(), "MyName__mytitle".to_owned())]
            .into_iter()
            .collect()
    );
    let compound = out.compound_beacons();
    assert_eq!(compound["NameTitle"], "N_MyName.T_MyTitle");
    // The default constructor is the signed parts, then the encrypted parts.
    assert_eq!(compound["YearName"], "Y_1984.N_MyName");
    assert_eq!(compound["JustSigned"], "Y_1984.M_May");
}

#[tokio::test]
async fn resolve_attributes_without_search() {
    for (t, table) in [
        (transforms(), "foo"),
        (beacon_transforms(), "no_such_table"),
    ] {
        let out = t
            .resolve_attributes(resolve_input(table, simple_item()))
            .await
            .unwrap();
        assert!(out.virtual_fields().is_empty());
        assert!(out.compound_beacons().is_empty());
    }
}

#[tokio::test]
async fn resolve_attributes_split_character_in_part() {
    let it = item(&[("bar", s("key")), ("Name", s("My.Name")), ("Title", s("t"))]);
    let err = beacon_transforms()
        .resolve_attributes(resolve_input("foo", it))
        .await
        .unwrap_err();
    assert!(matches!(err, aws_db_esdk::Error::Validation(_)), "{err:?}");
}

#[test]
fn resolve_attributes_input_requires_fields() {
    let input = resolve_input("foo", simple_item());
    assert_eq!(input.table_name(), "foo");
    assert_eq!(input.item(), &simple_item());
    for (b, missing) in [
        (
            ResolveAttributesInput::builder().item(simple_item()),
            "table_name",
        ),
        (ResolveAttributesInput::builder().table_name("foo"), "item"),
    ] {
        expect_validation(b.build(), &format!("{missing} is required"));
    }
}
