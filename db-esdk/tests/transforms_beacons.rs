// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The transforms of a table with a search configuration, ported from the Dafny
//! `PutItemTransform.dfy` (`TestPutItemInputMulti*`) with the beacons of
//! `BeaconTestFixtures.GetLotsaBeacons`, plus the beacon paths of Query, Scan,
//! and `ResolveAttributes` that the Dafny transform tests leave out.

mod transforms_support;

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::operation::batch_get_item::{
    BatchGetItemInput, BatchGetItemOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::operation::delete_item::{DeleteItemInput, DeleteItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::get_item::{GetItemInput, GetItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::{PutItemInput, PutItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::query::{QueryInput, QueryOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::scan::{ScanInput, ScanOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::transact_get_items::{
    TransactGetItemsInput, TransactGetItemsOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::operation::update_item::{UpdateItemInput, UpdateItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::types::{
    AttributeValue, Get, ItemResponse, KeysAndAttributes, ReturnValue, TransactGetItem,
};
use aws_db_esdk::keyring::{
    GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    ItemKeyBranchKeySupplier, ItemKeySupplier,
};
use aws_db_esdk::search::SearchConfig;
use aws_db_esdk::transforms::{ResolveAttributesInput, Transforms};
use aws_db_esdk::types::PlaintextOverride;
use aws_db_esdk::{TableConfig, async_trait};
use transforms_support::{
    Item, NAME_BEACON, STD2_BEACON, STD4_BEACON, STD6_BEACON, TITLE_BEACON, beacon_transforms,
    expect_validation, fake_key_store, item, lotsa_beacons, multi_actions,
    multi_transforms_hierarchical, multi_transforms_static, s, simple_item, transforms,
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

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
    //= type=test
    //# The resulting decrypted response MUST be [filtered](ddb-support.md#queryoutputforbeacons) from the result.
    assert_eq!(out.items, Some(vec![simple_item_read()]));
    assert_eq!(out.count, 1);
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
    assert_eq!(out.items, Some(vec![mine_read]));
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

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
    //= type=test
    //# The resulting decrypted response MUST be [filtered](ddb-support.md#scanoutputforbeacons) from the result.
    assert_eq!(out.items, Some(vec![simple_item_read()]));
    assert_eq!(out.count, 1);
}

// --- Read outputs remove beacons ---

/// `simple_item` encrypted for table `foo`, with its `aws_dbe_b_` beacons.
async fn beaconed(t: &Transforms) -> Item {
    let enc = put(t, simple_item()).await;
    assert!(enc.keys().any(|k| k.starts_with("aws_dbe_b_")));
    enc
}

#[tokio::test]
async fn get_item_output_removes_beacons() {
    let t = beacon_transforms();
    let input = GetItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .build()
        .unwrap();
    let output = GetItemOutput::builder()
        .set_item(Some(beaconed(&t).await))
        .build();
    let out = t.get_item_output(output, &input).await.unwrap();

    assert_eq!(out.item, Some(simple_item_read()));
}

#[tokio::test]
async fn put_item_output_removes_beacons() {
    let t = beacon_transforms();
    let output = PutItemOutput::builder()
        .set_attributes(Some(beaconed(&t).await))
        .build();
    let out = t
        .put_item_output(output, &put_input(simple_item()))
        .await
        .unwrap();

    assert_eq!(out.attributes, Some(simple_item_read()));
}

#[tokio::test]
async fn delete_item_output_removes_beacons() {
    let t = beacon_transforms();
    let input = DeleteItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .build()
        .unwrap();
    let output = DeleteItemOutput::builder()
        .set_attributes(Some(beaconed(&t).await))
        .build();
    let out = t.delete_item_output(output, &input).await.unwrap();

    assert_eq!(out.attributes, Some(simple_item_read()));
}

#[tokio::test]
async fn update_item_output_removes_beacons() {
    let t = beacon_transforms();
    let input = UpdateItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .return_values(ReturnValue::AllNew)
        .build()
        .unwrap();
    let output = UpdateItemOutput::builder()
        .set_attributes(Some(beaconed(&t).await))
        .build();
    let out = t.update_item_output(output, &input).await.unwrap();

    assert_eq!(out.attributes, Some(simple_item_read()));
}

#[tokio::test]
async fn batch_get_item_output_removes_beacons() {
    let t = beacon_transforms();
    let input = BatchGetItemInput::builder()
        .request_items(
            "foo",
            KeysAndAttributes::builder()
                .keys(HashMap::new())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let output = BatchGetItemOutput::builder()
        .responses("foo", vec![beaconed(&t).await])
        .build();
    let out = t.batch_get_item_output(output, &input).await.unwrap();

    assert_eq!(out.responses.unwrap()["foo"], vec![simple_item_read()]);
}

#[tokio::test]
async fn transact_get_items_output_removes_beacons() {
    let t = beacon_transforms();
    let input = TransactGetItemsInput::builder()
        .transact_items(
            TransactGetItem::builder()
                .get(
                    Get::builder()
                        .table_name("foo")
                        .set_key(Some(HashMap::new()))
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .build()
        .unwrap();
    let output = TransactGetItemsOutput::builder()
        .responses(
            ItemResponse::builder()
                .set_item(Some(beaconed(&t).await))
                .build(),
        )
        .build();
    let out = t.transact_get_items_output(output, &input).await.unwrap();

    assert_eq!(
        out.responses,
        Some(vec![
            ItemResponse::builder()
                .set_item(Some(simple_item_read()))
                .build()
        ])
    );
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
