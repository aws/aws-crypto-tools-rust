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
use aws_db_esdk::aws_sdk_dynamodb::operation::batch_write_item::BatchWriteItemInput;
use aws_db_esdk::aws_sdk_dynamodb::operation::delete_item::{DeleteItemInput, DeleteItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::get_item::{GetItemInput, GetItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::{PutItemInput, PutItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::query::{QueryInput, QueryOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::scan::{ScanInput, ScanOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::transact_get_items::{
    TransactGetItemsInput, TransactGetItemsOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsInput;
use aws_db_esdk::aws_sdk_dynamodb::operation::update_item::{UpdateItemInput, UpdateItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::types::{
    AttributeValue, ComparisonOperator, Condition, Get, ItemResponse, KeysAndAttributes, Put,
    PutRequest, ReturnValue, TransactGetItem, TransactWriteItem, WriteRequest,
};
use aws_db_esdk::key_store;
use aws_db_esdk::keyring::{
    GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    ItemKeyBranchKeySupplier, ItemKeySupplier, MultiKeyring,
};
use aws_db_esdk::search::SearchConfig;
use aws_db_esdk::transforms::{ResolveAttributesInput, Transforms};
use aws_db_esdk::types::PlaintextOverride;
use aws_db_esdk::{Error, ItemEncryptor, TableConfig, async_trait};
use transforms_support::{
    FakeKeyStore, Item, NAME_BEACON, STD2_BEACON, STD4_BEACON, STD6_BEACON, TITLE_BEACON,
    beacon_transforms, expect_validation, fake_key_store, hierarchical_keyring, item,
    lotsa_beacons, multi_actions, multi_actions_without_key_field, multi_transforms_hierarchical,
    multi_transforms_hierarchical_with, multi_transforms_static, multi_transforms_with,
    partitioned_transforms, s, simple_item, static_keyring, transforms,
};

fn put_input(it: Item) -> PutItemInput {
    PutItemInput::builder()
        .table_name("foo")
        .set_item(Some(it))
        .build()
        .unwrap()
}

async fn put(t: &Transforms, it: Item) -> Item {
    try_put(t, it).await.unwrap()
}

/// `it` as the PutItem input transform writes it to table `foo`.
async fn try_put(t: &Transforms, it: Item) -> Result<Item, Error> {
    Ok(t.put_item_input(put_input(it)).await?.item.unwrap())
}

/// `it` as the BatchWriteItem input transform writes it to table `foo`, in a put request.
async fn batch_put(t: &Transforms, it: Item) -> Result<Item, Error> {
    let put = WriteRequest::builder()
        .put_request(PutRequest::builder().set_item(Some(it)).build().unwrap())
        .build();
    let input = BatchWriteItemInput::builder()
        .request_items("foo", vec![put])
        .build()
        .unwrap();
    let mut out = t
        .batch_write_item_input(input)
        .await?
        .request_items
        .unwrap();
    let [req] = out.remove("foo").unwrap().try_into().unwrap();
    Ok(req.put_request.unwrap().item)
}

/// `it` as the TransactWriteItems input transform writes it to table `foo`, in a put.
async fn transact_put(t: &Transforms, it: Item) -> Result<Item, Error> {
    let put = TransactWriteItem::builder()
        .put(
            Put::builder()
                .table_name("foo")
                .set_item(Some(it))
                .build()
                .unwrap(),
        )
        .build();
    let input = TransactWriteItemsInput::builder()
        .transact_items(put)
        .build()
        .unwrap();
    let out = t.transact_write_items_input(input).await?.transact_items;
    let [action] = out.unwrap().try_into().unwrap();
    Ok(action.put.unwrap().item)
}

/// The GetItem output transform on `it`, an encrypted item of table `foo`.
async fn read(t: &Transforms, it: Item) -> Result<Option<Item>, Error> {
    let input = GetItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .build()
        .unwrap();
    let output = GetItemOutput::builder().set_item(Some(it)).build();
    Ok(t.get_item_output(output, &input).await?.item)
}

/// `encrypted` with its signed compound beacon `JustSigned` changed after it was signed.
fn tamper_just_signed(mut encrypted: Item) -> Item {
    encrypted.insert("JustSigned".into(), s("Y_1985.M_May"));
    encrypted
}

/// The multi-tenant table with branch key `id1`, whose key field `TheKeyField` has no action.
async fn multi_transforms_unconfigured_key_field() -> Transforms {
    multi_transforms_hierarchical_with("id1", multi_actions_without_key_field).await
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
    let t = beacon_transforms();
    let out = put(&t, simple_item()).await;
    assert_eq!(beacon(&out, "std2"), STD2_BEACON);
    assert_eq!(beacon(&out, "std4"), STD4_BEACON);
    assert_eq!(beacon(&out, "std6"), STD6_BEACON);

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //= type=test
    //# Encrypted Beacons MUST be [added](ddb-support.md#addencryptedbeacons).
    assert_eq!(beacon(&out, "Name"), NAME_BEACON);
    assert_eq!(beacon(&out, "Title"), TITLE_BEACON);

    // A fully signed compound beacon is written in plaintext.
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //= type=test
    //# Signed Beacons MUST be [added](ddb-support.md#addsignedbeacons).
    assert_eq!(out["JustSigned"], s("Y_1984.M_May"));

    // The encrypted attributes are ciphertext; the signed ones are unchanged.
    assert_ne!(out["Name"], simple_item()["Name"]);
    assert_eq!(out["Year"], simple_item()["Year"]);

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //= type=test
    //= reason=the request item, beacons asserted above, decrypts back to the original item
    //# The PutItem request's `Item` field MUST be replaced
    //# with a value that is equivalent to
    //# the output of the [add encrypted beacons](ddb-support.md#addencryptedbeacons) operation
    //# calculated above.
    assert_eq!(read(&t, out).await.unwrap(), Some(simple_item_read()));
}

/// `TestPutItemInputMulti`: a multi-tenant table needs a hierarchical keyring.
#[tokio::test]
async fn put_item_input_multi_fail() {
    for o in [
        None,
        Some(PlaintextOverride::ForbidPlaintextWriteForbidPlaintextRead),
        Some(PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead),
    ] {
        //= spec/searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header
        //= type=test
        //# If this single encrypted data key's
        //# [Key Provider ID](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/../structured-encryption/structures.md#key-provider-id)
        //# does not equal the provider ID
        //# for the [AWS KMS Hierarchical Keyring](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt)
        //# this function MUST fail.
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
    let beacon_store = FakeKeyStore::default();
    let t = multi_transforms_with(
        hierarchical_keyring("id1").await,
        key_store::SharedKeyStore::new(beacon_store.clone()),
    );
    // The item has no key field, so the beacon key id can only come from the data key.
    // (A key field naming another key is rejected; see put_item_multi_key_id_must_match_the_header.)
    let out = put(&t, simple_item()).await;
    // The fake key store gives every branch key id the same beacon key.
    //= spec/dynamodb-encryption-client/ddb-support.md#getencryptedbeacons
    //= type=test
    //= reason=NAME_BEACON is an HMAC under the key store's beacon key, so the beacon key was fetched
    //# To obtain [Beacon Key Materials] GetEncryptedBeacons
    //# MUST call [Get beacon key after encrypt](../searchable-encryption/search-config.md#get-beacon-key-after-encrypt).
    assert_eq!(beacon(&out, "Name"), NAME_BEACON);
    assert!(matches!(out["aws_dbe_head"], AttributeValue::B(_)));

    //= spec/searchable-encryption/search-config.md#get-beacon-key-after-encrypt
    //= type=test
    //# If the [Beacon Key Source](#beacon-key-source) is a [Multi Key Store](#multi-key-store-initialization)
    //# then `beacon key id` MUST be obtained from [Get beacon key id from parsed header](#get-beacon-key-id-from-parsed-header).
    //
    //= spec/searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header
    //= type=test
    //= reason=id1 is the provider info of the hierarchical keyring's encrypted data key
    //# This function MUST return the [Key Provider Information](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/../structured-encryption/structures.md#key-provider-id).
    assert_eq!(*beacon_store.beacon_key_ids.lock().unwrap(), ["id1"]);
}

#[tokio::test]
async fn put_item_multi_two_edks_fail() {
    let keyring = MultiKeyring::builder()
        .generator(hierarchical_keyring("id1").await)
        .child_keyrings(static_keyring())
        .build()
        .unwrap();
    let t = multi_transforms_with(keyring, fake_key_store());

    //= spec/searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header
    //= type=test
    //# If the [Parsed Header](../dynamodb-encryption-client/encrypt-item.md#parsed-header)'s encrypted data keys
    //# do not contain only one encrypted data key
    //# this function MUST fail.
    expect_validation(
        t.put_item_input(put_input(multi_item("id1"))).await,
        "Encrypt header has more than one Encrypted Data Key",
    );
}

#[tokio::test]
async fn put_item_signs_the_signed_beacons() {
    let t = beacon_transforms();
    let out = put(&t, simple_item()).await;
    assert_eq!(
        read(&t, out.clone()).await.unwrap(),
        Some(simple_item_read())
    );
    let result = read(&t, tamper_just_signed(out)).await;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //= type=test
    //= reason=JustSigned was added before EncryptItem, so the signature covers it
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Single Key Store](../searchable-encryption/search-config.md#single-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [adding the signed beacons](ddb-support.md#addsignedbeacons) operation.
    assert!(matches!(result, Err(Error::Cryptographic(_))), "{result:?}");
}

#[tokio::test]
async fn put_item_multi_removes_an_unconfigured_key_field() {
    let t = multi_transforms_unconfigured_key_field().await;
    let out = put(&t, multi_item("id1")).await;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //= type=test
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
    //# MUST be [handled](./ddb-support.md#handlebeaconkeyfieldname).
    assert!(!out.contains_key("TheKeyField"));

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //= type=test
    //= reason=TheKeyField is unconfigured, so EncryptItem would reject it had it not been removed first
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname) operation.
    assert_eq!(read(&t, out).await.unwrap(), Some(simple_item_read()));
}

#[tokio::test]
async fn put_item_multi_key_id_must_match_the_header() {
    let t = multi_transforms_hierarchical("id1").await;
    // A matching key id passes, and the SIGN_ONLY key field is kept.
    let out = try_put(&t, multi_item("id1")).await.unwrap();
    assert_eq!(out["TheKeyField"], s("id1"));
    // An item without the key field returns no branch key id, so there is nothing to match.
    let out = try_put(&t, simple_item()).await.unwrap();
    assert_eq!(read(&t, out).await.unwrap(), Some(simple_item_read()));
    let mut numeric = simple_item();
    numeric.insert("TheKeyField".into(), AttributeValue::N("1".into()));

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-putitem
    //= type=test
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# and a `branch key id` was returned from [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname)
    //# this `branch key id` MUST match the value
    //# returned from [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header).
    expect_validation(
        try_put(&t, multi_item("id2")).await,
        "The beacon key id in TheKeyField does not match the branch key id id1 that encrypted the item.",
    );
    expect_validation(
        try_put(&t, numeric).await,
        "The beacon key id in TheKeyField does not match the branch key id id1 that encrypted the item.",
    );
}

// --- BatchWriteItem ---

#[tokio::test]
async fn batch_write_item_adds_the_lotsa_beacons() {
    let t = beacon_transforms();
    let out = batch_put(&t, simple_item()).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //= type=test
    //# Signed Beacons MUST be [added](ddb-support.md#addsignedbeacons).
    assert_eq!(out["JustSigned"], s("Y_1984.M_May"));

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //= type=test
    //# Encrypted Beacons MUST be [added](ddb-support.md#addencryptedbeacons).
    assert_eq!(beacon(&out, "Name"), NAME_BEACON);
    assert_eq!(
        read(&t, out.clone()).await.unwrap(),
        Some(simple_item_read())
    );
    let result = read(&t, tamper_just_signed(out)).await;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //= type=test
    //= reason=JustSigned was added before EncryptItem, so the signature covers it
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Single Key Store](../searchable-encryption/search-config.md#single-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [adding the signed beacons](ddb-support.md#addsignedbeacons) operation.
    assert!(matches!(result, Err(Error::Cryptographic(_))), "{result:?}");
}

#[tokio::test]
async fn batch_write_item_multi_removes_an_unconfigured_key_field() {
    let t = multi_transforms_unconfigured_key_field().await;
    let out = batch_put(&t, multi_item("id1")).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //= type=test
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
    //# MUST be [handled](./ddb-support.md#handlebeaconkeyfieldname).
    assert!(!out.contains_key("TheKeyField"));

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //= type=test
    //= reason=TheKeyField is unconfigured, so EncryptItem would reject it had it not been removed first
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname) operation.
    assert_eq!(read(&t, out).await.unwrap(), Some(simple_item_read()));
}

#[tokio::test]
async fn batch_write_item_multi_key_id_must_match_the_header() {
    let t = multi_transforms_hierarchical("id1").await;
    // A matching key id passes, and the SIGN_ONLY key field is kept.
    let out = batch_put(&t, multi_item("id1")).await.unwrap();
    assert_eq!(out["TheKeyField"], s("id1"));
    // An item without the key field returns no branch key id, so there is nothing to match.
    let out = batch_put(&t, simple_item()).await.unwrap();
    assert_eq!(read(&t, out).await.unwrap(), Some(simple_item_read()));
    let mut numeric = simple_item();
    numeric.insert("TheKeyField".into(), AttributeValue::N("1".into()));

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-batchwriteitem
    //= type=test
    //# If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# and a `branch key id` was returned from [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname)
    //# this `branch key id` MUST match the value
    //# returned from [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header).
    expect_validation(
        batch_put(&t, multi_item("id2")).await,
        "The beacon key id in TheKeyField does not match the branch key id id1 that encrypted the item.",
    );
    expect_validation(
        batch_put(&t, numeric).await,
        "The beacon key id in TheKeyField does not match the branch key id id1 that encrypted the item.",
    );
}

// --- TransactWriteItems ---

#[tokio::test]
async fn transact_write_items_adds_the_lotsa_beacons() {
    let t = beacon_transforms();
    let out = transact_put(&t, simple_item()).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //= type=test
    //# - Signed Beacons MUST be [added](ddb-support.md#addsignedbeacons).
    assert_eq!(out["JustSigned"], s("Y_1984.M_May"));

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //= type=test
    //# - Encrypted Beacons MUST be [added](ddb-support.md#addencryptedbeacons).
    assert_eq!(beacon(&out, "Name"), NAME_BEACON);
    assert_eq!(
        read(&t, out.clone()).await.unwrap(),
        Some(simple_item_read())
    );
    let result = read(&t, tamper_just_signed(out)).await;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //= type=test
    //= reason=JustSigned was added before EncryptItem, so the signature covers it
    //# - If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Single Key Store](../searchable-encryption/search-config.md#single-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [adding the signed beacons](ddb-support.md#addsignedbeacons) operation.
    assert!(matches!(result, Err(Error::Cryptographic(_))), "{result:?}");
}

#[tokio::test]
async fn transact_write_items_multi_removes_an_unconfigured_key_field() {
    let t = multi_transforms_unconfigured_key_field().await;
    let out = transact_put(&t, multi_item("id1")).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //= type=test
    //# - If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Beacon Key Field Name](../searchable-encryption/search-config.md#beacon-key-field-name)
    //# MUST be [handled](./ddb-support.md#handlebeaconkeyfieldname).
    assert!(!out.contains_key("TheKeyField"));

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //= type=test
    //= reason=TheKeyField is unconfigured, so EncryptItem would reject it had it not been removed first
    //# - If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# the [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Encrypt Item](./encrypt-item.md),
    //# where the input [DynamoDB Item](./encrypt-item.md#dynamodb-item)
    //# is output of [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname) operation.
    assert_eq!(read(&t, out).await.unwrap(), Some(simple_item_read()));
}

#[tokio::test]
async fn transact_write_items_multi_key_id_must_match_the_header() {
    let t = multi_transforms_hierarchical("id1").await;
    // A matching key id passes, and the SIGN_ONLY key field is kept.
    let out = transact_put(&t, multi_item("id1")).await.unwrap();
    assert_eq!(out["TheKeyField"], s("id1"));
    // An item without the key field returns no branch key id, so there is nothing to match.
    let out = transact_put(&t, simple_item()).await.unwrap();
    assert_eq!(read(&t, out).await.unwrap(), Some(simple_item_read()));
    let mut numeric = simple_item();
    numeric.insert("TheKeyField".into(), AttributeValue::N("1".into()));

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#encrypt-before-transactwriteitems
    //= type=test
    //# - If the [Beacon Key Source](../searchable-encryption/search-config.md#beacon-key-source)
    //# is a [Multi Key Store](../searchable-encryption/search-config.md#multi-key-store-initialization)
    //# and a `branch key id` was returned from [handling the beacon key field name](ddb-support.md#handlebeaconkeyfieldname)
    //# this `branch key id` MUST match the value
    //# returned from [Get beacon key id from Parsed Header](../searchable-encryption/search-config.md#get-beacon-key-id-from-parsed-header).
    expect_validation(
        transact_put(&t, multi_item("id2")).await,
        "The beacon key id in TheKeyField does not match the branch key id id1 that encrypted the item.",
    );
    expect_validation(
        transact_put(&t, numeric).await,
        "The beacon key id in TheKeyField does not match the branch key id id1 that encrypted the item.",
    );
}

// --- Query ---

#[tokio::test]
async fn query_input_beaconizes_encrypted_field() {
    let out = beacon_transforms()
        .query_input(query_name("MyName"))
        .await
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-query
    //= type=test
    //# The request MUST be [altered](./ddb-support.md#queryinputforbeacons)
    //# to transform any references to encrypted attributes into references to beacons.
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
    //
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

/// `TestNumberOfQueriesPartition5` and its 25-partition sibling, from `BeaconPartition.dfy`.
#[tokio::test]
async fn get_number_of_queries_with_a_partitioned_beacon() {
    let input = QueryInput::builder()
        .table_name("foo")
        .key_condition_expression("std2 = :std2")
        .expression_attribute_values(":std2", AttributeValue::N("1.23".into()))
        .build()
        .unwrap();
    for (partitions, max) in [(5, 6), (25, 26)] {
        let t = partitioned_transforms(partitions, max);

        //= spec/dynamodb-encryption-client/ddb-get-number-of-queries.md#input
        //= type=test
        //# This operation MUST return the number of queries necessary.
        assert_eq!(
            t.get_number_of_queries(&input).await.unwrap(),
            partitions,
            "max {max}"
        );
    }
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

/// The multi-tenant table `foo` whose keyring can decrypt the items of both tenants,
/// with the search configuration `search`.
async fn two_tenant_config(search: Option<SearchConfig>) -> TableConfig {
    let keyring = HierarchicalKeyring::builder()
        .key_store(fake_key_store())
        .branch_key_id_supplier(ItemKeyBranchKeySupplier::new(TenantSupplier))
        .ttl(Duration::from_secs(3600))
        .build()
        .await
        .unwrap();
    multi_actions(TableConfig::builder())
        .logical_table_name("foo")
        .partition_key_name("bar")
        .allowed_unsigned_attributes("plain")
        .keyring(keyring)
        .set_search(search)
        .build()
        .unwrap()
}

/// A multi-tenant table whose keyring can decrypt the items of both tenants.
async fn two_tenant_transforms() -> Transforms {
    let search = SearchConfig::builder()
        .write_version(1)
        .versions(lotsa_beacons(true))
        .build()
        .unwrap();
    Transforms::builder()
        .table_encryption_configs("foo", two_tenant_config(Some(search)).await)
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
    // The write transforms reject that item, so it is encrypted without them.
    let mut theirs = multi_item("id1");
    theirs.insert("bar".into(), s("key2"));
    let theirs = ItemEncryptor::builder()
        .table("foo", two_tenant_config(None).await)
        .build()
        .unwrap()
        .encrypt_item()
        .plaintext_item(theirs)
        .send()
        .await
        .unwrap()
        .into_encrypted_item();
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

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-scan
    //= type=test
    //# The request MUST be [altered](./ddb-support.md#scaninputforbeacons)
    //# to transform any references to encrypted attributes into references to beacons.
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
