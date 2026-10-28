// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The read transforms, ported from the Dafny `GetItemTransform.dfy`, `QueryTransform.dfy`,
//! `ScanTransform.dfy`, `BatchGetItemTransform.dfy`, and `TransactGetItemsTransform.dfy`,
//! plus the checks those files leave out.

mod transforms_support;

use std::collections::HashMap;

use aws_db_esdk::Error;
use aws_db_esdk::aws_sdk_dynamodb::operation::batch_get_item::{
    BatchGetItemInput, BatchGetItemOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::operation::get_item::{GetItemInput, GetItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::PutItemInput;
use aws_db_esdk::aws_sdk_dynamodb::operation::query::{QueryInput, QueryOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::scan::{ScanInput, ScanOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::transact_get_items::{
    TransactGetItemsInput, TransactGetItemsOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::types::{
    AttributeValue, ComparisonOperator, Condition, ConditionalOperator, Get, ItemResponse,
    KeysAndAttributes, TransactGetItem,
};
use aws_db_esdk::transforms::Transforms;
use transforms_support::{Item, expect_validation, item, s, transforms};

fn item_n(i: u32) -> Item {
    item(&[
        ("bar", s(&format!("bar{i}"))),
        ("sign", s(&format!("sign{i}"))),
        ("encrypt", s(&format!("encrypt{i}"))),
        ("plain", s(&format!("plain{i}"))),
    ])
}

async fn encrypt(t: &Transforms, it: Item) -> Item {
    t.put_item_input(
        PutItemInput::builder()
            .table_name("foo")
            .set_item(Some(it))
            .build()
            .unwrap(),
    )
    .await
    .unwrap()
    .item
    .unwrap()
}

// --- GetItem ---

fn get_input(table: &str) -> GetItemInput {
    GetItemInput::builder()
        .table_name(table)
        .set_key(Some(HashMap::new()))
        .build()
        .unwrap()
}

#[tokio::test]
async fn get_item_input_passthrough() {
    let input = get_input("no_such_table");
    let out = transforms().get_item_input(input.clone()).await.unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn get_item_output_passthrough() {
    // An unconfigured table's item is returned as is, even if it looks encrypted.
    let output = GetItemOutput::builder()
        .item("encrypt", AttributeValue::B(vec![1, 2, 3].into()))
        .build();
    let out = transforms()
        .get_item_output(output.clone(), &get_input("no_such_table"))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn get_item_output_decrypts_item() {
    let t = transforms();
    let encrypted = encrypt(&t, item_n(1)).await;
    let out = t
        .get_item_output(
            GetItemOutput::builder().set_item(Some(encrypted)).build(),
            &get_input("foo"),
        )
        .await
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
    //= type=test
    //= reason=the encrypted Item on configured table foo comes back as plaintext, so the response was modified
    //# After a [GetItem](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html)
    //# call is made to DynamoDB,
    //# the resulting response MUST be modified before
    //# being returned to the caller if there exists
    //# an Item Encryptor specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to the `TableName` on the GetItem request.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
    //= type=test
    //= reason=the encrypted Item comes back as its plaintext only because table foo is configured
    //# The GetItem response's `Item` field MUST be
    //# replaced by the encrypted DynamoDb Item outputted above.
    assert_eq!(out.item, Some(item_n(1)));
}

#[tokio::test]
async fn get_item_output_no_item() {
    let output = GetItemOutput::builder().build();
    let out = transforms()
        .get_item_output(output.clone(), &get_input("foo"))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn get_item_output_tampered() {
    let t = transforms();
    let mut encrypted = encrypt(&t, item_n(1)).await;
    let AttributeValue::B(ct) = &encrypted["encrypt"] else {
        panic!("encrypt is not binary")
    };
    let mut ct = ct.clone().into_inner();
    let last = ct.len() - 1;
    ct[last] ^= 1;
    encrypted.insert("encrypt".into(), AttributeValue::B(ct.into()));
    let err = t
        .get_item_output(
            GetItemOutput::builder().set_item(Some(encrypted)).build(),
            &get_input("foo"),
        )
        .await
        .unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-getitem
    //= type=test
    //= reason=a tampered ciphertext in Item fails verification, so Decrypt Item ran on Item
    //# The [Item Encryptor](./ddb-item-encryptor.md) MUST perform
    //# [Decrypt Item](./decrypt-item.md) where the input
    //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
    //# is the `Item` field in the original response
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn get_item_output_not_encrypted() {
    // A plaintext item has no header, so it is not a well-formed encrypted item.
    let err = transforms()
        .get_item_output(
            GetItemOutput::builder().set_item(Some(item_n(1))).build(),
            &get_input("foo"),
        )
        .await
        .unwrap_err();
    assert!(
        !matches!(err, Error::Internal(_)),
        "an unencrypted item must fail with a specific variant: {err:?}"
    );
}

// --- Query ---

fn query_input(table: &str) -> QueryInput {
    QueryInput::builder().table_name(table).build().unwrap()
}

#[tokio::test]
async fn query_input_passthrough() {
    // On table foo, both the legacy parameter and the filter on `encrypt` are rejected.
    let input = QueryInput::builder()
        .table_name("no_such_table")
        .attributes_to_get("sign")
        .filter_expression("encrypt = :e")
        .expression_attribute_values(":e", s("x"))
        .build()
        .unwrap();
    let out = transforms().query_input(input.clone()).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-query
    //= type=test
    //# If the `TableName` in the request does not refer to an [encrypted-table](#encrypted-table),
    //# the Query request MUST be unchanged.
    assert_eq!(out, input);
}

#[tokio::test]
async fn query_input_configured_table_passthrough() {
    let input = QueryInput::builder()
        .table_name("foo")
        .key_condition_expression("bar = :b")
        .filter_expression("#s = :s")
        .expression_attribute_names("#s", "sign")
        .expression_attribute_values(":b", s("bar1"))
        .expression_attribute_values(":s", s("sign1"))
        .build()
        .unwrap();
    let out = transforms().query_input(input.clone()).await.unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn query_input_encrypted_field() {
    let input = QueryInput::builder()
        .table_name("foo")
        .key_condition_expression("bar = :b")
        .filter_expression("#e = :e")
        .expression_attribute_names("#e", "encrypt")
        .build()
        .unwrap();
    expect_validation(
        transforms().query_input(input).await,
        "Query is using encrypted field : encrypt.",
    );
}

#[tokio::test]
async fn query_input_legacy_parameters() {
    let condition = Condition::builder()
        .comparison_operator(ComparisonOperator::Eq)
        .attribute_value_list(s("x"))
        .build()
        .unwrap();
    let base = || QueryInput::builder().table_name("foo");
    let cases = [
        (
            base().attributes_to_get("sign").build().unwrap(),
            "Legacy parameter 'AttributesToGet' not supported in Query with Encryption",
        ),
        (
            base()
                .key_conditions("bar", condition.clone())
                .build()
                .unwrap(),
            "Legacy parameter 'KeyConditions' not supported in Query with Encryption",
        ),
        (
            base().query_filter("sign", condition).build().unwrap(),
            "Legacy parameter 'QueryFilter' not supported in Query with Encryption",
        ),
        (
            base()
                .conditional_operator(ConditionalOperator::And)
                .build()
                .unwrap(),
            "Legacy parameter 'ConditionalOperator' not supported in Query with Encryption",
        ),
    ];
    for (input, message) in cases {
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-query
        //= type=test
        //# The Query request MUST NOT refer to any legacy parameters,
        //# specifically AttributesToGet, KeyConditions, QueryFilter and ConditionalOperator MUST NOT be set.
        expect_validation(transforms().query_input(input).await, message);
    }
}

#[tokio::test]
async fn query_input_expression_length() {
    // 4096 UTF-16 code units is the limit: one more fails.
    let ok = format!("bar = :{}", "b".repeat(4096 - 7));
    let input = QueryInput::builder()
        .table_name("foo")
        .key_condition_expression(ok)
        .build()
        .unwrap();
    assert_eq!(
        transforms().query_input(input.clone()).await.unwrap(),
        input
    );

    let long = "a".repeat(4097);
    let input = QueryInput::builder()
        .table_name("foo")
        .key_condition_expression(long.clone())
        .build()
        .unwrap();
    expect_validation(
        transforms().query_input(input).await,
        "KeyConditionExpression exceeds maximum length of 4096 characters.",
    );
    let input = QueryInput::builder()
        .table_name("foo")
        .filter_expression(long)
        .build()
        .unwrap();
    expect_validation(
        transforms().query_input(input).await,
        "FilterExpression exceeds maximum length of 4096 characters.",
    );
}

#[tokio::test]
async fn query_output_passthrough() {
    let output = QueryOutput::builder().build();
    let out = transforms()
        .query_output(output.clone(), &query_input("no_such_table"))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn query_output_decrypts_items() {
    let t = transforms();
    let items = vec![encrypt(&t, item_n(1)).await, encrypt(&t, item_n(2)).await];
    let output = QueryOutput::builder()
        .set_items(Some(items))
        .count(2)
        .build();
    let out = t.query_output(output, &query_input("foo")).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
    //= type=test
    //= reason=each encrypted entry comes back as its own plaintext, so each was decrypted
    //# For each list entry in `Items` in the response,
    //# if there exists an Item Encryptor specified within the
    //# [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to the `TableName` on the request,
    //# the corresponding Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md)
    //# where the input [DynamoDB Item](./decrypt-item.md#dynamodb-item)
    //# is this list entry.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
    //= type=test
    //# Each of these entries on the original response MUST be replaced
    //# with the resulting decrypted [DynamoDB Item](./decrypt-item.md#dynamodb-item-1).
    assert_eq!(out.items, Some(vec![item_n(1), item_n(2)]));
    assert_eq!(out.count, 2);
}

#[tokio::test]
async fn query_output_tampered() {
    let t = transforms();
    let mut tampered = encrypt(&t, item_n(2)).await;
    tampered.insert("sign".into(), s("sign3"));
    let output = QueryOutput::builder()
        .items(encrypt(&t, item_n(1)).await)
        .items(tampered)
        .count(2)
        .build();
    let err = t
        .query_output(output, &query_input("foo"))
        .await
        .unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-query
    //= type=test
    //# If any [Decrypt Item](./decrypt-item.md) fails,
    //# Query MUST yield an error.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn query_output_original_expression_too_long() {
    let t = transforms();
    let input = QueryInput::builder()
        .table_name("foo")
        .filter_expression("a".repeat(4097))
        .build()
        .unwrap();
    let output = QueryOutput::builder()
        .items(encrypt(&t, item_n(1)).await)
        .build();
    expect_validation(
        t.query_output(output, &input).await,
        "FilterExpression exceeds maximum length of 4096 characters.",
    );
}

#[tokio::test]
async fn get_number_of_queries_without_beacons() {
    let t = transforms();
    for table in ["foo", "no_such_table"] {
        assert_eq!(
            t.get_number_of_queries(&query_input(table)).await.unwrap(),
            1
        );
    }
}

// --- Scan ---

fn scan_input(table: &str) -> ScanInput {
    ScanInput::builder().table_name(table).build().unwrap()
}

#[tokio::test]
async fn scan_input_passthrough() {
    // On table foo, both the legacy parameter and the filter on `encrypt` are rejected.
    let input = ScanInput::builder()
        .table_name("no_such_table")
        .attributes_to_get("sign")
        .filter_expression("encrypt = :e")
        .expression_attribute_values(":e", s("x"))
        .build()
        .unwrap();
    let out = transforms().scan_input(input.clone()).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-scan
    //= type=test
    //# If the `TableName` in the request does not refer to an [encrypted-table](#encrypted-table),
    //# the Scan request MUST be unchanged.
    assert_eq!(out, input);
}

#[tokio::test]
async fn scan_input_configured_table_passthrough() {
    let input = ScanInput::builder()
        .table_name("foo")
        .filter_expression("sign = :s")
        .build()
        .unwrap();
    let out = transforms().scan_input(input.clone()).await.unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn scan_input_encrypted_field() {
    let input = ScanInput::builder()
        .table_name("foo")
        .filter_expression("begins_with(encrypt, :e)")
        .build()
        .unwrap();
    expect_validation(
        transforms().scan_input(input).await,
        "Query is using encrypted field : encrypt.",
    );
}

#[tokio::test]
async fn scan_input_legacy_parameters() {
    let condition = Condition::builder()
        .comparison_operator(ComparisonOperator::Eq)
        .attribute_value_list(s("x"))
        .build()
        .unwrap();
    let base = || ScanInput::builder().table_name("foo");
    let cases = [
        (
            base().attributes_to_get("sign").build().unwrap(),
            "Legacy parameter 'AttributesToGet' not supported in UpdateItem with Encryption",
        ),
        (
            base().scan_filter("sign", condition).build().unwrap(),
            "Legacy parameter 'ScanFilter' not supported in UpdateItem with Encryption",
        ),
        (
            base()
                .conditional_operator(ConditionalOperator::Or)
                .build()
                .unwrap(),
            "Legacy parameter 'ConditionalOperator' not supported in UpdateItem with Encryption",
        ),
    ];
    for (input, message) in cases {
        //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#modify-before-scan
        //= type=test
        //# The Scan request MUST NOT refer to any legacy parameters,
        //# specifically AttributesToGet, ScanFilter and ConditionalOperator MUST NOT be set.
        expect_validation(transforms().scan_input(input).await, message);
    }
}

#[tokio::test]
async fn scan_input_filter_expression_too_long() {
    // No spec requirement: DynamoDB's 4096-character expression limit, ported from Dafny,
    // checked before modify-before-scan's beacon rewrite. 4096 is the limit: one more fails.
    let input = ScanInput::builder()
        .table_name("foo")
        .filter_expression("a".repeat(4097))
        .build()
        .unwrap();
    expect_validation(
        transforms().scan_input(input).await,
        "FilterExpression exceeds maximum length of 4096 characters.",
    );
}

#[tokio::test]
async fn scan_output_passthrough() {
    let output = ScanOutput::builder().build();
    let out = transforms()
        .scan_output(output.clone(), &scan_input("no_such_table"))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn scan_output_decrypts_items() {
    let t = transforms();
    let output = ScanOutput::builder()
        .items(encrypt(&t, item_n(3)).await)
        .count(1)
        .build();
    let out = t.scan_output(output, &scan_input("foo")).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
    //= type=test
    //= reason=the encrypted entry comes back as its plaintext, so it was decrypted
    //# For each list entry in `Items` in the response,
    //# if there exists an Item Encryptor specified within the
    //# [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to the `TableName` on the request,
    //# the corresponding Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md)
    //# where the input [DynamoDB Item](./decrypt-item.md#dynamodb-item)
    //# is this list entry.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
    //= type=test
    //# Each of these entries on the original response MUST be replaced
    //# with the resulting decrypted
    //# [DynamoDB Item](./decrypt-item.md#dynamodb-item-1).
    assert_eq!(out.items, Some(vec![item_n(3)]));
    assert_eq!(out.count, 1);
}

#[tokio::test]
async fn scan_output_tampered() {
    let t = transforms();
    let mut tampered = encrypt(&t, item_n(2)).await;
    tampered.insert("sign".into(), s("sign3"));
    let output = ScanOutput::builder()
        .items(encrypt(&t, item_n(1)).await)
        .items(tampered)
        .count(2)
        .build();
    let err = t.scan_output(output, &scan_input("foo")).await.unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-scan
    //= type=test
    //# If any [Decrypt Item](./decrypt-item.md) operation fails,
    //# Scan MUST yield an error.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

// --- BatchGetItem ---

fn batch_get_input() -> BatchGetItemInput {
    BatchGetItemInput::builder()
        .request_items(
            "foo",
            KeysAndAttributes::builder()
                .keys(HashMap::new())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn batch_get_item_input_transform() {
    let input = batch_get_input();
    let out = transforms()
        .batch_get_item_input(input.clone())
        .await
        .unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn batch_get_item_output_transform() {
    let output = BatchGetItemOutput::builder().build();
    let out = transforms()
        .batch_get_item_output(output.clone(), &batch_get_input())
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn batch_get_item_output_decrypts_configured_tables() {
    let t = transforms();
    let output = BatchGetItemOutput::builder()
        .responses(
            "foo",
            vec![encrypt(&t, item_n(1)).await, encrypt(&t, item_n(2)).await],
        )
        .responses("baz", vec![item_n(3)])
        .build();
    let out = t
        .batch_get_item_output(output, &batch_get_input())
        .await
        .unwrap();
    let responses = out.responses.unwrap();
    assert_eq!(responses.len(), 2);

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
    //= type=test
    //= reason=foo's encrypted items come back as plaintext while unconfigured baz is untouched
    //# For each list item under each key in `Responses`,
    //# if there is a configured Item Encryptor with [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name) equal to the key,
    //# that Item Encryptor MUST perform [Decrypt Item](./decrypt-item.md) where the input
    //# [DynamoDB Item](./decrypt-item.md#dynamodb-item)
    //# is the `Item` field in the original response.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
    //= type=test
    //# Each of these items on the original response MUST be replaced
    //# with a value that is equivalent to
    //# this result.
    assert_eq!(responses["foo"], vec![item_n(1), item_n(2)]);
    assert_eq!(responses["baz"], vec![item_n(3)]);
}

#[tokio::test]
async fn batch_get_item_output_tampered() {
    let t = transforms();
    let mut encrypted = encrypt(&t, item_n(1)).await;
    encrypted.insert("bar".into(), s("bar2"));
    let output = BatchGetItemOutput::builder()
        .responses("foo", vec![encrypted])
        .build();
    let err = t
        .batch_get_item_output(output, &batch_get_input())
        .await
        .unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-batchgetitem
    //= type=test
    //# If any [Decrypt Item](./decrypt-item.md) operation fails,
    //# BatchGetItem MUST yield an error.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

// --- TransactGetItems ---

fn transact_get_input(tables: &[&str]) -> TransactGetItemsInput {
    TransactGetItemsInput::builder()
        .set_transact_items(Some(
            tables
                .iter()
                .map(|t| {
                    TransactGetItem::builder()
                        .get(
                            Get::builder()
                                .table_name(*t)
                                .set_key(Some(HashMap::new()))
                                .build()
                                .unwrap(),
                        )
                        .build()
                })
                .collect(),
        ))
        .build()
        .unwrap()
}

fn response(it: Option<Item>) -> ItemResponse {
    ItemResponse::builder().set_item(it).build()
}

#[tokio::test]
async fn transact_get_items_input_passthrough() {
    let input = transact_get_input(&["no_such_table"]);
    let out = transforms()
        .transact_get_items_input(input.clone())
        .await
        .unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn transact_get_items_output_passthrough() {
    let output = TransactGetItemsOutput::builder().build();
    let out = transforms()
        .transact_get_items_output(output.clone(), &transact_get_input(&["no_such_table"]))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn transact_get_items_output_decrypts_by_position() {
    let t = transforms();
    let output = TransactGetItemsOutput::builder()
        .responses(response(Some(encrypt(&t, item_n(1)).await)))
        .responses(response(Some(item_n(2))))
        .responses(response(None))
        .responses(response(Some(HashMap::new())))
        .build();
    let input = transact_get_input(&["foo", "baz", "foo", "foo"]);
    let out = t.transact_get_items_output(output, &input).await.unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
    //= type=test
    //= reason=only the item whose request position names configured table foo is decrypted
    //# For each list item under each key in `Responses`,
    //# if there exists an Item Encryptor specified within
    //# the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to the key,
    //# the Item Encryptor that corresponds to the key in the request
    //# MUST perform [Decrypt Item](./decrypt-item.md) where the input
    //# [DynamoDB Item](./decrypt-item.md#dynamodb-item) is the `Item` in the original response.
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
    //= type=test
    //# Each of these items on the original response MUST be replaced
    //# with a value that is equivalent to the resulting item.
    assert_eq!(
        out.responses,
        Some(vec![
            response(Some(item_n(1))),
            response(Some(item_n(2))),
            response(None),
            response(None),
        ])
    );
}

#[tokio::test]
async fn transact_get_items_output_tampered() {
    let t = transforms();
    let mut tampered = encrypt(&t, item_n(1)).await;
    tampered.insert("sign".into(), s("sign2"));
    let output = TransactGetItemsOutput::builder()
        .responses(response(Some(tampered)))
        .build();
    let err = t
        .transact_get_items_output(output, &transact_get_input(&["foo"]))
        .await
        .unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#decrypt-after-transactgetitems
    //= type=test
    //# If any [Decrypt Item](./decrypt-item.md) fails,
    //# TransactGetItems MUST yield an error.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn transact_get_items_output_count_mismatch() {
    let output = TransactGetItemsOutput::builder()
        .responses(response(None))
        .build();
    expect_validation(
        transforms()
            .transact_get_items_output(output, &transact_get_input(&["foo", "foo"]))
            .await,
        "Invalid TransactGetItems response for original request: Number of items returned must equal number of items requested.",
    );
}
