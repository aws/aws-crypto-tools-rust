// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The write transforms, ported from the Dafny `PutItemTransform.dfy`,
//! `UpdateItemTransform.dfy`, `DeleteItemTransform.dfy`, `BatchWriteItemTransform.dfy`,
//! and `TransactWriteItemsTransform.dfy`, plus the checks those files leave out.

mod transforms_support;

use std::collections::HashMap;

use aws_db_esdk::Error;
use aws_db_esdk::aws_sdk_dynamodb::operation::batch_write_item::{
    BatchWriteItemInput, BatchWriteItemOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::operation::delete_item::{DeleteItemInput, DeleteItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::get_item::{GetItemInput, GetItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::{PutItemInput, PutItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::operation::transact_write_items::{
    TransactWriteItemsInput, TransactWriteItemsOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::operation::update_item::{UpdateItemInput, UpdateItemOutput};
use aws_db_esdk::aws_sdk_dynamodb::types::{
    AttributeValue, ConditionCheck, ConditionalOperator, Delete, DeleteRequest,
    ExpectedAttributeValue, Put, PutRequest, ReturnValue, TransactWriteItem, Update, WriteRequest,
};
use aws_db_esdk::transforms::Transforms;
use aws_db_esdk::types::PlaintextOverride;
use transforms_support::{
    Item, expect_validation, item, s, transforms, transforms_with_override, transforms2,
};

fn put_input(table: &str, it: Item) -> PutItemInput {
    PutItemInput::builder()
        .table_name(table)
        .set_item(Some(it))
        .build()
        .unwrap()
}

fn item_n(i: u32) -> Item {
    item(&[
        ("bar", s(&format!("bar{i}"))),
        ("sign", s(&format!("sign{i}"))),
        ("encrypt", s(&format!("encrypt{i}"))),
        ("plain", s(&format!("plain{i}"))),
    ])
}

/// Encrypt `it` for table `foo` of `t` with the PutItem transform.
async fn encrypt(t: &Transforms, it: Item) -> Item {
    t.put_item_input(put_input("foo", it))
        .await
        .unwrap()
        .item
        .unwrap()
}

fn get_input() -> GetItemInput {
    GetItemInput::builder()
        .table_name("foo")
        .key("bar", s("bar1"))
        .build()
        .unwrap()
}

// --- PutItem ---

#[tokio::test]
async fn put_item_input_passthrough() {
    let input = put_input("no_such_table", HashMap::new());
    let out = transforms().put_item_input(input.clone()).await.unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn put_item_input_encrypts_and_signs() {
    let t = transforms();
    let encrypted = encrypt(&t, item_n(1)).await;

    // Signed and unsigned plaintext attributes are unchanged; the encrypted one is binary.
    assert_eq!(encrypted["bar"], s("bar1"));
    assert_eq!(encrypted["sign"], s("sign1"));
    assert_eq!(encrypted["plain"], s("plain1"));
    assert!(matches!(&encrypted["encrypt"], AttributeValue::B(_)));
    let mut names: Vec<&str> = encrypted.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "aws_dbe_foot",
            "aws_dbe_head",
            "bar",
            "encrypt",
            "plain",
            "sign"
        ]
    );

    // The GetItem output transform decrypts it back to the original.
    let out = t
        .get_item_output(
            GetItemOutput::builder().set_item(Some(encrypted)).build(),
            &get_input(),
        )
        .await
        .unwrap();
    assert_eq!(out.item, Some(item_n(1)));
}

#[tokio::test]
async fn put_item_attribute_name_too_long_bytes() {
    // 0xE9 is a 2-byte UTF-8 char, so 40000 chars => 80000 bytes, exceeding the 65535-byte limit.
    let long_key: String = std::iter::repeat_n('\u{e9}', 40000).collect();
    let input = put_input(
        "foo",
        item(&[
            ("bar", s("key")),
            ("encrypt", AttributeValue::M(item(&[(&long_key, s("x"))]))),
        ]),
    );
    let result = transforms().put_item_input(input).await;
    match result {
        Err(e) => assert_eq!(
            e.message(),
            "Attribute name must be between 1 and 65535 UTF-8 bytes"
        ),
        Ok(v) => panic!("expected failure, got {v:?}"),
    }
}

#[tokio::test]
async fn put_item_input_legacy_expected() {
    let input = PutItemInput::builder()
        .table_name("foo")
        .set_item(Some(item_n(1)))
        .expected(
            "sign",
            ExpectedAttributeValue::builder().value(s("x")).build(),
        )
        .build()
        .unwrap();
    expect_validation(
        transforms().put_item_input(input).await,
        "Legacy parameter 'Expected' not supported in PutItem with Encryption.",
    );
}

#[tokio::test]
async fn put_item_input_legacy_conditional_operator() {
    let input = PutItemInput::builder()
        .table_name("foo")
        .set_item(Some(item_n(1)))
        .conditional_operator(ConditionalOperator::And)
        .build()
        .unwrap();
    expect_validation(
        transforms().put_item_input(input).await,
        "Legacy parameter 'ConditionalOperator' not supported in PutItem with Encryption.",
    );
}

#[tokio::test]
async fn put_item_input_reserved_attributes() {
    let mut it = item_n(1);
    it.insert("aws_dbe_zzz".into(), s("x"));
    it.insert("aws_dbe_head".into(), s("x"));

    //= spec/dynamodb-encryption-client/ddb-support.md#writable
    //= type=test
    //# Writeable MUST reject any item containing an attribute which begins with `aws_dbe_`.
    expect_validation(
        transforms().put_item_input(put_input("foo", it)).await,
        "Writing reserved attributes not allowed : aws_dbe_head\naws_dbe_zzz",
    );
}

#[tokio::test]
async fn put_item_input_condition_on_encrypted() {
    let input = PutItemInput::builder()
        .table_name("foo")
        .set_item(Some(item_n(1)))
        .condition_expression("#e = :v AND sign = :v")
        .expression_attribute_names("#e", "encrypt")
        .build()
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-support.md#testconditionexpression
    //= type=test
    //# TestConditionExpression MUST fail if any operand in the condition expression is an encrypted attribute name.
    expect_validation(
        transforms().put_item_input(input).await,
        "Condition Expressions forbidden on encrypted attributes : encrypt",
    );
}

/// `attribute_not_exists` and the other value-ignoring functions do not read the
/// attribute they name, so they may name an encrypted one (`FilterExpr.ExtractAttributes`).
#[tokio::test]
async fn put_item_input_existence_check_on_encrypted() {
    let input = PutItemInput::builder()
        .table_name("foo")
        .set_item(Some(item_n(1)))
        .condition_expression("attribute_not_exists(#e) AND sign = :v")
        .expression_attribute_names("#e", "encrypt")
        .build()
        .unwrap();
    let out = transforms().put_item_input(input).await.unwrap();
    assert_eq!(
        out.condition_expression.as_deref(),
        Some("attribute_not_exists(#e) AND sign = :v")
    );
    assert!(matches!(out.item.unwrap()["encrypt"], AttributeValue::B(_)));
}

#[tokio::test]
async fn put_item_input_condition_on_signed_is_allowed() {
    let input = PutItemInput::builder()
        .table_name("foo")
        .set_item(Some(item_n(1)))
        .condition_expression("attribute_not_exists(sign)")
        .build()
        .unwrap();
    let out = transforms().put_item_input(input).await.unwrap();
    assert_eq!(
        out.condition_expression.as_deref(),
        Some("attribute_not_exists(sign)")
    );
    assert!(out.item.unwrap().contains_key("aws_dbe_head"));
}

#[tokio::test]
async fn put_item_input_force_plaintext_write() {
    let t = transforms_with_override(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead);
    let input = put_input("foo", item_n(1));
    let out = t.put_item_input(input.clone()).await.unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn put_item_output_passthrough() {
    let output = PutItemOutput::builder().build();
    let out = transforms()
        .put_item_output(output.clone(), &put_input("no_such_table", HashMap::new()))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn put_item_output_decrypts_old_item() {
    let t = transforms();
    let old = encrypt(&t, item_n(2)).await;
    let out = t
        .put_item_output(
            PutItemOutput::builder().set_attributes(Some(old)).build(),
            &put_input("foo", item_n(1)),
        )
        .await
        .unwrap();
    assert_eq!(out.attributes, Some(item_n(2)));
}

#[tokio::test]
async fn put_item_output_empty_attributes_passthrough() {
    let output = PutItemOutput::builder()
        .set_attributes(Some(HashMap::new()))
        .build();
    let out = transforms()
        .put_item_output(output.clone(), &put_input("foo", item_n(1)))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn put_item_output_tampered_old_item() {
    let t = transforms();
    let mut old = encrypt(&t, item_n(2)).await;
    old.insert("sign".into(), s("tampered"));
    let err = t
        .put_item_output(
            PutItemOutput::builder().set_attributes(Some(old)).build(),
            &put_input("foo", item_n(1)),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

// --- UpdateItem ---

fn update_input(table: &str, expr: Option<&str>) -> UpdateItemInput {
    UpdateItemInput::builder()
        .table_name(table)
        .set_key(Some(HashMap::new()))
        .set_update_expression(expr.map(str::to_owned))
        .build()
        .unwrap()
}

#[tokio::test]
async fn update_item_input_passthrough() {
    let input = update_input("no_such_table", None);
    let out = transforms().update_item_input(input.clone()).await.unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn update_item_input_update_expression_signed() {
    //= spec/dynamodb-encryption-client/ddb-support.md#testupdateexpression
    //= type=test
    //# TestUpdateExpression MUST fail if any operand in the update expression is a signed attribute name.
    expect_validation(
        transforms()
            .update_item_input(update_input("foo", Some("SET sign = :p")))
            .await,
        "Update Expressions forbidden on signed attributes : sign",
    );
}

#[tokio::test]
async fn update_item_input_update_expression_encrypted() {
    //= spec/dynamodb-encryption-client/ddb-support.md#testupdateexpression
    //= type=test
    //# TestUpdateExpression MUST fail if any operand in the update expression is a signed attribute name.
    expect_validation(
        transforms()
            .update_item_input(update_input("foo", Some("SET encrypt = :p")))
            .await,
        "Update Expressions forbidden on signed attributes : encrypt",
    );
}

#[tokio::test]
async fn update_item_input_update_expression_plain() {
    // Dafny uses `no_such_table` here; `foo` also lets an unsigned attribute be updated.
    for table in ["no_such_table", "foo"] {
        let input = update_input(table, Some("SET plain = :p"));
        let out = transforms().update_item_input(input.clone()).await.unwrap();
        assert_eq!(out, input);
    }
}

#[tokio::test]
async fn update_item_input_update_expression_names() {
    let input = UpdateItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .update_expression("SET #s = :p")
        .expression_attribute_names("#s", "sign")
        .build()
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-support.md#testupdateexpression
    //= type=test
    //# TestUpdateExpression MUST fail if any operand in the update expression is a signed attribute name.
    expect_validation(
        transforms().update_item_input(input).await,
        "Update Expressions forbidden on signed attributes : sign",
    );
}

#[tokio::test]
async fn update_item_input_legacy_parameters() {
    let base = || {
        UpdateItemInput::builder()
            .table_name("foo")
            .set_key(Some(HashMap::new()))
    };
    let cases = [
        (
            base()
                .expected("sign", ExpectedAttributeValue::builder().build())
                .build()
                .unwrap(),
            "Legacy parameter 'Expected' not supported in UpdateItem with Encryption",
        ),
        (
            base()
                .attribute_updates(
                    "plain",
                    aws_db_esdk::aws_sdk_dynamodb::types::AttributeValueUpdate::builder()
                        .value(s("x"))
                        .build(),
                )
                .build()
                .unwrap(),
            "Legacy parameter 'AttributeUpdates' not supported in UpdateItem with Encryption",
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
        expect_validation(transforms().update_item_input(input).await, message);
    }
}

#[tokio::test]
async fn update_item_output_passthrough() {
    let output = UpdateItemOutput::builder().build();
    let out = transforms()
        .update_item_output(output.clone(), &update_input("no_such_table", None))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn update_item_output_partial_signed_attributes() {
    let output = UpdateItemOutput::builder()
        .attributes("sign", s("x"))
        .build();
    let input = UpdateItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .return_values(ReturnValue::UpdatedNew)
        .build()
        .unwrap();
    expect_validation(
        transforms().update_item_output(output, &input).await,
        "UpdateItems response contains signed attributes, but does not include the entire item which is required for verification.",
    );
}

#[tokio::test]
async fn update_item_output_partial_unsigned_attributes() {
    // Only unsigned (or unknown) attributes: nothing to verify, so they pass through.
    let output = UpdateItemOutput::builder()
        .attributes("plain", s("x"))
        .attributes("unknown", s("y"))
        .build();
    let input = UpdateItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .return_values(ReturnValue::UpdatedOld)
        .build()
        .unwrap();
    let out = transforms()
        .update_item_output(output.clone(), &input)
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn update_item_output_whole_item_decrypts() {
    let t = transforms();
    for rv in [ReturnValue::AllNew, ReturnValue::AllOld] {
        let encrypted = encrypt(&t, item_n(3)).await;
        let input = UpdateItemInput::builder()
            .table_name("foo")
            .set_key(Some(HashMap::new()))
            .return_values(rv)
            .build()
            .unwrap();
        let out = t
            .update_item_output(
                UpdateItemOutput::builder()
                    .set_attributes(Some(encrypted))
                    .build(),
                &input,
            )
            .await
            .unwrap();
        assert_eq!(out.attributes, Some(item_n(3)));
    }
}

// --- DeleteItem ---

fn delete_input(table: &str) -> DeleteItemInput {
    DeleteItemInput::builder()
        .table_name(table)
        .set_key(Some(HashMap::new()))
        .build()
        .unwrap()
}

#[tokio::test]
async fn delete_item_input_passthrough() {
    let input = delete_input("no_such_table");
    let out = transforms().delete_item_input(input.clone()).await.unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn delete_item_input_configured_table_passthrough() {
    let input = DeleteItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .condition_expression("sign = :v")
        .build()
        .unwrap();
    let out = transforms().delete_item_input(input.clone()).await.unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn delete_item_input_condition_on_encrypted() {
    let input = DeleteItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .condition_expression("encrypt = :v")
        .build()
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-support.md#testconditionexpression
    //= type=test
    //# TestConditionExpression MUST fail if any operand in the condition expression is an encrypted attribute name.
    expect_validation(
        transforms().delete_item_input(input).await,
        "Condition Expressions forbidden on encrypted attributes : encrypt",
    );
}

#[tokio::test]
async fn delete_item_input_legacy_parameters() {
    let expected = DeleteItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .expected("sign", ExpectedAttributeValue::builder().build())
        .build()
        .unwrap();
    expect_validation(
        transforms().delete_item_input(expected).await,
        "Legacy parameter 'Expected' not supported in UpdateItem with Encryption",
    );
    let op = DeleteItemInput::builder()
        .table_name("foo")
        .set_key(Some(HashMap::new()))
        .conditional_operator(ConditionalOperator::And)
        .build()
        .unwrap();
    expect_validation(
        transforms().delete_item_input(op).await,
        "Legacy parameter 'ConditionalOperator' not supported in UpdateItem with Encryption",
    );
}

#[tokio::test]
async fn delete_item_output_passthrough() {
    let output = DeleteItemOutput::builder().build();
    let out = transforms()
        .delete_item_output(output.clone(), &delete_input("no_such_table"))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn delete_item_output_decrypts_old_item() {
    let t = transforms();
    let old = encrypt(&t, item_n(4)).await;
    let out = t
        .delete_item_output(
            DeleteItemOutput::builder()
                .set_attributes(Some(old))
                .build(),
            &delete_input("foo"),
        )
        .await
        .unwrap();
    assert_eq!(out.attributes, Some(item_n(4)));
}

// --- BatchWriteItem ---

fn make_put(it: Item) -> WriteRequest {
    WriteRequest::builder()
        .put_request(PutRequest::builder().set_item(Some(it)).build().unwrap())
        .build()
}

fn batch_input(tables: &[(&str, Vec<WriteRequest>)]) -> BatchWriteItemInput {
    BatchWriteItemInput::builder()
        .set_request_items(Some(
            tables
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        ))
        .build()
        .unwrap()
}

#[tokio::test]
async fn batch_write_item_input_transform() {
    let input = batch_input(&[("foo", vec![WriteRequest::builder().build()])]);
    let out = transforms()
        .batch_write_item_input(input.clone())
        .await
        .unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn batch_write_item_input_no_request_items() {
    let input = BatchWriteItemInput::builder().build().unwrap();
    let out = transforms()
        .batch_write_item_input(input.clone())
        .await
        .unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn batch_write_item_input_encrypts_puts_only() {
    let delete = WriteRequest::builder()
        .delete_request(
            DeleteRequest::builder()
                .key("bar", s("bar9"))
                .build()
                .unwrap(),
        )
        .build();
    let input = batch_input(&[
        ("foo", vec![make_put(item_n(1)), delete.clone()]),
        ("baz", vec![make_put(item_n(2))]),
    ]);
    let out = transforms().batch_write_item_input(input).await.unwrap();
    let items = out.request_items.unwrap();
    let foo = &items["foo"];
    let put = &foo[0].put_request.as_ref().unwrap().item;
    assert!(put.contains_key("aws_dbe_head"));
    assert!(matches!(&put["encrypt"], AttributeValue::B(_)));
    assert_eq!(foo[1], delete);
    assert_eq!(items["baz"], vec![make_put(item_n(2))]);
}

#[tokio::test]
async fn batch_write_item_input_reserved_attribute() {
    let mut it = item_n(1);
    it.insert("aws_dbe_b_x".into(), s("x"));

    //= spec/dynamodb-encryption-client/ddb-support.md#writable
    //= type=test
    //# Writeable MUST reject any item containing an attribute which begins with `aws_dbe_`.
    expect_validation(
        transforms()
            .batch_write_item_input(batch_input(&[("foo", vec![make_put(it)])]))
            .await,
        "Writing reserved attributes not allowed : aws_dbe_b_x",
    );
}

#[tokio::test]
async fn batch_write_item_output_transform() {
    let output = BatchWriteItemOutput::builder().build();
    let input = batch_input(&[("foo", vec![WriteRequest::builder().build()])]);
    let out = transforms()
        .batch_write_item_output(output.clone(), &input)
        .await
        .unwrap();
    assert_eq!(out, output);
}

/// Encrypt `input`, return all of it as unprocessed, and expect the original plaintext back.
async fn round_trip_unprocessed(t: &Transforms, input: BatchWriteItemInput) {
    let encrypted = t
        .batch_write_item_input(input.clone())
        .await
        .unwrap()
        .request_items
        .unwrap();
    assert_ne!(Some(&encrypted), input.request_items.as_ref());
    let output = BatchWriteItemOutput::builder()
        .set_unprocessed_items(Some(encrypted))
        .build();
    let out = t.batch_write_item_output(output, &input).await.unwrap();
    assert_eq!(out.unprocessed_items, input.request_items);
}

// Each item in UnprocessedItems must be replaced by its original plaintext value.
#[tokio::test]
async fn batch_write_item_output_transform_unprocessed() {
    let input = batch_input(&[(
        "foo",
        vec![
            make_put(item_n(1)),
            make_put(item_n(2)),
            make_put(item_n(3)),
            make_put(item_n(4)),
        ],
    )]);
    round_trip_unprocessed(&transforms(), input).await;
}

#[tokio::test]
async fn batch_write_item_output_transform_unprocessed2() {
    let input = batch_input(&[
        ("foo", vec![make_put(item_n(1)), make_put(item_n(2))]),
        ("baz", vec![make_put(item_n(3)), make_put(item_n(4))]),
    ]);
    round_trip_unprocessed(&transforms(), input).await;
}

#[tokio::test]
async fn batch_write_item_output_transform_unprocessed3() {
    let t = transforms();
    let input = batch_input(&[
        ("foo", vec![make_put(item_n(1)), make_put(item_n(2))]),
        ("baz", vec![make_put(item_n(3)), make_put(item_n(4))]),
    ]);
    let encrypted = t
        .batch_write_item_input(input.clone())
        .await
        .unwrap()
        .request_items
        .unwrap();
    let unprocessed: HashMap<String, Vec<WriteRequest>> = encrypted
        .into_iter()
        .map(|(k, v)| (k, v[0..1].to_vec()))
        .collect();
    let output = BatchWriteItemOutput::builder()
        .set_unprocessed_items(Some(unprocessed))
        .build();
    let out = t.batch_write_item_output(output, &input).await.unwrap();
    let expected = HashMap::from([
        ("foo".to_owned(), vec![make_put(item_n(1))]),
        ("baz".to_owned(), vec![make_put(item_n(3))]),
    ]);
    assert_eq!(out.unprocessed_items, Some(expected));
}

#[tokio::test]
async fn batch_write_item_output_transform_unprocessed4() {
    // With sort key `sign`, items sharing the partition key `bar1` are told apart by it.
    let item1a = item(&[
        ("bar", s("bar1")),
        ("sign", s("sign2")),
        ("encrypt", s("encrypt2")),
        ("plain", s("plain2")),
    ]);
    let item1b = item(&[
        ("bar", s("bar1")),
        ("sign", s("sign3")),
        ("encrypt", s("encrypt3")),
        ("plain", s("plain3")),
    ]);
    let item1c = item(&[
        ("bar", s("bar1")),
        ("sign", s("sign4")),
        ("encrypt", s("encrypt4")),
        ("plain", s("plain4")),
    ]);
    let input = batch_input(&[
        ("foo", vec![make_put(item_n(1)), make_put(item1a)]),
        ("baz", vec![make_put(item1b), make_put(item1c)]),
    ]);
    round_trip_unprocessed(&transforms2(), input).await;
}

#[tokio::test]
async fn batch_write_item_output_sort_key_selects_original() {
    // Only the second item of `foo` is unprocessed; it shares its partition key with the first.
    let t = transforms2();
    let first = item_n(1);
    let mut second = item_n(2);
    second.insert("bar".into(), s("bar1"));
    let input = batch_input(&[("foo", vec![make_put(first), make_put(second.clone())])]);
    let encrypted = t
        .batch_write_item_input(input.clone())
        .await
        .unwrap()
        .request_items
        .unwrap();
    let unprocessed = HashMap::from([("foo".to_owned(), encrypted["foo"][1..].to_vec())]);
    let out = t
        .batch_write_item_output(
            BatchWriteItemOutput::builder()
                .set_unprocessed_items(Some(unprocessed))
                .build(),
            &input,
        )
        .await
        .unwrap();
    assert_eq!(
        out.unprocessed_items,
        Some(HashMap::from([("foo".to_owned(), vec![make_put(second)])]))
    );
}

#[tokio::test]
async fn batch_write_item_output_unprocessed_delete_passes_through() {
    let delete = WriteRequest::builder()
        .delete_request(
            DeleteRequest::builder()
                .key("bar", s("bar1"))
                .build()
                .unwrap(),
        )
        .build();
    let input = batch_input(&[("foo", vec![delete.clone()])]);
    let output = BatchWriteItemOutput::builder()
        .unprocessed_items("foo", vec![delete.clone()])
        .build();
    let out = transforms()
        .batch_write_item_output(output.clone(), &input)
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn batch_write_item_output_table_not_in_request() {
    let input = batch_input(&[("baz", vec![make_put(item_n(1))])]);
    let output = BatchWriteItemOutput::builder()
        .unprocessed_items("foo", vec![make_put(item_n(1))])
        .build();
    expect_validation(
        transforms().batch_write_item_output(output, &input).await,
        "foo in UnprocessedItems for BatchWriteItem response, but not in original request.",
    );
}

#[tokio::test]
async fn batch_write_item_output_item_not_in_request() {
    let input = batch_input(&[("foo", vec![make_put(item_n(1))])]);
    let output = BatchWriteItemOutput::builder()
        .unprocessed_items("foo", vec![make_put(item_n(2))])
        .build();
    expect_validation(
        transforms().batch_write_item_output(output, &input).await,
        "Item in UnprocessedItems not found in original request.",
    );
}

#[tokio::test]
async fn batch_write_item_output_missing_keys() {
    let input = batch_input(&[("foo", vec![make_put(item_n(1))])]);
    let no_partition = item(&[("sign", s("sign1"))]);
    let output = BatchWriteItemOutput::builder()
        .unprocessed_items("foo", vec![make_put(no_partition)])
        .build();
    expect_validation(
        transforms().batch_write_item_output(output, &input).await,
        "Required partition key not in unprocessed item",
    );

    let no_sort = item(&[("bar", s("bar1"))]);
    let output = BatchWriteItemOutput::builder()
        .unprocessed_items("foo", vec![make_put(no_sort)])
        .build();
    expect_validation(
        transforms2().batch_write_item_output(output, &input).await,
        "Required sort key not in unprocessed item",
    );
}

#[tokio::test]
async fn batch_write_item_force_plaintext_write() {
    // Writes are plaintext, so neither the request nor the unprocessed items change.
    let t = transforms_with_override(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead);
    let input = batch_input(&[("foo", vec![make_put(item_n(1))])]);
    assert_eq!(
        t.batch_write_item_input(input.clone()).await.unwrap(),
        input
    );
    let output = BatchWriteItemOutput::builder()
        .unprocessed_items("foo", vec![make_put(item_n(1))])
        .build();
    assert_eq!(
        t.batch_write_item_output(output.clone(), &input)
            .await
            .unwrap(),
        output
    );
}

// --- TransactWriteItems ---

fn transact_input(items: Vec<TransactWriteItem>) -> TransactWriteItemsInput {
    TransactWriteItemsInput::builder()
        .set_transact_items(Some(items))
        .build()
        .unwrap()
}

#[tokio::test]
async fn transact_write_items_input_passthrough() {
    let input = transact_input(vec![
        TransactWriteItem::builder()
            .delete(
                Delete::builder()
                    .key("this", s("that"))
                    .table_name("bar")
                    .build()
                    .unwrap(),
            )
            .build(),
    ]);
    let out = transforms()
        .transact_write_items_input(input.clone())
        .await
        .unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn transact_write_items_input_empty() {
    expect_validation(
        transforms()
            .transact_write_items_input(transact_input(vec![TransactWriteItem::builder().build()]))
            .await,
        "Each item in TransactWriteItems must specify at least one supported operation",
    );
}

#[tokio::test]
async fn transact_write_items_input_no_items() {
    let input = TransactWriteItemsInput::builder().build().unwrap();
    let out = transforms()
        .transact_write_items_input(input.clone())
        .await
        .unwrap();
    assert_eq!(out, input);
}

#[tokio::test]
async fn transact_write_items_output_transform() {
    let output = TransactWriteItemsOutput::builder().build();
    let input = transact_input(vec![TransactWriteItem::builder().build()]);
    let out = transforms()
        .transact_write_items_output(output.clone(), &input)
        .await
        .unwrap();
    assert_eq!(out, output);
}

fn transact_put(table: &str, it: Item, condition: Option<&str>) -> TransactWriteItem {
    TransactWriteItem::builder()
        .put(
            Put::builder()
                .table_name(table)
                .set_item(Some(it))
                .set_condition_expression(condition.map(str::to_owned))
                .build()
                .unwrap(),
        )
        .build()
}

#[tokio::test]
async fn transact_write_items_input_encrypts_puts() {
    let t = transforms();
    let input = transact_input(vec![
        transact_put("foo", item_n(1), Some("attribute_not_exists(bar)")),
        transact_put("baz", item_n(2), None),
    ]);
    let out = t.transact_write_items_input(input).await.unwrap();
    let items = out.transact_items.unwrap();
    let encrypted = items[0].put.as_ref().unwrap().item.clone();
    assert!(matches!(&encrypted["encrypt"], AttributeValue::B(_)));
    assert_eq!(items[1], transact_put("baz", item_n(2), None));
    let decrypted = t
        .get_item_output(
            GetItemOutput::builder().set_item(Some(encrypted)).build(),
            &get_input(),
        )
        .await
        .unwrap();
    assert_eq!(decrypted.item, Some(item_n(1)));
}

#[tokio::test]
async fn transact_write_items_input_rejections() {
    let condition_check = |expr: &str| {
        TransactWriteItem::builder()
            .condition_check(
                ConditionCheck::builder()
                    .table_name("foo")
                    .set_key(Some(HashMap::new()))
                    .condition_expression(expr)
                    .build()
                    .unwrap(),
            )
            .build()
    };
    let delete = |expr: &str| {
        TransactWriteItem::builder()
            .delete(
                Delete::builder()
                    .table_name("foo")
                    .set_key(Some(HashMap::new()))
                    .condition_expression(expr)
                    .build()
                    .unwrap(),
            )
            .build()
    };
    let update = |update: &str, condition: Option<&str>| {
        TransactWriteItem::builder()
            .update(
                Update::builder()
                    .table_name("foo")
                    .set_key(Some(HashMap::new()))
                    .update_expression(update)
                    .set_condition_expression(condition.map(str::to_owned))
                    .build()
                    .unwrap(),
            )
            .build()
    };
    let mut reserved = item_n(1);
    reserved.insert("aws_dbe_foot".into(), s("x"));
    let cases = [
        (
            condition_check("encrypt = :v"),
            "Condition Expressions forbidden on encrypted attributes : encrypt",
        ),
        (
            delete("encrypt = :v"),
            "Condition Expressions forbidden on encrypted attributes : encrypt",
        ),
        (
            update("SET sign = :v", None),
            "Update Expressions forbidden on signed attributes : sign",
        ),
        (
            update("SET plain = :v", Some("encrypt = :w")),
            "Condition Expressions forbidden on encrypted attributes : encrypt",
        ),
        (
            transact_put("foo", reserved, None),
            "Writing reserved attributes not allowed : aws_dbe_foot",
        ),
        (
            transact_put("foo", item_n(1), Some("encrypt = :v")),
            "Condition Expressions forbidden on encrypted attributes : encrypt",
        ),
    ];
    // Writeable, TestConditionExpression and TestUpdateExpression are each cited by their dedicated tests.
    for (action, message) in cases {
        expect_validation(
            transforms()
                .transact_write_items_input(transact_input(vec![action]))
                .await,
            message,
        );
    }
}

#[tokio::test]
async fn transact_write_items_input_allowed_actions_pass_through() {
    let check = TransactWriteItem::builder()
        .condition_check(
            ConditionCheck::builder()
                .table_name("foo")
                .set_key(Some(HashMap::new()))
                .condition_expression("sign = :v")
                .build()
                .unwrap(),
        )
        .build();
    let delete = TransactWriteItem::builder()
        .delete(
            Delete::builder()
                .table_name("foo")
                .set_key(Some(HashMap::new()))
                .build()
                .unwrap(),
        )
        .build();
    let update = TransactWriteItem::builder()
        .update(
            Update::builder()
                .table_name("foo")
                .set_key(Some(HashMap::new()))
                .update_expression("SET plain = :v")
                .condition_expression("sign = :w")
                .build()
                .unwrap(),
        )
        .build();
    let input = transact_input(vec![check, delete, update]);
    let out = transforms()
        .transact_write_items_input(input.clone())
        .await
        .unwrap();
    assert_eq!(out, input);
}
