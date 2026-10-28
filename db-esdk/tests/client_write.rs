// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Client` write operations end to end against an in-process fake DynamoDB:
//! PutItem, UpdateItem, DeleteItem, BatchWriteItem, and TransactWriteItems.

mod client_support;

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_db_esdk::aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_db_esdk::aws_sdk_dynamodb::types::{
    AttributeValue, AttributeValueUpdate, ConditionCheck, Delete, DeleteRequest,
    ExpectedAttributeValue, Put, PutRequest, ReturnValue, TransactWriteItem, Update, WriteRequest,
};
use aws_db_esdk::error::{ConflictReason, Service};
use aws_db_esdk::types::PlaintextOverride;
use aws_db_esdk::{Client, Error, TableConfig};
use client_support::fake::REQUEST_ID;
use client_support::{
    Item, PLAIN_TABLE, TABLE, dafny_item, fake, full_item, item, key, keyring, s, setup,
};

async fn get(client: &Client, table: &str, k: Item) -> Result<Option<Item>, Error> {
    let out = client
        .get_item()
        .table_name(table)
        .set_key(Some(k))
        .send()
        .await?;
    Ok(out.item().cloned())
}

async fn put(client: &Client, table: &str, i: Item) {
    client
        .put_item()
        .table_name(table)
        .set_item(Some(i))
        .send()
        .await
        .expect("the put succeeds");
}

fn put_request(i: Item) -> WriteRequest {
    WriteRequest::builder()
        .put_request(PutRequest::builder().set_item(Some(i)).build().unwrap())
        .build()
}

fn delete_request(k: Item) -> WriteRequest {
    WriteRequest::builder()
        .delete_request(DeleteRequest::builder().set_key(Some(k)).build().unwrap())
        .build()
}

/// Assert `stored` is the encrypted form of `plaintext`: the same signed and unsigned
/// attributes, `encrypt` as ciphertext, and the header and footer.
fn assert_encrypted(stored: &Item, plaintext: &Item) {
    let mut names: Vec<&str> = stored.keys().map(String::as_str).collect();
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
    for name in ["bar", "sign", "plain"] {
        assert_eq!(stored[name], plaintext[name], "{name} is stored as written");
    }
    let AttributeValue::S(secret) = &plaintext["encrypt"] else {
        panic!("the plaintext secret is a string");
    };
    let AttributeValue::B(ciphertext) = &stored["encrypt"] else {
        panic!(
            "encrypt is stored as ciphertext, not {:?}",
            stored["encrypt"]
        );
    };
    assert!(
        !ciphertext
            .as_ref()
            .windows(secret.len())
            .any(|w| w == secret.as_bytes()),
        "the ciphertext does not contain the plaintext"
    );
    assert!(matches!(stored["aws_dbe_head"], AttributeValue::B(_)));
    assert!(matches!(stored["aws_dbe_foot"], AttributeValue::B(_)));
}

#[tokio::test]
async fn put_item_stores_the_item_encrypted_and_get_item_decrypts_it() {
    let (fake, client) = setup();
    let plaintext = full_item("a", "1");

    put(&client, TABLE, plaintext.clone()).await;

    let stored = fake.item(TABLE, &key("a", "1")).unwrap();
    assert_encrypted(&stored, &plaintext);
    assert_eq!(
        get(&client, TABLE, key("a", "1")).await.unwrap(),
        Some(plaintext)
    );
}

#[tokio::test]
async fn an_item_moved_to_another_key_fails_verification() {
    let (fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;
    let mut moved = fake.item(TABLE, &key("a", "1")).unwrap();
    moved.insert("sign".to_owned(), s("2"));
    fake.set_item(TABLE, &moved);

    let err = get(&client, TABLE, key("a", "2")).await.unwrap_err();

    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn a_modified_ciphertext_fails_verification() {
    let (fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;
    let mut stored = fake.item(TABLE, &key("a", "1")).unwrap();
    let AttributeValue::B(ct) = &stored["encrypt"] else {
        panic!("encrypt is ciphertext");
    };
    let mut bytes = ct.clone().into_inner();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    stored.insert("encrypt".to_owned(), AttributeValue::B(bytes.into()));
    fake.set_item(TABLE, &stored);

    let err = get(&client, TABLE, key("a", "1")).await.unwrap_err();

    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn an_unsigned_attribute_can_change_in_the_table() {
    let (fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;
    let mut stored = fake.item(TABLE, &key("a", "1")).unwrap();
    stored.insert("plain".to_owned(), s("changed"));
    fake.set_item(TABLE, &stored);

    let got = get(&client, TABLE, key("a", "1")).await.unwrap().unwrap();

    let mut expected = full_item("a", "1");
    expected.insert("plain".to_owned(), s("changed"));
    assert_eq!(got, expected);
}

#[tokio::test]
async fn an_item_of_an_unconfigured_table_passes_through() {
    let (fake, client) = setup();
    let plaintext = full_item("a", "1");

    put(&client, PLAIN_TABLE, plaintext.clone()).await;

    assert_eq!(fake.items(PLAIN_TABLE), std::slice::from_ref(&plaintext));
    assert_eq!(
        get(&client, PLAIN_TABLE, key("a", "1")).await.unwrap(),
        Some(plaintext)
    );
}

#[tokio::test]
async fn force_plaintext_write_stores_the_item_unencrypted() {
    let fake = fake();
    let config = TableConfig::builder()
        .logical_table_name(TABLE)
        .partition_key_name("bar")
        .sort_key_name("sign")
        .attribute_actions_on_encrypt("bar", aws_db_esdk::types::CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sign", aws_db_esdk::types::CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("encrypt", aws_db_esdk::types::CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("plain", aws_db_esdk::types::CryptoAction::DoNothing)
        .allowed_unsigned_attributes("plain")
        .plaintext_override(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead)
        .keyring(keyring())
        .build()
        .unwrap();
    let client = Client::builder()
        .ddb_client(fake.client())
        .table_encryption_configs(TABLE, config)
        .build()
        .unwrap();
    let plaintext = full_item("a", "1");

    put(&client, TABLE, plaintext.clone()).await;

    assert_eq!(fake.items(TABLE), std::slice::from_ref(&plaintext));
    assert_eq!(
        get(&client, TABLE, key("a", "1")).await.unwrap(),
        Some(plaintext)
    );
}

#[tokio::test]
async fn put_item_returns_the_replaced_item_decrypted() {
    let (_fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;
    let mut replacement = full_item("a", "1");
    replacement.insert("encrypt".to_owned(), s("new secret"));

    let out = client
        .put_item()
        .table_name(TABLE)
        .set_item(Some(replacement))
        .return_values(ReturnValue::AllOld)
        .send()
        .await
        .unwrap();

    assert_eq!(out.attributes(), Some(&full_item("a", "1")));
}

#[tokio::test]
async fn put_item_rejects_reserved_attributes_before_calling_dynamodb() {
    let (fake, client) = setup();
    let mut bad = full_item("a", "1");
    bad.insert("aws_dbe_head".to_owned(), s("mine"));

    let err = client
        .put_item()
        .table_name(TABLE)
        .set_item(Some(bad))
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "Writing reserved attributes not allowed : aws_dbe_head"
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn put_item_rejects_a_condition_on_an_encrypted_attribute() {
    let (fake, client) = setup();

    let err = client
        .put_item()
        .table_name(TABLE)
        .set_item(Some(full_item("a", "1")))
        .condition_expression("encrypt = :v")
        .expression_attribute_values(":v", s("guess"))
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "Condition Expressions forbidden on encrypted attributes : encrypt"
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn put_item_rejects_the_legacy_expected_parameter() {
    let (fake, client) = setup();

    let err = client
        .put_item()
        .table_name(TABLE)
        .set_item(Some(full_item("a", "1")))
        .expected(
            "sign",
            ExpectedAttributeValue::builder().exists(false).build(),
        )
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn a_failed_condition_is_a_conflict_with_dynamodbs_error() {
    let (_fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;
    let mut second = full_item("a", "1");
    second.insert("encrypt".to_owned(), s("other"));

    let err = client
        .put_item()
        .table_name(TABLE)
        .set_item(Some(second))
        .condition_expression("attribute_not_exists(bar)")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    assert!(matches!(
        err.as_service_error::<PutItemError>(),
        Some(PutItemError::ConditionalCheckFailedException(_))
    ));
    assert_eq!(err.code(), Some("ConditionalCheckFailedException"));
    assert_eq!(err.service(), Some(&Service::DynamoDb));
    assert_eq!(err.request_id(), Some(REQUEST_ID));
    assert_eq!(
        get(&client, TABLE, key("a", "1")).await.unwrap(),
        Some(full_item("a", "1"))
    );
}

#[tokio::test]
async fn update_item_of_an_unsigned_attribute_keeps_the_item_verifiable() {
    let (fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;

    let out = client
        .update_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .update_expression("SET plain = :p")
        .expression_attribute_values(":p", s("updated"))
        .return_values(ReturnValue::AllNew)
        .send()
        .await
        .unwrap();

    let mut expected = full_item("a", "1");
    expected.insert("plain".to_owned(), s("updated"));
    assert_eq!(out.attributes(), Some(&expected));
    assert_eq!(
        fake.item(TABLE, &key("a", "1")).unwrap()["plain"],
        s("updated")
    );
    assert_eq!(
        get(&client, TABLE, key("a", "1")).await.unwrap(),
        Some(expected)
    );
}

#[tokio::test]
async fn update_item_returns_the_updated_unsigned_attributes() {
    let (_fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;

    let out = client
        .update_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .update_expression("SET #p = :p")
        .expression_attribute_names("#p", "plain")
        .expression_attribute_values(":p", s("updated"))
        .return_values(ReturnValue::UpdatedNew)
        .send()
        .await
        .unwrap();

    assert_eq!(out.attributes(), Some(&item(&[("plain", "updated")])));
}

#[tokio::test]
async fn update_item_rejects_a_partial_response_with_a_signed_attribute() {
    let (fake, client) = setup();
    fake.reply_next(
        "UpdateItem",
        200,
        r#"{"Attributes":{"plain":{"S":"updated"},"sign":{"S":"1"}}}"#,
    );

    let err = client
        .update_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .update_expression("SET plain = :p")
        .expression_attribute_values(":p", s("updated"))
        .return_values(ReturnValue::UpdatedNew)
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
}

// TestUpdateItemInputUpdateExpressionSigned and TestUpdateItemInputUpdateExpressionEncrypted.
#[tokio::test]
async fn update_item_rejects_an_update_of_a_signed_attribute() {
    let (fake, client) = setup();
    for attr in ["sign", "encrypt"] {
        let err = client
            .update_item()
            .table_name(TABLE)
            .set_key(Some(key("a", "1")))
            .update_expression(format!("SET {attr} = :p"))
            .expression_attribute_values(":p", s("x"))
            .send()
            .await
            .unwrap_err();

        assert!(matches!(err, Error::Validation(_)), "{err:?}");
        assert_eq!(
            err.message(),
            format!("Update Expressions forbidden on signed attributes : {attr}")
        );
    }
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn update_item_rejects_the_legacy_attribute_updates_parameter() {
    let (fake, client) = setup();

    let err = client
        .update_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .attribute_updates(
            "plain",
            AttributeValueUpdate::builder().value(s("x")).build(),
        )
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(fake.calls().is_empty());
}

// TestUpdateItemInputPassthrough: a signed attribute of the configured table means nothing elsewhere.
#[tokio::test]
async fn update_item_of_an_unconfigured_table_passes_through() {
    let (fake, client) = setup();
    put(&client, PLAIN_TABLE, full_item("a", "1")).await;

    let out = client
        .update_item()
        .table_name(PLAIN_TABLE)
        .set_key(Some(key("a", "1")))
        .update_expression("SET encrypt = :p")
        .expression_attribute_values(":p", s("visible"))
        .return_values(ReturnValue::AllNew)
        .send()
        .await
        .unwrap();

    let mut expected = full_item("a", "1");
    expected.insert("encrypt".to_owned(), s("visible"));
    assert_eq!(out.attributes(), Some(&expected));
    assert_eq!(fake.items(PLAIN_TABLE), [expected]);
}

#[tokio::test]
async fn delete_item_returns_the_deleted_item_decrypted() {
    let (fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;

    let out = client
        .delete_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .condition_expression("attribute_exists(sign)")
        .return_values(ReturnValue::AllOld)
        .send()
        .await
        .unwrap();

    assert_eq!(out.attributes(), Some(&full_item("a", "1")));
    assert!(fake.items(TABLE).is_empty());
}

#[tokio::test]
async fn delete_item_rejects_a_condition_on_an_encrypted_attribute() {
    let (fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;

    let err = client
        .delete_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .condition_expression("#e = :v")
        .expression_attribute_names("#e", "encrypt")
        .expression_attribute_values(":v", s("guess"))
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(fake.calls(), ["PutItem"]);
    assert_eq!(fake.items(TABLE).len(), 1);
}

#[tokio::test]
async fn batch_write_item_encrypts_puts_of_configured_tables_only() {
    let (fake, client) = setup();
    put(&client, TABLE, dafny_item(9, 9)).await;

    let out = client
        .batch_write_item()
        .request_items(
            TABLE,
            vec![
                put_request(dafny_item(1, 1)),
                put_request(dafny_item(2, 2)),
                delete_request(key("bar9", "sign9")),
            ],
        )
        .request_items(PLAIN_TABLE, vec![put_request(dafny_item(3, 3))])
        .send()
        .await
        .unwrap();

    assert_eq!(out.unprocessed_items(), Some(&HashMap::new()));
    let stored = fake.items(TABLE);
    assert_eq!(stored.len(), 2);
    assert_encrypted(&stored[0], &dafny_item(1, 1));
    assert_encrypted(&stored[1], &dafny_item(2, 2));
    assert_eq!(fake.items(PLAIN_TABLE), [dafny_item(3, 3)]);
    for (bar, n) in [(1, 1), (2, 2)] {
        assert_eq!(
            get(
                &client,
                TABLE,
                key(&format!("bar{bar}"), &format!("sign{n}"))
            )
            .await
            .unwrap(),
            Some(dafny_item(bar, n))
        );
    }
}

// TestBatchWriteItemOutputTransformUnprocessed4: every request comes back unprocessed,
// with each put holding its original plaintext item.
#[tokio::test]
async fn batch_write_item_returns_unprocessed_puts_as_plaintext() {
    let (fake, client) = setup();
    fake.leave_unprocessed(TABLE, 2);
    fake.leave_unprocessed(PLAIN_TABLE, 2);
    let requests = HashMap::from([
        (
            TABLE.to_owned(),
            vec![put_request(dafny_item(1, 1)), put_request(dafny_item(1, 2))],
        ),
        (
            PLAIN_TABLE.to_owned(),
            vec![put_request(dafny_item(1, 3)), put_request(dafny_item(1, 4))],
        ),
    ]);

    let out = client
        .batch_write_item()
        .set_request_items(Some(requests.clone()))
        .send()
        .await
        .unwrap();

    assert_eq!(out.unprocessed_items(), Some(&requests));
    assert!(fake.items(TABLE).is_empty());
}

// TestBatchWriteItemOutputTransformUnprocessed3: only the first request of each table
// comes back unprocessed.
#[tokio::test]
async fn batch_write_item_returns_some_unprocessed_puts_as_plaintext() {
    let (fake, client) = setup();
    fake.leave_unprocessed(TABLE, 1);
    fake.leave_unprocessed(PLAIN_TABLE, 1);

    let out = client
        .batch_write_item()
        .request_items(
            TABLE,
            vec![put_request(dafny_item(1, 1)), put_request(dafny_item(2, 2))],
        )
        .request_items(
            PLAIN_TABLE,
            vec![put_request(dafny_item(3, 3)), put_request(dafny_item(4, 4))],
        )
        .send()
        .await
        .unwrap();

    let expected = HashMap::from([
        (TABLE.to_owned(), vec![put_request(dafny_item(1, 1))]),
        (PLAIN_TABLE.to_owned(), vec![put_request(dafny_item(3, 3))]),
    ]);
    assert_eq!(out.unprocessed_items(), Some(&expected));
    assert_eq!(
        get(&client, TABLE, key("bar2", "sign2")).await.unwrap(),
        Some(dafny_item(2, 2))
    );
}

#[tokio::test]
async fn batch_write_item_rejects_reserved_attributes() {
    let (fake, client) = setup();
    let mut bad = dafny_item(1, 1);
    bad.insert("aws_dbe_foot".to_owned(), s("mine"));

    let err = client
        .batch_write_item()
        .request_items(TABLE, vec![put_request(bad)])
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn transact_write_items_encrypts_puts_and_runs_every_action() {
    let (fake, client) = setup();
    put(&client, TABLE, full_item("a", "1")).await;
    put(&client, PLAIN_TABLE, full_item("b", "1")).await;

    client
        .transact_write_items()
        .transact_items(
            TransactWriteItem::builder()
                .put(
                    Put::builder()
                        .table_name(TABLE)
                        .set_item(Some(full_item("a", "2")))
                        .condition_expression("attribute_not_exists(bar)")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .transact_items(
            TransactWriteItem::builder()
                .update(
                    Update::builder()
                        .table_name(TABLE)
                        .set_key(Some(key("a", "1")))
                        .update_expression("SET plain = :p")
                        .expression_attribute_values(":p", s("updated"))
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .transact_items(
            TransactWriteItem::builder()
                .delete(
                    Delete::builder()
                        .table_name(PLAIN_TABLE)
                        .set_key(Some(key("b", "1")))
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .transact_items(
            TransactWriteItem::builder()
                .condition_check(
                    ConditionCheck::builder()
                        .table_name(TABLE)
                        .set_key(Some(key("a", "1")))
                        .condition_expression("attribute_exists(sign)")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    assert_encrypted(
        &fake.item(TABLE, &key("a", "2")).unwrap(),
        &full_item("a", "2"),
    );
    assert_eq!(
        get(&client, TABLE, key("a", "2")).await.unwrap(),
        Some(full_item("a", "2"))
    );
    assert_eq!(
        get(&client, TABLE, key("a", "1")).await.unwrap().unwrap()["plain"],
        s("updated")
    );
    assert!(fake.items(PLAIN_TABLE).is_empty());
}

// TestTransactWriteItemsInputEmpty.
#[tokio::test]
async fn transact_write_items_rejects_an_action_with_no_operation() {
    let (fake, client) = setup();

    let err = client
        .transact_write_items()
        .transact_items(TransactWriteItem::builder().build())
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "Each item in TransactWriteItems must specify at least one supported operation"
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn transact_write_items_rejects_an_update_of_a_signed_attribute() {
    let (fake, client) = setup();

    let err = client
        .transact_write_items()
        .transact_items(
            TransactWriteItem::builder()
                .update(
                    Update::builder()
                        .table_name(TABLE)
                        .set_key(Some(key("a", "1")))
                        .update_expression("SET sign = :p")
                        .expression_attribute_values(":p", s("x"))
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn a_transaction_conflict_is_a_concurrent_modification() {
    let (fake, client) = setup();
    fake.fail_next("PutItem", 400, "TransactionConflictException");

    let err = client
        .put_item()
        .table_name(TABLE)
        .set_item(Some(full_item("a", "1")))
        .send()
        .await
        .unwrap_err();

    let Error::Conflict(conflict) = &err else {
        panic!("expected a conflict, got {err:?}");
    };
    assert_eq!(
        conflict.reason(),
        Some(&ConflictReason::ConcurrentModification)
    );
    assert!(matches!(
        err.as_service_error::<PutItemError>(),
        Some(PutItemError::TransactionConflictException(_))
    ));
    assert!(fake.items(TABLE).is_empty());
}

#[tokio::test]
async fn a_canceled_transaction_keeps_dynamodbs_error() {
    let (fake, client) = setup();

    let err = client
        .transact_write_items()
        .transact_items(
            TransactWriteItem::builder()
                .condition_check(
                    ConditionCheck::builder()
                        .table_name(TABLE)
                        .set_key(Some(key("a", "1")))
                        .condition_expression("attribute_exists(sign)")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();

    assert!(matches!(
        err.as_service_error::<TransactWriteItemsError>(),
        Some(TransactWriteItemsError::TransactionCanceledException(_))
    ));
    assert_eq!(err.code(), Some("TransactionCanceledException"));
    assert_eq!(fake.calls(), ["TransactWriteItems"]);
}
