// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Client` read operations end to end against an in-process fake DynamoDB:
//! GetItem, Query, Scan, BatchGetItem, and TransactGetItems.

mod client_support;

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::{
    AttributeValue, ComparisonOperator, Condition, Get, KeysAndAttributes, TransactGetItem,
};
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{Client, Error, TableConfig};
use client_support::{Item, PLAIN_TABLE, TABLE, full_item, key, s, setup};

async fn put(client: &Client, table: &str, i: Item) {
    client
        .put_item()
        .table_name(table)
        .set_item(Some(i))
        .send()
        .await
        .expect("the put succeeds");
}

/// A client with items `a/1`, `a/2`, and `b/1` in [`TABLE`], and `a/1` in [`PLAIN_TABLE`].
async fn populated() -> (client_support::FakeDdb, Client) {
    let (fake, client) = setup();
    for (bar, sign) in [("a", "1"), ("a", "2"), ("b", "1")] {
        put(&client, TABLE, full_item(bar, sign)).await;
    }
    put(&client, PLAIN_TABLE, full_item("a", "1")).await;
    (fake, client)
}

fn get(table: &str, k: Item) -> TransactGetItem {
    TransactGetItem::builder()
        .get(
            Get::builder()
                .table_name(table)
                .set_key(Some(k))
                .build()
                .unwrap(),
        )
        .build()
}

#[tokio::test]
async fn get_item_of_a_missing_item_returns_none() {
    let (fake, client) = setup();

    let out = client
        .get_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .consistent_read(true)
        .send()
        .await
        .unwrap();

    assert_eq!(out.item(), None);
    assert_eq!(fake.calls(), ["GetItem"]);
}

#[tokio::test]
async fn get_item_rejects_a_plaintext_item_in_a_configured_table() {
    let (fake, client) = setup();
    fake.set_item(TABLE, &full_item("a", "1"));

    let err = client
        .get_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Serialization(_)), "{err:?}");
}

#[tokio::test]
async fn query_decrypts_each_matching_item() {
    let (_fake, client) = populated().await;

    let out = client
        .query()
        .table_name(TABLE)
        .key_condition_expression("#b = :b")
        .expression_attribute_names("#b", "bar")
        .expression_attribute_values(":b", s("a"))
        .send()
        .await
        .unwrap();

    assert_eq!(out.items(), [full_item("a", "1"), full_item("a", "2")]);
    assert_eq!(out.count(), 2);
}

#[tokio::test]
async fn query_filters_on_a_signed_attribute() {
    let (_fake, client) = populated().await;

    let out = client
        .query()
        .table_name(TABLE)
        .key_condition_expression("bar = :b")
        .filter_expression("sign = :s")
        .expression_attribute_values(":b", s("a"))
        .expression_attribute_values(":s", s("2"))
        .send()
        .await
        .unwrap();

    assert_eq!(out.items(), [full_item("a", "2")]);
}

#[tokio::test]
async fn query_rejects_a_filter_on_an_encrypted_attribute() {
    let (fake, client) = populated().await;
    let before = fake.calls().len();

    let err = client
        .query()
        .table_name(TABLE)
        .key_condition_expression("bar = :b")
        .filter_expression("encrypt = :e")
        .expression_attribute_values(":b", s("a"))
        .expression_attribute_values(":e", s("x"))
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(err.message(), "Query is using encrypted field : encrypt.");
    assert_eq!(fake.calls().len(), before, "nothing is sent");
}

#[tokio::test]
async fn query_rejects_the_legacy_key_conditions_parameter() {
    let (fake, client) = setup();

    let err = client
        .query()
        .table_name(TABLE)
        .key_conditions(
            "bar",
            Condition::builder()
                .comparison_operator(ComparisonOperator::Eq)
                .attribute_value_list(s("a"))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn query_of_an_unconfigured_table_passes_through() {
    let (fake, client) = populated().await;
    let raw = fake.items(PLAIN_TABLE);

    let out = client
        .query()
        .table_name(PLAIN_TABLE)
        .key_condition_expression("bar = :b")
        .filter_expression("encrypt = :e")
        .expression_attribute_values(":b", s("a"))
        .expression_attribute_values(":e", s("secret of a/1"))
        .send()
        .await
        .unwrap();

    assert_eq!(out.items(), raw);
}

#[tokio::test]
async fn scan_decrypts_every_item() {
    let (_fake, client) = populated().await;

    let out = client.scan().table_name(TABLE).send().await.unwrap();

    assert_eq!(
        out.items(),
        [
            full_item("a", "1"),
            full_item("a", "2"),
            full_item("b", "1")
        ]
    );
    assert_eq!(out.count(), 3);
}

#[tokio::test]
async fn scan_fails_when_any_item_fails_verification() {
    let (fake, client) = populated().await;
    let mut tampered = fake.item(TABLE, &key("b", "1")).unwrap();
    tampered.insert("bar".to_owned(), s("c"));
    fake.set_item(TABLE, &tampered);

    let err = client.scan().table_name(TABLE).send().await.unwrap_err();

    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn scan_rejects_a_filter_on_an_encrypted_attribute() {
    let (fake, client) = setup();

    let err = client
        .scan()
        .table_name(TABLE)
        .filter_expression("encrypt = :e")
        .expression_attribute_values(":e", s("x"))
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn scan_rejects_the_legacy_attributes_to_get_parameter() {
    let (fake, client) = setup();

    let err = client
        .scan()
        .table_name(TABLE)
        .attributes_to_get("bar")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn batch_get_item_decrypts_the_items_of_configured_tables_only() {
    let (fake, client) = populated().await;
    let keys = |ks: Vec<Item>| {
        KeysAndAttributes::builder()
            .set_keys(Some(ks))
            .build()
            .unwrap()
    };

    let out = client
        .batch_get_item()
        .request_items(TABLE, keys(vec![key("a", "1"), key("b", "1")]))
        .request_items(PLAIN_TABLE, keys(vec![key("a", "1")]))
        .send()
        .await
        .unwrap();

    let responses = out.responses().unwrap();
    assert_eq!(responses[TABLE], [full_item("a", "1"), full_item("b", "1")]);
    assert_eq!(responses[PLAIN_TABLE], fake.items(PLAIN_TABLE));
    assert_eq!(out.unprocessed_keys(), Some(&HashMap::new()));
}

#[tokio::test]
async fn transact_get_items_decrypts_each_item_in_request_order() {
    let (fake, client) = populated().await;

    let out = client
        .transact_get_items()
        .transact_items(get(TABLE, key("b", "1")))
        .transact_items(get(PLAIN_TABLE, key("a", "1")))
        .transact_items(get(TABLE, key("z", "9")))
        .transact_items(get(TABLE, key("a", "2")))
        .send()
        .await
        .unwrap();

    let items: Vec<Option<&Item>> = out.responses().iter().map(|r| r.item()).collect();
    let plain = fake.items(PLAIN_TABLE);
    assert_eq!(
        items,
        [
            Some(&full_item("b", "1")),
            Some(&plain[0]),
            None,
            Some(&full_item("a", "2")),
        ]
    );
}

#[tokio::test]
async fn transact_get_items_rejects_a_response_with_the_wrong_number_of_items() {
    let (fake, client) = setup();
    fake.reply_next("TransactGetItems", 200, r#"{"Responses":[{}]}"#);

    let err = client
        .transact_get_items()
        .transact_items(get(TABLE, key("a", "1")))
        .transact_items(get(TABLE, key("a", "2")))
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "Invalid TransactGetItems response for original request: Number of items returned must equal number of items requested."
    );
}

#[tokio::test]
async fn every_attribute_type_round_trips_encrypted() {
    let fake = client_support::fake();
    let others = [
        ("n", AttributeValue::N("12.5".to_owned())),
        ("b", AttributeValue::B(vec![0, 1, 2].into())),
        ("t", AttributeValue::Bool(true)),
        ("z", AttributeValue::Null(true)),
        (
            "ss",
            AttributeValue::Ss(vec!["x".to_owned(), "y".to_owned()]),
        ),
        (
            "ns",
            AttributeValue::Ns(vec!["1".to_owned(), "2".to_owned()]),
        ),
        (
            "bs",
            AttributeValue::Bs(vec![vec![1].into(), vec![2].into()]),
        ),
        (
            "l",
            AttributeValue::L(vec![s("x"), AttributeValue::N("3".to_owned())]),
        ),
        (
            "m",
            AttributeValue::M(HashMap::from([("k".to_owned(), s("\"quoted\"\n"))])),
        ),
    ];
    let mut config = TableConfig::builder()
        .logical_table_name(TABLE)
        .partition_key_name("bar")
        .sort_key_name("sign")
        .attribute_actions_on_encrypt("bar", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sign", CryptoAction::SignOnly)
        .keyring(client_support::keyring());
    let mut plaintext = key("a", "1");
    for (name, value) in others {
        config = config.attribute_actions_on_encrypt(name, CryptoAction::EncryptAndSign);
        plaintext.insert(name.to_owned(), value);
    }
    let client = Client::builder()
        .ddb_client(fake.client())
        .table_encryption_configs(TABLE, config.build().unwrap())
        .build()
        .unwrap();

    put(&client, TABLE, plaintext.clone()).await;
    let out = client
        .get_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .send()
        .await
        .unwrap();

    let stored = fake.item(TABLE, &key("a", "1")).unwrap();
    assert!(
        matches!(stored["ss"], AttributeValue::B(_)),
        "ss is encrypted"
    );
    assert_eq!(out.item(), Some(&plaintext));
}
