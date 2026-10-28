// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Building a `Client`, its fluent builders' setters and getters, and ResolveAttributes.

mod client_support;

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::{AttributeValue, ReturnValue};
use aws_db_esdk::{Client, Error};
use client_support::{TABLE, fake, full_item, key, s, table_config};

#[test]
fn build_requires_a_dynamodb_client() {
    let err = Client::builder()
        .table_encryption_configs(TABLE, table_config())
        .build()
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(err.message(), "ddb_client is required");
}

#[test]
fn set_ddb_client_none_clears_the_client() {
    let err = Client::builder()
        .ddb_client(fake().client())
        .set_ddb_client(None)
        .build()
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
}

#[test]
fn build_rejects_two_tables_with_one_logical_name() {
    let err = Client::builder()
        .ddb_client(fake().client())
        .table_encryption_configs("physical1", table_config())
        .table_encryption_configs("physical2", table_config())
        .build()
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "Duplicate logical table mapped to multiple physical tables: foo"
    );
}

async fn put_and_read_back(client: &Client, fake: &client_support::FakeDdb) -> Vec<String> {
    client
        .put_item()
        .table_name(TABLE)
        .set_item(Some(full_item("a", "1")))
        .send()
        .await
        .unwrap();
    let mut names: Vec<String> = fake
        .item(TABLE, &key("a", "1"))
        .unwrap()
        .into_keys()
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn set_table_encryption_configs_replaces_every_configuration() {
    let fake = fake();
    let encrypted = Client::builder()
        .set_ddb_client(Some(fake.client()))
        .table_encryption_configs("other", table_config())
        .set_table_encryption_configs(Some(HashMap::from([(TABLE.to_owned(), table_config())])))
        .build()
        .unwrap();

    assert_eq!(
        put_and_read_back(&encrypted, &fake).await,
        [
            "aws_dbe_foot",
            "aws_dbe_head",
            "bar",
            "encrypt",
            "plain",
            "sign"
        ]
    );
}

#[tokio::test]
async fn set_table_encryption_configs_none_leaves_every_table_plaintext() {
    let fake = fake();
    let plain = Client::builder()
        .ddb_client(fake.client())
        .table_encryption_configs(TABLE, table_config())
        .set_table_encryption_configs(None)
        .build()
        .unwrap();

    assert_eq!(
        put_and_read_back(&plain, &fake).await,
        ["bar", "encrypt", "plain", "sign"]
    );
}

#[test]
fn fluent_builders_keep_what_is_set() {
    let client = client_support::setup().1;

    let put = client
        .put_item()
        .table_name(TABLE)
        .item("bar", s("a"))
        .return_values(ReturnValue::AllOld);
    assert_eq!(put.get_table_name().as_deref(), Some(TABLE));
    assert_eq!(
        put.get_item(),
        &Some(HashMap::from([("bar".to_owned(), s("a"))]))
    );
    assert_eq!(put.get_return_values(), &Some(ReturnValue::AllOld));
    let put = put.set_item(None).set_table_name(None);
    assert_eq!(put.get_item(), &None);
    assert_eq!(put.get_table_name(), &None);

    let get = client
        .get_item()
        .attributes_to_get("bar")
        .attributes_to_get("sign");
    assert_eq!(
        get.get_attributes_to_get(),
        &Some(vec!["bar".to_owned(), "sign".to_owned()])
    );
    let get = get.set_attributes_to_get(Some(vec!["plain".to_owned()]));
    assert_eq!(get.get_attributes_to_get(), &Some(vec!["plain".to_owned()]));
}

#[tokio::test]
async fn resolve_attributes_of_a_table_without_search_is_empty() {
    let client = client_support::setup().1;

    for table in [TABLE, "unconfigured"] {
        let out = client
            .resolve_attributes()
            .table_name(table)
            .item(full_item("a", "1"))
            .send()
            .await
            .unwrap();

        assert!(out.virtual_fields().is_empty(), "{table}");
        assert!(out.compound_beacons().is_empty(), "{table}");
    }
}

#[tokio::test]
async fn resolve_attributes_requires_a_table_name_and_an_item() {
    let client = client_support::setup().1;
    let item: HashMap<String, AttributeValue> = full_item("a", "1");

    let builder = client
        .resolve_attributes()
        .table_name(TABLE)
        .item(item.clone());
    assert_eq!(builder.get_table_name().as_deref(), Some(TABLE));
    assert_eq!(builder.get_item(), &Some(item.clone()));

    let err = builder
        .clone()
        .set_table_name(None)
        .send()
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(err.message(), "table_name is required");

    let err = builder.set_item(None).send().await.unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(err.message(), "item is required");
}
