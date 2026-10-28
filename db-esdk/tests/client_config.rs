// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Building a `Client`, its fluent builders' setters and getters, and ResolveAttributes.

mod client_support;

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::{AttributeValue, ReturnValue};
use aws_db_esdk::{Client, Error};
use client_support::{PLAIN_TABLE, TABLE, fake, full_item, key, s, table_config};

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

/// Put item `a/1` in `table`, and the names of the attributes the fake stores for it.
async fn put_and_read_back(
    client: &Client,
    fake: &client_support::FakeDdb,
    table: &str,
) -> Vec<String> {
    client
        .put_item()
        .table_name(table)
        .set_item(Some(full_item("a", "1")))
        .send()
        .await
        .unwrap();
    let mut names: Vec<String> = fake
        .item(table, &key("a", "1"))
        .unwrap()
        .into_keys()
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn set_table_encryption_configs_replaces_every_configuration() {
    let fake = fake();
    let builder = Client::builder()
        .set_ddb_client(Some(fake.client()))
        .table_encryption_configs(PLAIN_TABLE, table_config());

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#overview
    //= type=test
    //# There is no restriction on what this process is,
    //# other than the fact that at some point the customer
    //# MUST specify a [DynamoDB Encryption Client Configuration](#dynamodb-encryption-client-configuration).
    let builder = builder
        .set_table_encryption_configs(Some(HashMap::from([(TABLE.to_owned(), table_config())])));

    let encrypted = builder.build().unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#overview
    //= type=test
    //= reason=the built client writes TABLE's item with the encryption attributes
    //# There MUST be some process by which
    //# the customer can create this AWS SDK with
    //# additional encryption behavior, which
    //# this document will refer to as a [DynamoDB Encryption Client](#dynamodb-encryption-client).
    //
    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#dynamodb-encryption-client-configuration
    //= type=test
    //= reason=TABLE is encrypted only because the configuration provided above names it
    //# The DynamoDB Encryption Client Configuration is a structure that
    //# the customer MUST provide in the process of creating a [DynamoDB Encryption Client](#dynamodb-encryption-client).
    assert_eq!(
        put_and_read_back(&encrypted, &fake, TABLE).await,
        [
            "aws_dbe_foot",
            "aws_dbe_head",
            "bar",
            "encrypt",
            "plain",
            "sign"
        ]
    );

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#overview
    //= type=test
    //= reason=PLAIN_TABLE's earlier configuration was replaced, so its item is stored plaintext
    //# This configuration MUST be the configuration ultimately used by
    //# the behaviors within the DynamoDB Encryption Client.
    assert_eq!(
        put_and_read_back(&encrypted, &fake, PLAIN_TABLE).await,
        ["bar", "encrypt", "plain", "sign"]
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
        put_and_read_back(&plain, &fake, TABLE).await,
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

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#overview
    //= type=test
    //= reason=the builder's setters and getters are the AWS SDK builder's, with the same values
    //# This new implementation SHOULD be a drop-in replacement of the
    //# regular AWS SDK.
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
