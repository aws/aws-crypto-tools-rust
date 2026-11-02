// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Writes and reads encrypted items with the batch and transaction operations.
//!
//! `batch_write_item`, `transact_write_items`, `batch_get_item`, and `transact_get_items`
//! take and return the same types as in `aws_sdk_dynamodb`.
//! The client encrypts the items for a configured table on write, and decrypts them on read.
//!
//! Requires AWS credentials and a DynamoDB table with:
//! - partition key `partition_key`, type S
//! - sort key `sort_key`, type N

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::{
    AttributeValue, Get, KeysAndAttributes, Put, PutRequest, TransactGetItem, TransactWriteItem,
    WriteRequest,
};
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb};

const TABLE_NAME: &str = "DynamoDbEncryptionInterceptorTestTableCS";

fn item(sort_key: &str) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("MultiPutGetExample".into()),
        ),
        ("sort_key".to_string(), AttributeValue::N(sort_key.into())),
        (
            "sensitive_data".to_string(),
            AttributeValue::S("encrypt and sign me!".into()),
        ),
    ])
}

fn key(sort_key: &str) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("MultiPutGetExample".into()),
        ),
        ("sort_key".to_string(), AttributeValue::N(sort_key.into())),
    ])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    let table = TableConfig::builder()
        .partition_key_name("partition_key")
        .sort_key_name("sort_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sort_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sensitive_data", CryptoAction::EncryptAndSign)
        .keyring(keyring)
        .build()?;

    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .table_encryption_configs(TABLE_NAME, table)
        .build()?;

    // Write one item in a batch and one in a transaction.
    let put_request = PutRequest::builder().set_item(Some(item("1"))).build()?;
    ddb.batch_write_item()
        .request_items(
            TABLE_NAME,
            vec![WriteRequest::builder().put_request(put_request).build()],
        )
        .send()
        .await?;

    let put = Put::builder()
        .table_name(TABLE_NAME)
        .set_item(Some(item("2")))
        .build()?;
    ddb.transact_write_items()
        .transact_items(TransactWriteItem::builder().put(put).build())
        .send()
        .await?;

    // Read them back the same two ways.
    let output = ddb
        .batch_get_item()
        .request_items(
            TABLE_NAME,
            KeysAndAttributes::builder()
                .keys(key("1"))
                .keys(key("2"))
                .consistent_read(true)
                .build()?,
        )
        .send()
        .await?;
    let mut items = output.responses().ok_or("no responses")?[TABLE_NAME].clone();
    items.sort_by(|a, b| a["sort_key"].as_n().ok().cmp(&b["sort_key"].as_n().ok()));
    assert_eq!(
        items,
        vec![item("1"), item("2")],
        "batch get: item mismatch"
    );

    let get = Get::builder()
        .table_name(TABLE_NAME)
        .set_key(Some(key("2")))
        .build()?;
    let output = ddb
        .transact_get_items()
        .transact_items(TransactGetItem::builder().get(get).build())
        .send()
        .await?;
    assert_eq!(
        output.responses()[0].item(),
        Some(&item("2")),
        "transact get: item mismatch"
    );

    println!("Success! Wrote and read encrypted items in batches and transactions.");
    Ok(())
}
