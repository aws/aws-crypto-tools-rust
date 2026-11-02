// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Puts an encrypted item into a DynamoDB table and gets it back, using a raw AES keyring.
//!
//! `aws_db_esdk::Client` has the same operations as `aws_sdk_dynamodb::Client`.
//! It encrypts and signs each item before it is written, and verifies and decrypts it after it is read.
//!
//! Requires AWS credentials and a DynamoDB table with:
//! - partition key `partition_key`, type S
//! - sort key `sort_key`, type N

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
use aws_db_esdk::{Error, TableConfig, aws_config, aws_sdk_dynamodb};

const TABLE_NAME: &str = "DynamoDbEncryptionInterceptorTestTableCS";

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

    // Every attribute that the application writes needs an action:
    // - `EncryptAndSign`: encrypted, and covered by the item's signature
    // - `SignOnly`: stored as plaintext, but covered by the signature
    // - `DoNothing`: stored as plaintext, not covered by the signature
    // The partition and sort keys must be `SignOnly`, since DynamoDB must read them.
    //
    // On read, the config must list each attribute that is not signed.
    // Here every unsigned attribute starts with ":", so new ones need no config change.
    // Never change the prefix once you have written items with it.
    let table = TableConfig::builder()
        .partition_key_name("partition_key")
        .sort_key_name("sort_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sort_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("attribute1", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("attribute2", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt(":attribute3", CryptoAction::DoNothing)
        .allowed_unsigned_attribute_prefix(":")
        .keyring(keyring)
        .build()?;

    // The DynamoDB client takes its region and credentials from the default AWS config chain.
    // Requests for a table with no config pass through unencrypted.
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .table_encryption_configs(TABLE_NAME, table)
        .build()?;

    let item = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("BasicPutGetExample".into()),
        ),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
        (
            "attribute1".to_string(),
            AttributeValue::S("encrypt and sign me!".into()),
        ),
        (
            "attribute2".to_string(),
            AttributeValue::S("sign me!".into()),
        ),
        (
            ":attribute3".to_string(),
            AttributeValue::S("ignore me!".into()),
        ),
    ]);

    ddb.put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item.clone()))
        .send()
        .await?;

    let key = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("BasicPutGetExample".into()),
        ),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
    ]);
    let result = ddb
        .get_item()
        .table_name(TABLE_NAME)
        .set_key(Some(key))
        // Strongly consistent, because this read follows the write at once.
        .consistent_read(true)
        .send()
        .await;
    let output = match result {
        Ok(output) => output,
        Err(e) => {
            match &e {
                Error::NoMatchingDataKey(_) => {
                    eprintln!("the item was encrypted under a different keyring");
                }
                Error::Cryptographic(_) | Error::Serialization(_) => {
                    eprintln!("the item is corrupt or was tampered with");
                }
                _ => eprintln!("get_item failed: {e}"),
            }
            return Err(e.into());
        }
    };

    assert_eq!(
        output.item(),
        Some(&item),
        "Decryption failed: item mismatch"
    );
    println!("Success! Put and got an encrypted item.");
    Ok(())
}
