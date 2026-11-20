// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts an item directly, with no call to DynamoDB, using an [`ItemEncryptor`].
//!
//! Use the item encryptor when you already hold an item and make no put or get call:
//! for example, an encrypted item from a DynamoDB stream that you want to decrypt.
//! It takes the same `TableConfig` as `aws_db_esdk::Client`.
//!
//! Runs offline.

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
use aws_db_esdk::{ItemEncryptor, TableConfig};

// The encryptor binds the logical table name to every item, so an item decrypts only under the same name.
const TABLE_NAME: &str = "ItemEncryptDecryptExample";

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
        .attribute_actions_on_encrypt("attribute1", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("attribute2", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt(":attribute3", CryptoAction::DoNothing)
        .allowed_unsigned_attribute_prefix(":")
        .keyring(keyring)
        .build()?;

    let encryptor = ItemEncryptor::builder().table(TABLE_NAME, table).build()?;

    let item = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("ItemEncryptDecryptExample".into()),
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

    let encrypted = encryptor
        .encrypt_item()
        .plaintext_item(item.clone())
        .send()
        .await?;
    let encrypted_item = encrypted.encrypted_item();

    // Signed attributes stay readable; encrypted ones become binary.
    assert_eq!(encrypted_item["partition_key"], item["partition_key"]);
    assert_eq!(encrypted_item["attribute2"], item["attribute2"]);
    assert!(encrypted_item["attribute1"].is_b());

    let decrypted = encryptor
        .decrypt_item()
        .encrypted_item(encrypted.into_encrypted_item())
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext_item(),
        &item,
        "Decryption failed: item mismatch"
    );
    println!("Success! Encrypted and decrypted an item without DynamoDB.");
    Ok(())
}
