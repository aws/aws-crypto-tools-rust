// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Writes an item with a non-default algorithm suite.
//!
//! The default suite, `AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384`,
//! signs each item twice: with ECDSA and with HMAC.
//! ECDSA lets a reader verify that the item came from someone allowed to write,
//! not just someone allowed to read.
//! When writers and readers are equally trusted, the HMAC-only suite is faster.
//! This example uses `AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384`.
//!
//! Reads take the suite from each item, so a reader needs no suite set.
//!
//! Runs offline.

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::types::{AesWrappingAlg, AlgorithmSuiteId, CryptoAction};
use aws_db_esdk::{ItemEncryptor, TableConfig};

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
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sensitive_data", CryptoAction::EncryptAndSign)
        .keyring(keyring)
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384)
        .build()?;
    let encryptor = ItemEncryptor::builder()
        .table("SetAlgorithmSuiteExample", table)
        .build()?;

    let item = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("SetAlgorithmSuiteExample".into()),
        ),
        (
            "sensitive_data".to_string(),
            AttributeValue::S("encrypt and sign me!".into()),
        ),
    ]);

    let encrypted = encryptor
        .encrypt_item()
        .plaintext_item(item.clone())
        .send()
        .await?;
    assert_eq!(
        encrypted.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384
    );

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
    println!("Success! Wrote and read an item with the HMAC-only suite.");
    Ok(())
}
