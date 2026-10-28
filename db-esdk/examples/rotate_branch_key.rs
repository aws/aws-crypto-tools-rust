// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Creates a branch key, then rotates it to a new version.
//!
//! Rotating a branch key makes a new version active.
//! Writes then use the new version,
//! and reads still decrypt items written under earlier versions.
//!
//! Requires AWS credentials and an existing key store.
//! Each run creates a new branch key in it.

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::types::{CryptoAction, EncryptionContext};
use aws_db_esdk::{
    ItemEncryptor, TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store,
};

const TABLE_NAME: &str = "RotateBranchKeyExample";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126".into(),
        ))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .build()
        .await?;

    // The branch key's encryption context is bound to every version of it.
    let branch_key_context = EncryptionContext::from([("purpose", "example")]);
    let branch_key_id = key_store
        .create_key()
        .set_encryption_context(Some(branch_key_context))
        .send()
        .await?
        .into_branch_key_id();

    // A keyring keeps using the version it cached until its TTL expires,
    // so each encryptor here gets a new keyring.
    let make_encryptor = async || -> Result<ItemEncryptor, Box<dyn std::error::Error>> {
        let keyring = HierarchicalKeyring::builder()
            .key_store(key_store.clone())
            .ttl(Duration::from_secs(600))
            .branch_key_id(&branch_key_id)
            .build()
            .await?;
        let table = TableConfig::builder()
            .partition_key_name("partition_key")
            .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
            .attribute_actions_on_encrypt("sensitive_data", CryptoAction::EncryptAndSign)
            .keyring(keyring)
            .build()?;
        Ok(ItemEncryptor::builder().table(TABLE_NAME, table).build()?)
    };

    let item = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("RotateBranchKeyExample".into()),
        ),
        (
            "sensitive_data".to_string(),
            AttributeValue::S("encrypt and sign me!".into()),
        ),
    ]);
    let encrypt_with = async |encryptor: &ItemEncryptor| {
        encryptor
            .encrypt_item()
            .plaintext_item(item.clone())
            .send()
            .await
            .map(|output| output.into_encrypted_item())
    };

    let before_rotation = encrypt_with(&make_encryptor().await?).await?;

    key_store
        .version_key()
        .branch_key_id(&branch_key_id)
        .send()
        .await?;

    // This encryptor's keyring is new, so it fetches the version that is active now.
    let encryptor = make_encryptor().await?;
    let after_rotation = encrypt_with(&encryptor).await?;

    // Both items decrypt: the first under the earlier version, the second under the active one.
    for encrypted_item in [before_rotation, after_rotation] {
        let decrypted = encryptor
            .decrypt_item()
            .encrypted_item(encrypted_item)
            .send()
            .await?;
        assert_eq!(
            decrypted.plaintext_item(),
            &item,
            "Decryption failed: item mismatch"
        );
    }

    println!("Success! Rotated branch key {branch_key_id}; items from both versions decrypt.");
    Ok(())
}
