// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds the `aws_db_esdk::Client` that the encrypted steps (1-3) share.

use std::time::Duration;

use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::types::{CryptoAction, PlaintextOverride};
use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

/// The DynamoDB table that the migration reads and writes.
pub const DDB_TABLE_NAME: &str = "DynamoDbEncryptionInterceptorTestTableCS";

// The AWS Crypto Tools CI test key store.
// Replace these with your own key store's table, logical name, KMS key ARN, and branch key ID.
const KEY_STORE_TABLE_NAME: &str = "KeyStoreDdbTable";
const KEY_STORE_LOGICAL_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

/// Builds the DB-ESDK client that the encrypted steps use.
///
/// `plaintext_override` sets whether this client writes and reads plaintext items.
/// `None` takes the default, which forbids both, as a fully migrated system does.
pub async fn encrypted_client(
    sdk_config: &aws_config::SdkConfig,
    ddb_sdk: aws_sdk_dynamodb::Client,
    plaintext_override: Option<PlaintextOverride>,
) -> Result<aws_db_esdk::Client, Box<dyn std::error::Error>> {
    // The hierarchical keyring wraps each item's data key with a branch key from the key store.
    // It caches the branch key material for `ttl`.
    let kms = aws_sdk_kms::Client::new(sdk_config);
    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name(KEY_STORE_TABLE_NAME)
        .logical_key_store_name(KEY_STORE_LOGICAL_NAME)
        .kms_configuration(KmsConfiguration::kms_key_arn(KMS_KEY_ARN))
        .kms_client(kms)
        .ddb_client(ddb_sdk.clone())
        .build()
        .await?;
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        .branch_key_id(BRANCH_KEY_ID)
        .ttl(Duration::from_secs(600))
        .build()
        .await?;

    // How each attribute is treated when writing a new item:
    //  - EncryptAndSign: encrypted and included in the signature
    //  - SignOnly:       not encrypted, but included in the signature
    //  - DoNothing:      neither encrypted nor signed
    // The partition and sort keys must be signed, so list them as SignOnly.
    let mut table = TableConfig::builder()
        .partition_key_name("partition_key")
        .sort_key_name("sort_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sort_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("attribute1", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("attribute2", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("attribute3", CryptoAction::DoNothing)
        // A DoNothing attribute is not signed, so the config must list it as unsigned.
        // Keep a name on this list even after you stop writing that attribute:
        // older items may still have it, and the reader must still leave it out of the signature check.
        .allowed_unsigned_attributes("attribute3")
        .keyring(keyring);
    if let Some(plaintext_override) = plaintext_override {
        table = table.plaintext_override(plaintext_override);
    }
    let table = table.build()?;

    // Requests for a table with no config pass through unchanged.
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(DDB_TABLE_NAME, table)
        .build()
        .await?;
    Ok(ddb)
}
