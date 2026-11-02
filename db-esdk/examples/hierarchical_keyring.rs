// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Puts an encrypted item and gets it back, using a hierarchical keyring.
//!
//! Requires AWS credentials, an existing key store with a provisioned branch key,
//! and a DynamoDB table with:
//! - partition key `partition_key`, type S
//! - sort key `sort_key`, type N

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::error::{Resource, Service};
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{Error, TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

const TABLE_NAME: &str = "DynamoDbEncryptionInterceptorTestTableCS";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The clients take their region and credentials from the default AWS config chain.
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms = aws_sdk_kms::Client::new(&sdk_config);
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, logical name, and KMS key ARN.
    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126".into(),
        ))
        .kms_client(kms)
        .ddb_client(ddb_sdk.clone())
        .build()
        .await?;

    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        // How long the keyring reuses cached branch key material.
        .ttl(Duration::from_secs(600))
        .branch_key_id("3f43a9af-08c5-4317-b694-3d3e883dcaef")
        .build()
        .await?;

    let table = TableConfig::builder()
        .partition_key_name("partition_key")
        .sort_key_name("sort_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sort_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sensitive_data", CryptoAction::EncryptAndSign)
        .keyring(keyring)
        .build()?;

    // The same DynamoDB client serves the key store and the encrypted table.
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(TABLE_NAME, table)
        .build()?;

    let item = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("HierarchicalKeyringExample".into()),
        ),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
        (
            "sensitive_data".to_string(),
            AttributeValue::S("encrypt and sign me!".into()),
        ),
    ]);

    let result = ddb
        .put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item.clone()))
        .send()
        .await;
    if let Err(e) = result {
        match &e {
            Error::ResourceNotFound(not_found) => match not_found.resource() {
                Some(Resource::BranchKey(branch_key)) => {
                    eprintln!("branch key {} is not in the key store", branch_key.id());
                }
                Some(Resource::DynamoDbTable(table)) => {
                    eprintln!("table {} does not exist", table.name());
                }
                _ => eprintln!("an AWS resource does not exist: {e}"),
            },
            Error::AccessDenied(denied) => match denied.service() {
                Some(Service::Kms) => eprintln!("AWS KMS denied access: {e}"),
                Some(Service::DynamoDb) => eprintln!("DynamoDB denied access: {e}"),
                _ => eprintln!("access denied: {e}"),
            },
            _ => eprintln!("put_item failed: {e}"),
        }
        return Err(e.into());
    }

    let key = HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("HierarchicalKeyringExample".into()),
        ),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
    ]);
    let output = ddb
        .get_item()
        .table_name(TABLE_NAME)
        .set_key(Some(key))
        .consistent_read(true)
        .send()
        .await?;

    assert_eq!(
        output.item(),
        Some(&item),
        "Decryption failed: item mismatch"
    );
    println!("Success! Put and got an item encrypted under a branch key.");
    Ok(())
}
