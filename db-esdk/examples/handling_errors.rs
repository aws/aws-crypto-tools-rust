// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handles the errors that DB-ESDK operations return.
//!
//! Every operation returns one `aws_db_esdk::Error`.
//! Decide from its fields, never from the message text, which can change in any release:
//! - `is_retryable()`: whether a retry can help
//! - the variant: the kind of failure
//! - `service()`: the AWS service involved
//! - `resource()`: the resource to act on
//!
//! A DynamoDB failure on your own table keeps DynamoDB's own error.
//! `as_service_error()` returns it, so code written for `aws_sdk_dynamodb` can match it unchanged.
//!
//! Requires AWS credentials, an existing key store with a provisioned branch key,
//! and a DynamoDB table with:
//! - partition key `partition_key`, type S
//! - sort key `sort_key`, type N

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::error::{Resource, Service};
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{Error, TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

const TABLE_NAME: &str = "DynamoDbEncryptionInterceptorTestTableCS";

fn item() -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S("HandlingErrorsExample".into()),
        ),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
        (
            "sensitive_data".to_string(),
            AttributeValue::S("encrypt and sign me!".into()),
        ),
    ])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);
    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::kms_key_arn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126",
        ))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(ddb_sdk.clone())
        .build()
        .await?;
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
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
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(TABLE_NAME, table)
        .build()
        .await?;

    // Put, handling errors from coarse to fine.
    // A put can fail in DynamoDB (the table), or in AWS KMS or the key store (the keyring).
    let result = ddb
        .put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item()))
        .send()
        .await;
    if let Err(e) = result {
        match &e {
            // Checking `is_retryable()` first catches throttling, timeouts, etc. in one arm, whatever their variant.
            // The AWS SDK clients already retried these, so retry at a higher level.
            _ if e.is_retryable() => eprintln!("retry later ({:?}): {e}", e.retry_kind()),

            // `is_credentials()` means AWS rejected the credentials themselves, not a permission on a resource.
            Error::AccessDenied(denied) if denied.is_credentials() => {
                eprintln!("the AWS credentials are expired or invalid");
            }

            // `service()` says which service denied access, and `resource()` what to grant.
            Error::AccessDenied(denied) => match (denied.service(), denied.resource()) {
                (Some(Service::Kms), Some(Resource::KmsKey(key))) => {
                    eprintln!("grant access to the KMS key {}", key.arn());
                }
                (Some(Service::DynamoDb), Some(Resource::DynamoDbTable(table))) => {
                    eprintln!("grant access to the table {}", table.name());
                }
                // `Service` and `Resource` gain values in later releases, so end every match with a catch-all arm.
                _ => eprintln!("access denied: {e}"),
            },

            Error::ResourceNotFound(not_found) => match not_found.resource() {
                Some(Resource::DynamoDbTable(table)) => {
                    eprintln!("the table {} does not exist", table.name());
                }
                Some(Resource::BranchKey(branch_key)) => {
                    eprintln!("create the branch key {} in the key store", branch_key.id());
                }
                _ => eprintln!("a resource does not exist: {e}"),
            },

            // `Error` gains variants in later releases, so the last arm handles every other failure.
            // `{e:#}` prints the error and every cause below it.
            _ => eprintln!("put_item failed: {e:#}"),
        }
        return Err(e.into());
    }

    // Put the same item again, only if it does not exist yet.
    // DynamoDB rejects it, and the DB-ESDK returns `Error::Conflict`.
    let result = ddb
        .put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item()))
        .condition_expression("attribute_not_exists(partition_key)")
        .send()
        .await;
    match result {
        Ok(_) => return Err("the conditional put must fail".into()),

        // The same failure, matched as `aws_sdk_dynamodb` code matches it.
        // `as_service_error()` returns `None` when DynamoDB did not fail, for example an encryption failure.
        Err(e) => match e.as_service_error() {
            Some(PutItemError::ConditionalCheckFailedException(_)) => {
                assert!(matches!(e, Error::Conflict(_)));
                println!("the item already exists");
            }
            Some(other) => return Err(format!("unexpected DynamoDB error: {other}").into()),
            None => return Err(e.into()),
        },
    }

    println!("Success! Handled a conditional put failure.");
    Ok(())
}
