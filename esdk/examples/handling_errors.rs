// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handles the errors that the hierarchical keyring and its key store return.
//!
//! Each call matches on the error's variant, then on its service and resource.
//! Decide from these, never from the message text.
//!
//! Requires AWS credentials and an existing key store with a provisioned branch key.
//! Each run creates a branch key and rotates it.

use std::time::Duration;

use aws_crypto_mpl::error::ConflictReason;
use aws_crypto_mpl::key_store::{BranchKeyStore, KeyStoreClient, KmsConfiguration};
use aws_crypto_mpl::{HierarchicalKeyring, aws_config, aws_sdk_dynamodb, aws_sdk_kms};
use aws_esdk::error::{Error, Resource, Service};
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};

// The AWS Crypto Tools CI test key store.
// Replace these with your own key store's table, name, KMS key ARN, and branch key ID.
const TABLE_NAME: &str = "KeyStoreDdbTable";
const LOGICAL_KEY_STORE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

const PLAINTEXT: &[u8] = b"Hello World";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let key_store = KeyStoreClient::from(
        BranchKeyStore::builder()
            .ddb_table_name(TABLE_NAME)
            .logical_key_store_name(LOGICAL_KEY_STORE_NAME)
            .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.to_string()))
            .kms_client(aws_sdk_kms::Client::new(&sdk_config))
            .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
            .build()
            .await?,
    );
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store.clone())
        .ttl(Duration::from_secs(600))
        .branch_key_id(BRANCH_KEY_ID)
        .build()?;

    let input = EncryptInput::builder()
        .plaintext(PLAINTEXT)
        .keyring(keyring.clone())
        .build()?;
    let encrypted = match encrypt(&input).await {
        Ok(output) => output,
        Err(e) => {
            match &e {
                // The AWS SDK clients already retried; e.retry_kind() says how to back off.
                err if err.is_retryable() => eprintln!("retry later: {e}"),
                Error::AccessDenied(denied) if denied.is_credentials() => {
                    eprintln!("the AWS credentials are expired or invalid");
                }
                Error::AccessDenied(denied) => match denied.service() {
                    Some(Service::Kms) => match denied.resource() {
                        Some(Resource::KmsKey(key)) => {
                            eprintln!("AWS KMS denied access to the KMS key {}", key.arn());
                        }
                        _ => eprintln!("AWS KMS denied access: {e}"),
                    },
                    Some(Service::DynamoDb) => match denied.resource() {
                        Some(Resource::DynamoDbTable(table)) => {
                            eprintln!("DynamoDB denied access to the table {}", table.name());
                        }
                        _ => eprintln!("DynamoDB denied access: {e}"),
                    },
                    _ => eprintln!("access denied: {e}"),
                },
                Error::ResourceNotFound(not_found) => match not_found.resource() {
                    Some(Resource::BranchKey(branch_key)) => {
                        eprintln!("branch key {} is not in the key store", branch_key.id());
                    }
                    Some(Resource::DynamoDbTable(table)) => {
                        eprintln!("the key store table {} does not exist", table.name());
                    }
                    Some(Resource::KmsKey(key)) => {
                        eprintln!("the KMS key {} does not exist", key.arn());
                    }
                    _ => eprintln!("an AWS resource does not exist: {e}"),
                },
                _ => eprintln!("encrypt failed: {e}"),
            }
            return Err(e.into());
        }
    };

    let input = DecryptInput::builder()
        .ciphertext(&encrypted.ciphertext)
        .keyring(keyring)
        .build()?;
    let decrypted = match decrypt(&input).await {
        Ok(output) => output,
        Err(e) => {
            match &e {
                err if err.is_retryable() => eprintln!("retry later: {e}"),
                Error::InvalidMaterials(invalid) => match invalid.resource() {
                    Some(Resource::BranchKey(branch_key)) => {
                        eprintln!("the record for branch key {} is malformed", branch_key.id());
                    }
                    _ => eprintln!("invalid materials: {e}"),
                },
                Error::NoMatchingDataKey(_) => {
                    eprintln!("the message was encrypted under a different keyring");
                }
                Error::Cryptographic(_) | Error::Serialization(_) => {
                    eprintln!("the message is corrupt or was tampered with");
                }
                // Each encrypted data key the keyring tried can fail differently.
                _ => {
                    for failure in e.failures() {
                        eprintln!("decrypt failed: {failure}");
                    }
                }
            }
            return Err(e.into());
        }
    };
    assert_eq!(decrypted.plaintext, PLAINTEXT);
    println!("decrypted the message");

    let mut branch_key_context = EncryptionContext::new();
    branch_key_context.insert("purpose", "example");
    match key_store
        .create_key()
        .branch_key_id(BRANCH_KEY_ID)
        .encryption_context(branch_key_context)
        .send()
        .await
    {
        Ok(output) => println!("created branch key {}", output.branch_key_id()),
        Err(aws_crypto_mpl::Error::Conflict(conflict)) => match conflict.reason() {
            Some(ConflictReason::AlreadyExists) => {
                println!("branch key {BRANCH_KEY_ID} already exists");
            }
            _ => return Err(conflict.into()),
        },
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
