// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Creates a new branch key in a key store.
//!
//! A hierarchical keyring needs a branch key; create one before first use.
//!
//! Requires AWS credentials and an existing key store.
//! Each run creates a new branch key in it.

use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::{aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, logical name, and KMS key ARN.
    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name("KeyStoreDdbTable")
        .logical_key_store_name("KeyStoreDdbTable")
        .kms_configuration(KmsConfiguration::kms_key_arn(
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126",
        ))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .build()
        .await?;

    // The key store picks a random branch key ID.
    // The key store binds the encryption context to every version of the branch key.
    let branch_key_id = key_store
        .create_key()
        .encryption_context("purpose", "example")
        .send()
        .await?
        .into_branch_key_id();

    println!("Success! Created branch key {branch_key_id}.");
    Ok(())
}
