// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lists which keys protect an encrypted item, without decrypting it.
//!
//! `describe_encrypted_data_keys` reads only the item's header, so it needs no keyring and makes no AWS call.
//! Use it to find which branch key an item needs, for example before a key migration.
//!
//! Requires AWS credentials and the item written by the `hierarchical_keyring` example.

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::{aws_config, aws_sdk_dynamodb};

const TABLE_NAME: &str = "DynamoDbEncryptionInterceptorTestTableCS";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A plain DynamoDB client: the item comes back still encrypted.
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb = aws_sdk_dynamodb::Client::new(&sdk_config);

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
        .send()
        .await?;
    let item = output
        .item()
        .ok_or("the item does not exist; run hierarchical_keyring first")?;

    let keys = aws_db_esdk::describe_encrypted_data_keys(item)?;

    // A hierarchical keyring writes one encrypted data key, naming its branch key.
    assert_eq!(keys[0].key_provider_id(), "aws-kms-hierarchy");
    assert_eq!(keys[0].branch_key_id(), Some(BRANCH_KEY_ID));

    println!("Success! The item is protected by branch key {BRANCH_KEY_ID}.");
    Ok(())
}
