// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shares one storm-tracking cache across two hierarchical keyrings.
//!
//! A hierarchical keyring caches branch key material so it does not call KMS on every item.
//! By default, each keyring gets its own cache.
//! Keyrings that share one cache reuse each other's entries
//! when they also have the same partition ID, logical key store name, and branch key ID.
//! Here the two keyrings serve two tables, as one service writing to both would.
//! The cache tells key stores apart by logical name, so never give two different key store tables the same logical name.
//!
//! A storm-tracking cache also keeps concurrent requests from all refreshing the same entry:
//! near expiry, one request refreshes the entry while the others keep using the cached value.
//!
//! Requires AWS credentials, an existing key store with a provisioned branch key,
//! and two DynamoDB tables, each with partition key `partition_key` (S) and sort key `sort_key` (N).

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::cmc::StormTrackingCmc;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

// The AWS Crypto Tools CI test tables.
// Replace these with your own tables.
const ORDERS_TABLE: &str = "DynamoDbEncryptionInterceptorTestTable";
const CUSTOMERS_TABLE: &str = "DynamoDbEncryptionInterceptorTestTableCS";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, logical name, and KMS key ARN.
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

    // Every parameter is optional; each value set here is its default.
    let cache = StormTrackingCmc::builder()
        // Maximum number of entries that the cache holds.
        .entry_capacity(1000)
        // How many of the least recently used entries the cache checks for expiry on each lookup.
        .entry_pruning_tail_size(1)
        // How long before expiry one request starts refreshing an entry.
        // Must be less than the keyring TTL.
        .grace_period(Duration::from_secs(10))
        // How long the other requests wait before another one may try to refresh the entry.
        .grace_interval(Duration::from_secs(1))
        // Maximum number of entries being refreshed at the same time.
        .fan_out(20)
        // How long a refresh may run before another request may retry it.
        .in_flight_ttl(Duration::from_secs(10))
        // How long a waiting request sleeps before checking the cache again.
        .sleep(Duration::from_millis(20))
        .build()?;

    // Both keyrings have the same cache, partition ID, logical key store name, and branch key ID,
    // so they reuse each other's entries.
    let make_table = async || -> Result<TableConfig, Box<dyn std::error::Error>> {
        let keyring = HierarchicalKeyring::builder()
            .key_store(key_store.clone())
            .ttl(Duration::from_secs(600))
            .branch_key_id("3f43a9af-08c5-4317-b694-3d3e883dcaef")
            .cache(cache.clone())
            .partition_id("shared-partition")
            .build()
            .await?;
        Ok(TableConfig::builder()
            .partition_key_name("partition_key")
            .sort_key_name("sort_key")
            .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
            .attribute_actions_on_encrypt("sort_key", CryptoAction::SignOnly)
            .attribute_actions_on_encrypt("sensitive_data", CryptoAction::EncryptAndSign)
            .keyring(keyring)
            .build()?)
    };

    // One client, two encrypted tables, each with its own keyring.
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(ORDERS_TABLE, make_table().await?)
        .table_encryption_configs(CUSTOMERS_TABLE, make_table().await?)
        .build()
        .await?;

    // The first put fetches the branch key from KMS; the second reuses the cached entry.
    for table in [ORDERS_TABLE, CUSTOMERS_TABLE] {
        let item = HashMap::from([
            (
                "partition_key".to_string(),
                AttributeValue::S("SharedCacheExample".into()),
            ),
            ("sort_key".to_string(), AttributeValue::N("0".into())),
            (
                "sensitive_data".to_string(),
                AttributeValue::S(format!("{table} secret")),
            ),
        ]);
        ddb.put_item()
            .table_name(table)
            .set_item(Some(item.clone()))
            .send()
            .await?;

        let key = HashMap::from([
            (
                "partition_key".to_string(),
                AttributeValue::S("SharedCacheExample".into()),
            ),
            ("sort_key".to_string(), AttributeValue::N("0".into())),
        ]);
        let output = ddb
            .get_item()
            .table_name(table)
            .set_key(Some(key))
            .consistent_read(true)
            .send()
            .await?;
        assert_eq!(
            output.item(),
            Some(&item),
            "Decryption failed: item mismatch"
        );
    }

    println!("Success! Two tables' keyrings shared one storm-tracking cache.");
    Ok(())
}
