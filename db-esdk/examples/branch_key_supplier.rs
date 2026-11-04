// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Picks a branch key per tenant from each item's primary key.
//!
//! Each tenant in the table has its own branch key,
//! so one tenant's branch key cannot decrypt another tenant's items.
//! One hierarchical keyring serves every tenant:
//! its supplier reads the tenant from the item's partition key and returns that tenant's branch key ID.
//!
//! Requires AWS credentials, an existing key store, and a DynamoDB table with:
//! - partition key `partition_key`, type S
//! - sort key `sort_key`, type N
//!
//! Each run creates two new branch keys in the key store.

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::{
    GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdOutput, HierarchicalKeyring,
    ItemKeyBranchKeySupplier, ItemKeySupplier,
};
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::types::{CryptoAction, EncryptionContext};
use aws_db_esdk::{
    Error, TableConfig, async_trait, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store,
};

const TABLE_NAME: &str = "DynamoDbEncryptionInterceptorTestTableCS";

/// Maps the tenant in an item's partition key to that tenant's branch key ID.
struct TenantBranchKeySupplier {
    tenant_a: String,
    tenant_b: String,
}

#[async_trait]
impl ItemKeySupplier for TenantBranchKeySupplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdFromItemKeyInput,
    ) -> Result<GetBranchKeyIdOutput, MplError> {
        // `item_key()` holds only the partition and sort key, never the encrypted attributes.
        let branch_key_id = match input.item_key().get("partition_key") {
            Some(AttributeValue::S(tenant)) if tenant == "TenantA" => &self.tenant_a,
            Some(AttributeValue::S(tenant)) if tenant == "TenantB" => &self.tenant_b,
            _ => return Err(MplError::validation("the item has no known tenant")),
        };
        Ok(branch_key_id.as_str().into())
    }
}

fn table_config(keyring: HierarchicalKeyring) -> Result<TableConfig, Error> {
    TableConfig::builder()
        .partition_key_name("partition_key")
        .sort_key_name("sort_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sort_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sensitive_data", CryptoAction::EncryptAndSign)
        .keyring(keyring)
        .build()
}

fn tenant_item(tenant: &str) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S(tenant.into()),
        ),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
        (
            "sensitive_data".to_string(),
            AttributeValue::S(format!("{tenant} secret")),
        ),
    ])
}

fn tenant_key(tenant: &str) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            "partition_key".to_string(),
            AttributeValue::S(tenant.into()),
        ),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
    ])
}

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

    let branch_key_context = EncryptionContext::from([("purpose", "example")]);
    let create_branch_key = async || {
        key_store
            .create_key()
            .set_encryption_context(Some(branch_key_context.clone()))
            .send()
            .await
            .map(|output| output.into_branch_key_id())
    };
    let branch_key_a = create_branch_key().await?;
    let branch_key_b = create_branch_key().await?;

    // The keyring passes the supplier an encryption context.
    // `ItemKeyBranchKeySupplier` rebuilds the item's primary key from it,
    // so `TenantBranchKeySupplier` works with primary keys.
    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store.clone())
        .ttl(Duration::from_secs(600))
        .branch_key_id_supplier(ItemKeyBranchKeySupplier::new(TenantBranchKeySupplier {
            tenant_a: branch_key_a.clone(),
            tenant_b: branch_key_b,
        }))
        .build()
        .await?;
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk.clone())
        .table_encryption_configs(TABLE_NAME, table_config(keyring)?)
        .build()?;

    for tenant in ["TenantA", "TenantB"] {
        ddb.put_item()
            .table_name(TABLE_NAME)
            .set_item(Some(tenant_item(tenant)))
            .send()
            .await?;
    }

    // A client fixed to tenant A's branch key reads tenant A's item...
    let keyring_a = HierarchicalKeyring::builder()
        .key_store(key_store)
        .ttl(Duration::from_secs(600))
        .branch_key_id(&branch_key_a)
        .build()
        .await?;
    let ddb_a = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(TABLE_NAME, table_config(keyring_a)?)
        .build()?;
    let output = ddb_a
        .get_item()
        .table_name(TABLE_NAME)
        .set_key(Some(tenant_key("TenantA")))
        .consistent_read(true)
        .send()
        .await?;
    assert_eq!(output.item(), Some(&tenant_item("TenantA")));

    // ...but not tenant B's.
    let result = ddb_a
        .get_item()
        .table_name(TABLE_NAME)
        .set_key(Some(tenant_key("TenantB")))
        .consistent_read(true)
        .send()
        .await;
    assert!(
        matches!(result, Err(Error::NoMatchingDataKey(_))),
        "a different tenant's branch key must not decrypt the item, got {result:?}"
    );

    println!("Success! Each tenant's item decrypts only under that tenant's branch key.");
    Ok(())
}
