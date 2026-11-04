// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds a virtual field from two attributes, puts a beacon on it, then queries that beacon.
//!
//! A virtual field is a transform of one or more attributes.
//! The client stores only the field's beacon, not the field itself.
//! Here the field is `state` followed by the first character of `hasTestResult`: "CA" + "t" = "CAt".
//! A query can then combine `state` with the boolean `hasTestResult`,
//! with no beacon on the boolean alone that would reveal how its values are distributed.
//!
//! Requires AWS credentials, a key store with a provisioned branch key, and a DynamoDB table:
//! - partition key `customer_id`, type S
//! - sort key `create_time`, type S
//! - a GSI `stateAndHasTestResult-index` with partition key `aws_dbe_b_stateAndHasTestResult` (S)

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::search::{
    BeaconKeySource, BeaconVersion, SearchConfig, SingleKeyStore, StandardBeacon, VirtualField,
    VirtualPart, VirtualTransform,
};
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

const TABLE_NAME: &str = "SimpleBeaconTestTable";
const GSI_NAME: &str = "stateAndHasTestResult-index";
const KEY_STORE_TABLE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);

    // Transforms treat every value as a string, so the length-1 prefix turns "true" and "false" into "t" and "f".
    // The client joins the parts in order, and the query value must use the same order.
    let state_part = VirtualPart::builder().location("state").build()?;
    let has_test_result_part = VirtualPart::builder()
        .location("hasTestResult")
        .transforms(VirtualTransform::prefix(1))
        .build()?;

    let virtual_fields = vec![
        VirtualField::builder()
            .name("stateAndHasTestResult")
            .parts(state_part)
            .parts(has_test_result_part)
            .build()?,
    ];

    // `state` has 56 values, so combined with the boolean the field has about 112.
    // The length guidance puts the beacon between 3 and 6 bits.
    // 5 bits gives 2^5 = 32 beacon values, with about 3.5 combinations sharing each one.
    // See `basic_searchable_encryption` for the length trade-off.
    let standard_beacons = vec![
        StandardBeacon::builder()
            .name("stateAndHasTestResult")
            .bits(5)
            .build()?,
    ];

    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name(KEY_STORE_TABLE_NAME)
        .logical_key_store_name(KEY_STORE_TABLE_NAME)
        .kms_configuration(KmsConfiguration::kms_key_arn(KMS_KEY_ARN))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(ddb_sdk.clone())
        .build()
        .await?;

    let beacon_version = BeaconVersion::builder()
        .set_standard_beacons(Some(standard_beacons))
        .set_virtual_fields(Some(virtual_fields))
        .version(1)
        .key_store(key_store.clone())
        .key_source(BeaconKeySource::Single(
            SingleKeyStore::builder()
                .key_id(BRANCH_KEY_ID)
                .cache_ttl(Duration::from_secs(6000))
                .build()?,
        ))
        .build()?;

    let search = SearchConfig::builder()
        .write_version(1)
        .versions(beacon_version)
        .build()?;

    let keyring = HierarchicalKeyring::builder()
        .key_store(key_store)
        .branch_key_id(BRANCH_KEY_ID)
        .ttl(Duration::from_secs(6000))
        .build()
        .await?;

    // The virtual field's source attributes must be EncryptAndSign; key attributes are SignOnly.
    let table = TableConfig::builder()
        .partition_key_name("customer_id")
        .sort_key_name("create_time")
        .attribute_actions_on_encrypt("customer_id", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("create_time", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("state", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("hasTestResult", CryptoAction::EncryptAndSign)
        .keyring(keyring)
        .search(search)
        .build()?;

    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(TABLE_NAME, table)
        .build()?;

    // Two items that differ only in customer_id and hasTestResult.
    let item_with_test_result = HashMap::from([
        (
            "customer_id".to_string(),
            AttributeValue::S("ABC-123".into()),
        ),
        (
            "create_time".to_string(),
            AttributeValue::N("1681495205".into()),
        ),
        ("state".to_string(), AttributeValue::S("CA".into())),
        ("hasTestResult".to_string(), AttributeValue::Bool(true)),
    ]);
    let item_without_test_result = HashMap::from([
        (
            "customer_id".to_string(),
            AttributeValue::S("DEF-456".into()),
        ),
        (
            "create_time".to_string(),
            AttributeValue::N("1681495205".into()),
        ),
        ("state".to_string(), AttributeValue::S("CA".into())),
        ("hasTestResult".to_string(), AttributeValue::Bool(false)),
    ]);

    // During development, `resolve_attributes` shows the virtual field value that this config computes.
    let resolved = ddb
        .resolve_attributes()
        .table_name(TABLE_NAME)
        .item(item_with_test_result.clone())
        .send()
        .await?;
    assert_eq!(resolved.compound_beacons().len(), 0);
    let virtual_fields = resolved.virtual_fields();
    assert_eq!(virtual_fields.len(), 1);
    assert_eq!(virtual_fields["stateAndHasTestResult"], "CAt");

    ddb.put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item_with_test_result.clone()))
        .send()
        .await?;
    ddb.put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item_without_test_result.clone()))
        .send()
        .await?;

    // Query for state=CA and hasTestResult=true.
    // Build the query value the way the client builds the field: `state`, then the first character of `hasTestResult`.
    let values = HashMap::from([(
        ":stateAndHasTestResult".to_string(),
        AttributeValue::S("CAt".into()),
    )]);
    let items = retry_query(|| async {
        let out = ddb
            .query()
            .table_name(TABLE_NAME)
            .index_name(GSI_NAME)
            .key_condition_expression("stateAndHasTestResult = :stateAndHasTestResult")
            .set_expression_attribute_values(Some(values.clone()))
            .send()
            .await?;
        Ok(out.items().to_vec())
    })
    .await?;

    assert_eq!(items.len(), 1, "expected exactly the matching item");
    let returned = &items[0];
    assert_eq!(returned["state"], AttributeValue::S("CA".into()));
    assert_eq!(returned["hasTestResult"], AttributeValue::Bool(true));

    println!("virtual_beacon_searchable_encryption successful.");
    Ok(())
}

/// Runs a GSI query until it returns an item, retrying a few times.
/// GSI reads are eventually consistent, so an item may not appear right after it is written.
async fn retry_query<F, Fut>(
    query: F,
) -> Result<Vec<HashMap<String, AttributeValue>>, Box<dyn std::error::Error>>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<
            Output = Result<Vec<HashMap<String, AttributeValue>>, aws_db_esdk::Error>,
        >,
{
    for _ in 0..10 {
        let items = query().await?;
        if !items.is_empty() {
            return Ok(items);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err("query returned no items after 10 tries".into())
}
