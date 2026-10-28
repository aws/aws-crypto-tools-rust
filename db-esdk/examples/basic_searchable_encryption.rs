// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Puts an item with a standard beacon on an encrypted attribute, then queries that beacon.
//!
//! The scenario is a table of unit-inspection records. Two attributes are beaconized:
//! `inspector_id_last4` (last 4 digits of an inspector ID) and `unit` (a 12-digit serial number).
//!
//! Requires AWS credentials, a key store with a provisioned branch key, and a DynamoDB table:
//! - partition key `work_id`, type S
//! - sort key `inspection_date`, type S
//! - a GSI `last4-unit-index` with partition key `aws_dbe_b_inspector_id_last4` (S)
//!   and sort key `aws_dbe_b_unit` (S)

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::search::{
    BeaconKeySource, BeaconVersion, SearchConfig, SingleKeyStore, StandardBeacon,
};
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

const TABLE_NAME: &str = "UnitInspectionTable";
const GSI_NAME: &str = "last4-unit-index";
const KEY_STORE_TABLE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);

    // A beacon's bit length trades query performance against how much it reveals.
    // See https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html
    //
    // `inspector_id_last4` ranges over 0..=9,999. The guidance bounds the length to 7..=12;
    // we pick 10, giving 2^10 = 1,024 HMAC values and ~9.8 suffixes sharing each beacon.
    let last4_beacon = StandardBeacon::builder()
        .name("inspector_id_last4")
        .bits(10)
        .number_of_partitions(1)
        .build()?;

    // `unit` is a 12-digit serial (0..=10^12). The guidance bounds the length to 20..=39;
    // we pick 30, giving 2^30 ~= 1.1B HMAC values and ~931 serials sharing each beacon.
    let unit_beacon = StandardBeacon::builder()
        .name("unit")
        .bits(30)
        .number_of_partitions(1)
        .build()?;

    // The key store holds the beacon keys and branch keys. The beacon version and the
    // keyring must share the same key store.
    let key_store = key_store::Client::builder()
        .ddb_table_name(KEY_STORE_TABLE_NAME)
        .logical_key_store_name(KEY_STORE_TABLE_NAME)
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.into()))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(ddb_sdk.clone())
        .build()
        .await?;

    // A beacon version holds the beacons and the beacon-key source for the table.
    // The beacon key is created with the same ID as the branch key.
    // `maximum_number_of_partitions` must exceed each beacon's count; 8 leaves room to grow.
    let beacon_version = BeaconVersion::builder()
        .standard_beacons(last4_beacon)
        .standard_beacons(unit_beacon)
        .version(1)
        .maximum_number_of_partitions(8)
        .default_number_of_partitions(1)
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

    // Beaconized attributes must be EncryptAndSign; the key attributes are SignOnly.
    let table = TableConfig::builder()
        .partition_key_name("work_id")
        .sort_key_name("inspection_date")
        .attribute_actions_on_encrypt("work_id", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("inspection_date", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("inspector_id_last4", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("unit", CryptoAction::EncryptAndSign)
        .keyring(keyring)
        .search(search)
        .build()?;

    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(TABLE_NAME, table)
        .build()?;

    // On write the client adds the beacon attributes `aws_dbe_b_inspector_id_last4`
    // and `aws_dbe_b_unit`, each a truncated HMAC of the plaintext.
    let item = HashMap::from([
        (
            "work_id".to_string(),
            AttributeValue::S("1313ba89-5661-41eb-ba6c-cb1b4cb67b2d".into()),
        ),
        (
            "inspection_date".to_string(),
            AttributeValue::S("2023-06-13".into()),
        ),
        (
            "inspector_id_last4".to_string(),
            AttributeValue::S("4321".into()),
        ),
        ("unit".to_string(), AttributeValue::S("123456789012".into())),
    ]);

    ddb.put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item.clone()))
        .send()
        .await?;

    // Query as if on plaintext. The client rewrites the query onto the beacon attributes,
    // then decrypts the matches and drops any false positives (distinct plaintext, same HMAC).
    let names = HashMap::from([
        ("#last4".to_string(), "inspector_id_last4".to_string()),
        ("#unit".to_string(), "unit".to_string()),
    ]);

    // A beacon can span several partitions; query each one. Here there is a single partition.
    // In general the count comes from the number of beacon partitions configured.
    let num_queries = 1;
    let mut all_results: Vec<HashMap<String, AttributeValue>> = Vec::new();
    for partition in 0..num_queries {
        // `:aws_dbe_partition` selects which beacon partition this query targets.
        let values = HashMap::from([
            (":last4".to_string(), AttributeValue::S("4321".into())),
            (
                ":unit".to_string(),
                AttributeValue::S("123456789012".into()),
            ),
            (
                ":aws_dbe_partition".to_string(),
                AttributeValue::N(partition.to_string()),
            ),
        ]);
        let items = retry_query(|| async {
            let out = ddb
                .query()
                .table_name(TABLE_NAME)
                .index_name(GSI_NAME)
                .key_condition_expression("#last4 = :last4 and #unit = :unit")
                .set_expression_attribute_names(Some(names.clone()))
                .set_expression_attribute_values(Some(values.clone()))
                .send()
                .await?;
            Ok(out.items().to_vec())
        })
        .await?;
        all_results.extend(items);
    }

    assert_eq!(all_results.len(), 1, "expected exactly the item we put");
    let returned = &all_results[0];
    assert_eq!(
        returned["inspector_id_last4"],
        AttributeValue::S("4321".into())
    );
    assert_eq!(returned["unit"], AttributeValue::S("123456789012".into()));

    println!("basic_searchable_encryption successful.");
    Ok(())
}

/// Runs a GSI query until it returns an item, retrying a few times.
/// GSI reads are eventually consistent, so a just-written item may not appear at once.
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
        // The GSI is eventually consistent: give it time to catch up.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err("query returned no items after 10 tries".into())
}
