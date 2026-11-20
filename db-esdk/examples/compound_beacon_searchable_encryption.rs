// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sets up a compound beacon over two encrypted attributes, then queries it.
//!
//! The scenario is the unit inspection table from `basic_searchable_encryption`.
//! Here one GSI covers both `inspector_id_last4` and `unit`, through a compound beacon over the two.
//!
//! Requires AWS credentials, a key store with a provisioned branch key, and a DynamoDB table:
//! - partition key `work_id`, type S
//! - sort key `inspection_date`, type S
//! - a GSI `last4UnitCompound-index` with partition key `aws_dbe_b_last4UnitCompound` (S)

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::search::{
    BeaconKeySource, BeaconVersion, CompoundBeacon, EncryptedPart, SearchConfig, SingleKeyStore,
    StandardBeacon,
};
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

const TABLE_NAME: &str = "UnitInspectionTestTableCS";
const GSI_NAME: &str = "last4UnitCompound-index";
const KEY_STORE_TABLE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);

    // Each encrypted part of a compound beacon must also be a standard beacon.
    // See `basic_searchable_encryption` for how to choose bit lengths.
    let standard_beacons = vec![
        StandardBeacon::builder()
            .name("inspector_id_last4")
            .bits(10)
            .build()?,
        StandardBeacon::builder().name("unit").bits(30).build()?,
    ];

    // Each encrypted part names a standard beacon and a prefix.
    // Prefixes must be unique, and none may be a prefix of another.
    // With no constructor given, the beacon joins the encrypted parts in order: `L-<last4>.U-<unit>`.
    let compound_beacons = vec![
        CompoundBeacon::builder()
            .name("last4UnitCompound")
            .split(".")
            .encrypted(
                EncryptedPart::builder()
                    .name("inspector_id_last4")
                    .prefix("L-")
                    .build()?,
            )
            .encrypted(EncryptedPart::builder().name("unit").prefix("U-").build()?)
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
        .set_compound_beacons(Some(compound_beacons))
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

    // Only the attributes in the written item need a crypto action, not the compound beacon.
    // Attributes with a standard beacon are EncryptAndSign; the key attributes are SignOnly.
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
        .build()
        .await?;

    let item = HashMap::from([
        (
            "work_id".to_string(),
            AttributeValue::S("9ce39272-8068-4efd-a211-cd162ad65d4c".into()),
        ),
        (
            "inspection_date".to_string(),
            AttributeValue::S("2023-06-13".into()),
        ),
        (
            "inspector_id_last4".to_string(),
            AttributeValue::S("5678".into()),
        ),
        ("unit".to_string(), AttributeValue::S("011899988199".into())),
    ]);

    // During development, `resolve_attributes` shows the compound beacon value that this config builds from an item.
    // The table does not store this value: it stores the beacon, with each encrypted part replaced by its HMAC.
    let resolved = ddb
        .resolve_attributes()
        .table_name(TABLE_NAME)
        .item(item.clone())
        .send()
        .await?;
    assert_eq!(resolved.virtual_fields().len(), 0);
    let compound_beacons = resolved.compound_beacons();
    assert_eq!(compound_beacons.len(), 1);
    assert_eq!(
        compound_beacons["last4UnitCompound"],
        "L-5678.U-011899988199"
    );

    ddb.put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item.clone()))
        .send()
        .await?;

    // Query the compound beacon with its plaintext value.
    // The parts go in the order that the encrypted parts are listed: last4, then unit.
    let values = HashMap::from([(
        ":value".to_string(),
        AttributeValue::S("L-5678.U-011899988199".into()),
    )]);
    let items = retry_query(|| async {
        let out = ddb
            .query()
            .table_name(TABLE_NAME)
            .index_name(GSI_NAME)
            .key_condition_expression("last4UnitCompound = :value")
            .set_expression_attribute_values(Some(values.clone()))
            .send()
            .await?;
        Ok(out.items().to_vec())
    })
    .await?;

    assert_eq!(items.len(), 1, "expected exactly the item we put");
    let returned = &items[0];
    assert_eq!(
        returned["inspector_id_last4"],
        AttributeValue::S("5678".into())
    );
    assert_eq!(returned["unit"], AttributeValue::S("011899988199".into()));

    println!("compound_beacon_searchable_encryption successful.");
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
