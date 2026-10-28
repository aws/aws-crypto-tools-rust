// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shows the beacon styles on standard beacons, then queries each with a scan.
//!
//! The scenario stores food records. It builds on the basic example and uses the same table.
//! Styles shown: a plain beacon (`fruit`), a `SharedSet` set beacon (`basket`, comparable to
//! `fruit`), a `Shared` beacon (`dessert`, comparable to `fruit`), an `AsSet` set beacon
//! (`veggies`), and a `PartOnly` beacon (`work_type`, usable only inside a compound beacon).
//!
//! Requires AWS credentials, a key store with a provisioned branch key, and a DynamoDB table:
//! - partition key `work_id`, type S
//! - sort key `inspection_date`, type S

use std::collections::HashMap;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::keyring::HierarchicalKeyring;
use aws_db_esdk::search::{
    BeaconKeySource, BeaconStyle, BeaconVersion, CompoundBeacon, EncryptedPart, SearchConfig,
    SignedPart, SingleKeyStore, StandardBeacon,
};
use aws_db_esdk::types::CryptoAction;
use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

const TABLE_NAME: &str = "UnitInspectionTable";
const KEY_STORE_TABLE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";
const INSPECTION_DATE: &str = "2023-06-13";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);

    // See the basic example for how to choose a beacon's bit length. We use 30 throughout.
    let standard_beacons = vec![
        StandardBeacon::builder().name("fruit").bits(30).build()?,
        // `basket` is a set shared with `fruit`, so set members can be compared to `fruit`.
        StandardBeacon::builder()
            .name("basket")
            .bits(30)
            .style(BeaconStyle::shared_set("fruit"))
            .build()?,
        // `dessert` shares `fruit` so the two scalars can be compared.
        StandardBeacon::builder()
            .name("dessert")
            .bits(30)
            .style(BeaconStyle::shared("fruit"))
            .build()?,
        // `veggies` is a set that is not shared with any other beacon.
        StandardBeacon::builder()
            .name("veggies")
            .bits(30)
            .style(BeaconStyle::as_set())
            .build()?,
        // `work_type` is only ever used inside `work_unit`, so disable it as a standalone beacon.
        StandardBeacon::builder()
            .name("work_type")
            .bits(30)
            .style(BeaconStyle::part_only())
            .build()?,
    ];

    // Build a compound beacon `work_unit` from the signed `work_id` and the PartOnly `work_type`.
    // The default constructor writes it as the signed part then the encrypted part: `I-...​.T-...`.
    let compound_beacons = vec![
        CompoundBeacon::builder()
            .name("work_unit")
            .split(".")
            .encrypted(
                EncryptedPart::builder()
                    .name("work_type")
                    .prefix("T-")
                    .build()?,
            )
            .signed(SignedPart::builder().name("work_id").prefix("I-").build()?)
            .build()?,
    ];

    let key_store = key_store::Client::builder()
        .ddb_table_name(KEY_STORE_TABLE_NAME)
        .logical_key_store_name(KEY_STORE_TABLE_NAME)
        .kms_configuration(KmsConfiguration::KmsKeyArn(KMS_KEY_ARN.into()))
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

    // Beaconized attributes must be EncryptAndSign; the key attributes are SignOnly.
    let table = TableConfig::builder()
        .partition_key_name("work_id")
        .sort_key_name("inspection_date")
        .attribute_actions_on_encrypt("work_id", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("inspection_date", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("dessert", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("fruit", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("basket", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("veggies", CryptoAction::EncryptAndSign)
        .attribute_actions_on_encrypt("work_type", CryptoAction::EncryptAndSign)
        .keyring(keyring)
        .search(search)
        .build()?;

    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(TABLE_NAME, table)
        .build()?;

    // Fresh work_id values per run avoid colliding with stale items.
    let work_id1 = uuid::Uuid::new_v4().to_string();
    let work_id2 = uuid::Uuid::new_v4().to_string();

    // Item one: dessert != fruit, and fruit is in basket.
    let item1 = HashMap::from([
        ("work_id".to_string(), AttributeValue::S(work_id1.clone())),
        (
            "inspection_date".to_string(),
            AttributeValue::S(INSPECTION_DATE.into()),
        ),
        ("dessert".to_string(), AttributeValue::S("cake".into())),
        ("fruit".to_string(), AttributeValue::S("banana".into())),
        (
            "basket".to_string(),
            AttributeValue::Ss(vec!["banana".into(), "apple".into(), "pear".into()]),
        ),
        (
            "veggies".to_string(),
            AttributeValue::Ss(vec!["beans".into(), "carrots".into(), "celery".into()]),
        ),
        ("work_type".to_string(), AttributeValue::S("small".into())),
    ]);

    // Item two: dessert == fruit, and fruit is not in basket.
    let item2 = HashMap::from([
        ("work_id".to_string(), AttributeValue::S(work_id2.clone())),
        (
            "inspection_date".to_string(),
            AttributeValue::S(INSPECTION_DATE.into()),
        ),
        ("dessert".to_string(), AttributeValue::S("orange".into())),
        ("fruit".to_string(), AttributeValue::S("orange".into())),
        (
            "basket".to_string(),
            AttributeValue::Ss(vec![
                "strawberry".into(),
                "blueberry".into(),
                "blackberry".into(),
            ]),
        ),
        (
            "veggies".to_string(),
            AttributeValue::Ss(vec!["beans".into(), "carrots".into(), "peas".into()]),
        ),
        ("work_type".to_string(), AttributeValue::S("large".into())),
    ]);

    ddb.put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item1.clone()))
        .send()
        .await?;
    ddb.put_item()
        .table_name(TABLE_NAME)
        .set_item(Some(item2.clone()))
        .send()
        .await?;

    // Run the scans, then clean up both items whatever the outcome.
    let result = run_scan_tests(&ddb, &item1, &item2, &work_id1, &work_id2).await;

    let plain_ddb = aws_sdk_dynamodb::Client::new(&sdk_config);
    for work_id in [work_id1, work_id2] {
        let _ = plain_ddb
            .delete_item()
            .table_name(TABLE_NAME)
            .key("work_id", AttributeValue::S(work_id))
            .key("inspection_date", AttributeValue::S(INSPECTION_DATE.into()))
            .send()
            .await;
    }

    result?;
    println!("beacon_styles_searchable_encryption successful.");
    Ok(())
}

/// Exercises each beacon style with a scan. The `work_id` filter keeps the scan to this run's items.
async fn run_scan_tests(
    ddb: &aws_db_esdk::Client,
    item1: &HashMap<String, AttributeValue>,
    item2: &HashMap<String, AttributeValue>,
    work_id1: &str,
    work_id2: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let wid_filter = "work_id IN (:wid1, :wid2)";
    let wid_values = HashMap::from([
        (":wid1".to_string(), AttributeValue::S(work_id1.to_string())),
        (":wid2".to_string(), AttributeValue::S(work_id2.to_string())),
    ]);

    // SharedSet: basket contains a given value.
    let mut values = wid_values.clone();
    values.insert(":value".to_string(), AttributeValue::S("banana".into()));
    let items = ddb
        .scan()
        .table_name(TABLE_NAME)
        .filter_expression(format!("{wid_filter} AND contains(basket, :value)"))
        .set_expression_attribute_values(Some(values))
        .send()
        .await?
        .items()
        .to_vec();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["work_id"], item1["work_id"]);

    // SharedSet: basket contains the fruit attribute.
    let items = ddb
        .scan()
        .table_name(TABLE_NAME)
        .filter_expression(format!("{wid_filter} AND contains(basket, fruit)"))
        .set_expression_attribute_values(Some(wid_values.clone()))
        .send()
        .await?
        .items()
        .to_vec();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["work_id"], item1["work_id"]);

    // SharedSet: fruit is a member of a given set.
    let mut values = wid_values.clone();
    values.insert(
        ":value".to_string(),
        AttributeValue::Ss(vec!["boysenberry".into(), "orange".into(), "grape".into()]),
    );
    let items = ddb
        .scan()
        .table_name(TABLE_NAME)
        .filter_expression(format!("{wid_filter} AND contains(:value, fruit)"))
        .set_expression_attribute_values(Some(values))
        .send()
        .await?
        .items()
        .to_vec();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["work_id"], item2["work_id"]);

    // Shared: dessert equals fruit.
    let items = ddb
        .scan()
        .table_name(TABLE_NAME)
        .filter_expression(format!("{wid_filter} AND dessert = fruit"))
        .set_expression_attribute_values(Some(wid_values.clone()))
        .send()
        .await?
        .items()
        .to_vec();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["work_id"], item2["work_id"]);

    // AsSet: veggies contains a given value.
    let mut values = wid_values.clone();
    values.insert(":value".to_string(), AttributeValue::S("peas".into()));
    let items = ddb
        .scan()
        .table_name(TABLE_NAME)
        .filter_expression(format!("{wid_filter} AND contains(veggies, :value)"))
        .set_expression_attribute_values(Some(values))
        .send()
        .await?
        .items()
        .to_vec();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["work_id"], item2["work_id"]);

    // Compound beacon: work_unit equals the composed value.
    let mut values = wid_values.clone();
    values.insert(
        ":value".to_string(),
        AttributeValue::S(format!("I-{work_id1}.T-small")),
    );
    let items = ddb
        .scan()
        .table_name(TABLE_NAME)
        .filter_expression(format!("{wid_filter} AND work_unit = :value"))
        .set_expression_attribute_values(Some(values))
        .send()
        .await?
        .items()
        .to_vec();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["work_id"], item1["work_id"]);

    Ok(())
}
