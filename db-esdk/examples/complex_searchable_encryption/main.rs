// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runs the searchable encryption workshop end to end:
//! - one table that holds six record types: meetings, employees, projects, reservations, tickets, and time cards
//! - a beacon configuration with many standard and compound beacons
//! - 23 queries over the beacons
//!
//! The data here is for illustration.
//! It may not meet the distribution and correlation guidance for real beacons; see
//! <https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html#are-beacons-right-for-me>.
//!
//! Requires AWS credentials, an existing key store with a provisioned branch key,
//! and a DynamoDB table `ComplexBeaconTestTable` with:
//! - partition key `partition_key`, type S
//! - global secondary indexes over the compound beacon attributes that this configuration writes:
//!   - `GSI-0`: hash `PK`, range `SK`
//!   - `GSI-1`: hash `PK1`, range `SK1`
//!   - `GSI-2`: hash `PK2`
//!   - `GSI-3`: hash `PK3`, range `SK3`

mod beacon_config;
mod put_requests;
mod query_requests;

use aws_db_esdk::key_store::types::KmsConfiguration;
use aws_db_esdk::{aws_config, aws_sdk_dynamodb, aws_sdk_kms, key_store};

type BoxError = Box<dyn std::error::Error>;

const TABLE_NAME: &str = "ComplexBeaconTestTable";
const KEY_STORE_TABLE_NAME: &str = "KeyStoreDdbTable";
const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const BRANCH_KEY_ID: &str = "3f43a9af-08c5-4317-b694-3d3e883dcaef";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // The clients take their region and credentials from the default AWS config chain.
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb_sdk = aws_sdk_dynamodb::Client::new(&sdk_config);

    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, logical name, and KMS key ARN.
    let key_store = key_store::DynamoDbKeyStore::builder()
        .ddb_table_name(KEY_STORE_TABLE_NAME)
        .logical_key_store_name(KEY_STORE_TABLE_NAME)
        .kms_configuration(KmsConfiguration::kms_key_arn(KMS_KEY_ARN))
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .ddb_client(ddb_sdk.clone())
        .build()
        .await?;

    let table = beacon_config::table_config(&key_store).await?;

    // The same DynamoDB client serves the key store and the encrypted table.
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(ddb_sdk)
        .table_encryption_configs(TABLE_NAME, table)
        .build()
        .await?;

    put_requests::put_all_items_to_table(&ddb).await?;
    query_requests::run_queries(&ddb).await?;

    println!("Success! Ran the complex searchable-encryption example.");
    Ok(())
}
