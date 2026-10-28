// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Step 0 — pre-migration starting state.
//!
//! Writes and reads with a plain DynamoDB client, so every item is stored in
//! plaintext. This is the system before any encryption is deployed. A plaintext
//! reader can read plaintext items; it cannot read client-side-encrypted items
//! (their encrypted attributes surface as missing, and verification fails).
//!
//! Nothing new needs to be deployed before Step 1.

use aws_db_esdk::{aws_config, aws_sdk_dynamodb};

use crate::common::DDB_TABLE_NAME;
use crate::migration_utils::{primary_key, sample_item, verify_returned_item};

pub async fn run(
    sdk_config: &aws_config::SdkConfig,
    partition_key: &str,
    sort_key_write: &str,
    sort_key_read: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // A standard DynamoDB client — no encryption configured.
    let ddb = aws_sdk_dynamodb::Client::new(sdk_config);

    // Write a plaintext item.
    ddb.put_item()
        .table_name(DDB_TABLE_NAME)
        .set_item(Some(sample_item(partition_key, sort_key_write)))
        .send()
        .await?;

    // Read it back. Strongly consistent because we read right after writing.
    let output = ddb
        .get_item()
        .table_name(DDB_TABLE_NAME)
        .set_key(Some(primary_key(partition_key, sort_key_read)))
        .consistent_read(true)
        .send()
        .await?;

    match output.item() {
        Some(item) => {
            verify_returned_item(item, partition_key, sort_key_read)?;
            println!("step 0: read plaintext item at sort_key {sort_key_read}");
            Ok(())
        }
        None => Err("no item found".into()),
    }
}
