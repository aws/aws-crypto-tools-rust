// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Step 2 — start writing encrypted items.
//!
//! Uses `PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead`:
//!   - Write: forbidden as plaintext (always encrypted).
//!   - Read:  plaintext or encrypted, both allowed.
//!
//! After this deploys, the dataset holds a mix of plaintext and encrypted
//! items; Step 1 already made every reader able to read both. Before Step 3,
//! back-fill: re-encrypt all remaining plaintext items in the dataset.

use aws_db_esdk::aws_config;
use aws_db_esdk::aws_sdk_dynamodb;
use aws_db_esdk::types::PlaintextOverride;

use crate::common::{DDB_TABLE_NAME, encrypted_client};
use crate::migration_utils::{primary_key, sample_item, verify_returned_item};

pub async fn run(
    sdk_config: &aws_config::SdkConfig,
    partition_key: &str,
    sort_key_write: &str,
    sort_key_read: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ddb_sdk = aws_sdk_dynamodb::Client::new(sdk_config);
    let ddb = encrypted_client(
        sdk_config,
        ddb_sdk,
        Some(PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead),
    )
    .await?;

    // Written encrypted, because of the override above.
    ddb.put_item()
        .table_name(DDB_TABLE_NAME)
        .set_item(Some(sample_item(partition_key, sort_key_write)))
        .send()
        .await?;

    // Still reads plaintext items as well as encrypted ones.
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
            println!("step 2: read item at sort_key {sort_key_read}");
            Ok(())
        }
        None => Err("no item found".into()),
    }
}
