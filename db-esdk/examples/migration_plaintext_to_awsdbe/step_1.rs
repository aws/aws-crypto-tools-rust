// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Step 1: prepare every reader for encrypted items.
//!
//! Uses `PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead`:
//!   - Write: always plaintext.
//!   - Read:  plaintext or encrypted.
//!
//! The dataset is still all plaintext; this step only gets the readers ready.
//! Deploy step 1 to every reader before moving to step 2.

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
        Some(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead),
    )
    .await?;

    // Written as plaintext, because of the override above.
    ddb.put_item()
        .table_name(DDB_TABLE_NAME)
        .set_item(Some(sample_item(partition_key, sort_key_write)))
        .send()
        .await?;

    // Returns a plaintext item as it is, and decrypts an encrypted one.
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
            println!("step 1: read item at sort_key {sort_key_read}");
            Ok(())
        }
        None => Err("no item found".into()),
    }
}
