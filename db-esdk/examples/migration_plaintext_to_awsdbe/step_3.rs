// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Step 3: the final state, with every item encrypted.
//!
//! Leaves the plaintext override unset, so it takes the default, `ForbidPlaintextWriteForbidPlaintextRead`:
//!   - Write: always encrypted.
//!   - Read:  encrypted only; reading a plaintext item fails.
//!
//! Deploy step 3 only after re-encrypting every remaining plaintext item, as step 2 describes.
//! From then on, every item that your system reads is encrypted and authenticated.

use aws_db_esdk::aws_config;
use aws_db_esdk::aws_sdk_dynamodb;

use crate::common::{DDB_TABLE_NAME, encrypted_client};
use crate::migration_utils::{primary_key, sample_item, verify_returned_item};

pub async fn run(
    sdk_config: &aws_config::SdkConfig,
    partition_key: &str,
    sort_key_write: &str,
    sort_key_read: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ddb_sdk = aws_sdk_dynamodb::Client::new(sdk_config);
    // `None` takes the default plaintext override, which forbids plaintext writes and reads.
    let ddb = encrypted_client(sdk_config, ddb_sdk, None).await?;

    ddb.put_item()
        .table_name(DDB_TABLE_NAME)
        .set_item(Some(sample_item(partition_key, sort_key_write)))
        .send()
        .await?;

    // Reads encrypted items; reading a plaintext item fails on `send`.
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
            println!("step 3: read encrypted item at sort_key {sort_key_read}");
            Ok(())
        }
        None => Err("no item found".into()),
    }
}
