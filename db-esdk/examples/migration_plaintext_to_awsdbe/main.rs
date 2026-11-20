// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Migrates a plaintext DynamoDB table to the AWS Database Encryption SDK.
//!
//! Runs the four migration steps in deployment order.
//! At each step, it reads the items that the other steps wrote, to show which reads succeed and which fail:
//! - step 0, a plain DynamoDB client: writes plaintext, reads plaintext only
//! - step 1, `ForcePlaintextWriteAllowPlaintextRead`: writes plaintext, reads plaintext or encrypted
//! - step 2, `ForbidPlaintextWriteAllowPlaintextRead`: writes encrypted, reads plaintext or encrypted
//! - step 3, the default plaintext override: writes encrypted, reads encrypted only
//!
//! Each step writes its own item, under its own sort key.
//! To read another step's item, a step reads that step's sort key.
//!
//! Requires AWS credentials, the key store in `common.rs` with its branch key provisioned,
//! and a DynamoDB table with:
//! - partition key `partition_key`, type S
//! - sort key `sort_key`, type N

mod common;
mod migration_utils;
mod step_0;
mod step_1;
mod step_2;
mod step_3;

use std::future::Future;

use aws_db_esdk::aws_config;

// One partition key for the whole run; one sort key per step's item.
const PARTITION_KEY: &str = "migration-plaintext-to-awsdbe";
const STEP_0_KEY: &str = "0";
const STEP_1_KEY: &str = "1";
const STEP_2_KEY: &str = "2";
const STEP_3_KEY: &str = "3";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Clients take their region and credentials from the default AWS config chain.
    let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // `Box::pin` puts each step's future on the heap, so `main` holds only a pointer to it.
    // Unboxed, the futures overflow the 1 MiB main thread stack on Windows in a debug build.

    // Step 0: the plaintext starting state, which writes and reads its own item.
    Box::pin(step_0::run(&cfg, PARTITION_KEY, STEP_0_KEY, STEP_0_KEY)).await?;

    // Step 1 deployed: still plaintext, but readers are ready for encryption.
    Box::pin(step_1::run(&cfg, PARTITION_KEY, STEP_1_KEY, STEP_1_KEY)).await?;
    // Step 1 reads step 0's plaintext item; the old step 0 reader reads step 1's.
    Box::pin(step_1::run(&cfg, PARTITION_KEY, STEP_1_KEY, STEP_0_KEY)).await?;
    Box::pin(step_0::run(&cfg, PARTITION_KEY, STEP_0_KEY, STEP_1_KEY)).await?;

    // Step 2 deployed: new writes are encrypted; both kinds are still readable.
    Box::pin(step_2::run(&cfg, PARTITION_KEY, STEP_2_KEY, STEP_2_KEY)).await?;
    // Step 2 reads the earlier plaintext items.
    Box::pin(step_2::run(&cfg, PARTITION_KEY, STEP_2_KEY, STEP_0_KEY)).await?;
    Box::pin(step_2::run(&cfg, PARTITION_KEY, STEP_2_KEY, STEP_1_KEY)).await?;
    // The step 1 reader decrypts step 2's encrypted item.
    Box::pin(step_1::run(&cfg, PARTITION_KEY, STEP_1_KEY, STEP_2_KEY)).await?;
    // The plaintext step 0 reader cannot read step 2's encrypted item.
    expect_err(
        "step 0 reading an encrypted item",
        Box::pin(step_0::run(&cfg, PARTITION_KEY, STEP_0_KEY, STEP_2_KEY)),
    )
    .await?;

    // In a real migration, re-encrypt every remaining plaintext item here, before deploying step 3.

    // Step 3 deployed: every write is encrypted, and plaintext reads fail.
    Box::pin(step_3::run(&cfg, PARTITION_KEY, STEP_3_KEY, STEP_3_KEY)).await?;
    // Step 2 reads step 3's encrypted item, and step 3 reads step 2's.
    Box::pin(step_2::run(&cfg, PARTITION_KEY, STEP_2_KEY, STEP_3_KEY)).await?;
    Box::pin(step_3::run(&cfg, PARTITION_KEY, STEP_3_KEY, STEP_2_KEY)).await?;
    // The step 1 reader still decrypts step 3's encrypted item.
    Box::pin(step_1::run(&cfg, PARTITION_KEY, STEP_1_KEY, STEP_3_KEY)).await?;
    // Step 3 refuses the items from steps 0 and 1, which are still plaintext.
    expect_err(
        "step 3 reading a plaintext item written by step 0",
        Box::pin(step_3::run(&cfg, PARTITION_KEY, STEP_3_KEY, STEP_0_KEY)),
    )
    .await?;
    expect_err(
        "step 3 reading a plaintext item written by step 1",
        Box::pin(step_3::run(&cfg, PARTITION_KEY, STEP_3_KEY, STEP_1_KEY)),
    )
    .await?;

    println!("Success! Walked every migration step and its cross-step reads.");
    Ok(())
}

/// Runs a step that must fail, and returns `Ok` if it does.
///
/// A plaintext reader must fail on an encrypted item.
/// A reader that forbids plaintext must fail on a plaintext item.
/// So if the step succeeds, `expect_err` returns an error.
async fn expect_err(
    label: &str,
    step: impl Future<Output = Result<(), Box<dyn std::error::Error>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    match step.await {
        Ok(()) => Err(format!("{label}: expected a failure, but the read succeeded").into()),
        Err(e) => {
            println!("{label}: correctly refused ({e})");
            Ok(())
        }
    }
}
