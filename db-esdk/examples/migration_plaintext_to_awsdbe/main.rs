// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Plaintext DynamoDB table -> AWS Database Encryption SDK migration.
//!
//! Walks the four migration steps in deployment order and, at each step,
//! reads items the other steps wrote — showing exactly which reads succeed
//! and which are refused as the dataset moves from plaintext to encrypted:
//!
//!   Step 0  plain client          write plaintext, read plaintext only
//!   Step 1  ForcePlaintextWrite…  write plaintext, read plaintext or encrypted
//!   Step 2  ForbidPlaintextWrite… write encrypted, read plaintext or encrypted
//!   Step 3  (default)             write encrypted, read encrypted only
//!
//! Each step writes its own item at its own sort key and reads one item back,
//! so a step reads another step's item by reading that step's sort key.
//!
//! Requires AWS credentials, the key store in `common.rs` with its branch key
//! provisioned, and a DynamoDB table with partition key `partition_key` (S)
//! and sort key `sort_key` (N).

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

    // Each step is boxed so this function keeps one pointer per step, not a
    // copy of each step's state; unboxed, a debug build overflows the 1 MiB
    // Windows main-thread stack.

    // Step 0: the plaintext starting state — write and read our own item.
    Box::pin(step_0::run(&cfg, PARTITION_KEY, STEP_0_KEY, STEP_0_KEY)).await?;

    // Step 1 deployed: still plaintext, but readers are ready for encryption.
    Box::pin(step_1::run(&cfg, PARTITION_KEY, STEP_1_KEY, STEP_1_KEY)).await?;
    // Step 1 reads Step 0's plaintext item; the old Step 0 reader reads Step 1's.
    Box::pin(step_1::run(&cfg, PARTITION_KEY, STEP_1_KEY, STEP_0_KEY)).await?;
    Box::pin(step_0::run(&cfg, PARTITION_KEY, STEP_0_KEY, STEP_1_KEY)).await?;

    // Step 2 deployed: new writes are encrypted; both kinds are still readable.
    Box::pin(step_2::run(&cfg, PARTITION_KEY, STEP_2_KEY, STEP_2_KEY)).await?;
    // Step 2 reads the earlier plaintext items.
    Box::pin(step_2::run(&cfg, PARTITION_KEY, STEP_2_KEY, STEP_0_KEY)).await?;
    Box::pin(step_2::run(&cfg, PARTITION_KEY, STEP_2_KEY, STEP_1_KEY)).await?;
    // The Step 1 reader decrypts Step 2's encrypted item.
    Box::pin(step_1::run(&cfg, PARTITION_KEY, STEP_1_KEY, STEP_2_KEY)).await?;
    // The plaintext Step 0 reader cannot read Step 2's encrypted item.
    expect_err(
        "step 0 reading an encrypted item",
        Box::pin(step_0::run(&cfg, PARTITION_KEY, STEP_0_KEY, STEP_2_KEY)),
    )
    .await?;

    // (Operator back-fills here: re-encrypt every remaining plaintext item.)

    // Step 3 deployed: fully encrypted, plaintext reads are refused.
    Box::pin(step_3::run(&cfg, PARTITION_KEY, STEP_3_KEY, STEP_3_KEY)).await?;
    // Step 2 and Step 3 readers both read Step 3's / Step 2's encrypted items.
    Box::pin(step_2::run(&cfg, PARTITION_KEY, STEP_2_KEY, STEP_3_KEY)).await?;
    Box::pin(step_3::run(&cfg, PARTITION_KEY, STEP_3_KEY, STEP_2_KEY)).await?;
    // The Step 1 reader still decrypts Step 3's encrypted item.
    Box::pin(step_1::run(&cfg, PARTITION_KEY, STEP_1_KEY, STEP_3_KEY)).await?;
    // Step 3 refuses the still-plaintext items from Steps 0 and 1.
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

/// Run a step we expect to fail, and turn that failure into success.
///
/// Reading an encrypted item with a plaintext reader, or a plaintext item with
/// a plaintext-forbidding reader, is supposed to fail — so a success here is
/// the error.
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
