// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end runnable demos of the AWS KMS Hierarchical Keyring,
//! composed through the [`MaterialProviders`] client.
//!
//! Each demo lives in its own submodule and is invoked from [`main`]:
//!
//! 1. [`static_branch_key`] — single-tenant pattern with a hard-coded
//!    branch key id.
//! 2. [`branch_key_supplier`] — multi-tenant pattern using a
//!    `BranchKeySupplier` plus per-tenant keyrings to demonstrate
//!    cross-tenant isolation.
//! 3. [`cache_configurations`] — every supported `CacheType` variant:
//!    keyring-local default cache, custom-sized default cache,
//!    shared CMC across two keyrings, and a storm-tracking CMC.
//!
//! ## Running
//!
//! ```text
//! cargo run --features keystore --example aws_kms_hierarchical
//! ```
//!
//! Required environment:
//!
//! - `MPL_EXAMPLE_KEY_STORE_TABLE` — DynamoDB table backing the keystore.
//! - `MPL_EXAMPLE_LOGICAL_KEY_STORE_NAME` — logical keystore name bound
//!   into branch-key encryption contexts.
//! - `MPL_EXAMPLE_KMS_KEY_ARN` — KMS Key ARN authorizing branch-key
//!   re-encrypt/decrypt for this keystore.
//! - `MPL_EXAMPLE_BRANCH_KEY_ID` — pre-existing branch key id (must
//!   already be provisioned in the keystore).
//!
//! Optional: `MPL_EXAMPLE_REGION` (defaults to `us-west-2`),
//! `MPL_EXAMPLE_BRANCH_KEY_ID_TENANT_A`, `MPL_EXAMPLE_BRANCH_KEY_ID_TENANT_B`.
//!
//! AWS credentials are picked up via the default provider chain.

use aws_crypto_mpl::MaterialProviders;

mod branch_key_supplier;
mod cache_configurations;
mod common;
mod example_branch_key_id_supplier;
mod static_branch_key;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = common::Config::from_env()?;
    // One client builds all three demos' primitives; the client is
    // intentionally `&self`-only so it can be reused freely.
    let mpl = MaterialProviders::builder().build();

    println!("=== AWS KMS Hierarchical Keyring examples ===\n");

    static_branch_key::run(&mpl, &config).await?;
    println!();
    branch_key_supplier::run(&mpl, &config).await?;
    println!();
    cache_configurations::run(&mpl, &config).await?;

    println!("\n=== All examples completed successfully ===");
    Ok(())
}
