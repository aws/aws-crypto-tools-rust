// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Demo 1: Hierarchical Keyring with a single, statically configured
//! branch key id.
//!
//! This is the simplest composition: every encrypt and decrypt routes
//! through the same branch key. Use this pattern when a single tenant
//! (or a single trust boundary) backs all your data.

use aws_crypto_mpl::MaterialProviders;
use aws_crypto_mpl::{CacheType, DefaultCache};

use super::common::{Config, build_keystore, demo_encryption_context, round_trip};

/// Run the static-branch-key demo end-to-end.
pub async fn run(
    mpl: &MaterialProviders,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("--- demo 1: static branch key id ---");

    // Compose the keystore through the MPL client. The factory wraps the
    // existing BranchKeyStore::new and returns an Arc<BranchKeyStore>;
    // the unsized coercion to Arc<dyn Keystore> is implicit when we
    // pass it to the keyring builder.
    let keystore = build_keystore(mpl, config).await?;

    // Compose the keyring through the MPL client. Every required input
    // is set explicitly; cache and partition_id default (default cache
    // with spec capacity 1000, fresh v4 UUID partition id).
    let keyring = mpl
        .create_aws_kms_hierarchical_keyring()
        .key_store(keystore)
        .branch_key_id(config.branch_key_id.clone())
        .ttl_seconds(600)
        // Equivalent to omitting `.cache(...)`; included here to make
        // the default explicit for the reader. 1000 is the entry capacity
        // the keyring uses when no cache is configured.
        .cache(CacheType::Default(DefaultCache::new(1000)))
        .partition_id("mpl-example-static-branch-key")
        .send()?;

    // Sanity check: the keyring records the branch key id we configured, and
    // no supplier.
    assert_eq!(keyring.branch_key_id(), Some(config.branch_key_id.as_str()));
    assert!(
        keyring.branch_key_id_supplier().is_none(),
        "static-branch-key demo configured a branch key id, not a supplier"
    );

    // Encrypt-then-decrypt round trip through the keyring.
    round_trip(&keyring, demo_encryption_context(&[])).await?;

    println!("    ✓ static-branch-key round-trip succeeded");
    Ok(())
}
