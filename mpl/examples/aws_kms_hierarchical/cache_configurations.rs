// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Demo 3: Hierarchical Keyring with each supported cache configuration.
//!
//! Walks through the four ways to wire a Cryptographic Materials Cache
//! into a `HierarchicalKeyring`:
//!
//! 1. `CacheType::Default(DefaultCache::new(1000))` — the spec-default
//!    1000-entry keyring-local LRU cache.
//! 2. `CacheType::Default(DefaultCache::new(50))`
//!    — a custom-sized keyring-local cache.
//! 3. `CacheType::Shared(...)` — a single CMC built once via
//!    `mpl.create_cryptographic_materials_cache()` and reused across
//!    multiple keyrings.
//! 4. `CacheType::StormTracking(...)` — a StormTrackingCmc for
//!    high-fan-out workloads where a thundering herd of misses against
//!    the same key would otherwise overload KMS / DDB.

use std::sync::Arc;

use aws_crypto_mpl::MaterialProviders;
use aws_crypto_mpl::{CacheType, DefaultCache, StormTrackingCache};

use super::common::{Config, build_keystore, demo_encryption_context, round_trip};

/// Run the cache-configurations demo end-to-end.
pub async fn run(
    mpl: &MaterialProviders,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("--- demo 3: cache configurations ---");

    let keystore = build_keystore(mpl, config).await?;

    // 1. Default cache (spec defaults: 1000-entry capacity, 64-entry pruning tail).
    {
        let keyring = mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(Arc::clone(&keystore))
            .branch_key_id(config.branch_key_id.clone())
            .ttl_seconds(600)
            .cache(CacheType::Default(DefaultCache::new(1000)))
            .partition_id("mpl-example-cache-default")
            .send()?;
        round_trip(&keyring, demo_encryption_context(&[("cache", "default")])).await?;
        println!("    ✓ default cache (1000 entries) — round-trip succeeded");
    }

    // 2. Default cache with a custom capacity. Useful when memory is tight
    //    or the working set is known to be small (single tenant, single
    //    branch key per keyring).
    {
        // `DefaultCache` carries only `entry_capacity`; the pruning tail size
        // is an internal constant, not a customer-set knob.
        let custom_default = DefaultCache::new(50);
        let keyring = mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(Arc::clone(&keystore))
            .branch_key_id(config.branch_key_id.clone())
            .ttl_seconds(600)
            .cache(CacheType::Default(custom_default))
            .partition_id("mpl-example-cache-default-custom")
            .send()?;
        round_trip(
            &keyring,
            demo_encryption_context(&[("cache", "default-custom")]),
        )
        .await?;
        println!("    ✓ default cache (50 entries) — round-trip succeeded");
    }

    // 3. Shared cache built once via the MPL client, reused across two
    //    keyrings. Both keyrings use the SAME partition id and the
    //    SAME branch key id, so the cache entry written by keyring A
    //    is hit by keyring B (and vice versa).
    {
        // The factory consumes a CacheType describing how to build the
        // cache, then returns an Arc<dyn Cmc> the caller can plumb into
        // multiple keyrings via CacheType::Shared.
        let shared_cmc = mpl
            .create_cryptographic_materials_cache()
            .cache(CacheType::Default(DefaultCache::new(200)))
            .send()?;

        let keyring_a = mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(Arc::clone(&keystore))
            .branch_key_id(config.branch_key_id.clone())
            .ttl_seconds(600)
            .cache(CacheType::Shared(Arc::clone(&shared_cmc)))
            .partition_id("mpl-example-cache-shared")
            .send()?;
        let keyring_b = mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(Arc::clone(&keystore))
            .branch_key_id(config.branch_key_id.clone())
            .ttl_seconds(600)
            .cache(CacheType::Shared(shared_cmc))
            .partition_id("mpl-example-cache-shared")
            .send()?;

        round_trip(
            &keyring_a,
            demo_encryption_context(&[("cache", "shared-a")]),
        )
        .await?;
        // The second round-trip on keyring_b SHOULD hit the cache entry
        // populated by keyring_a (same partition_id + logical keystore
        // name + branch key id). We don't have an observable counter
        // here, but the absence of a fresh keystore call is the contract.
        round_trip(
            &keyring_b,
            demo_encryption_context(&[("cache", "shared-b")]),
        )
        .await?;
        println!(
            "    ✓ shared cache (200 entries) — two keyrings sharing one CMC, round-trips succeeded"
        );
    }

    // 4. Storm-tracking cache. The keyring validates that
    //    `grace_period < ttl_seconds`; with ttl=600 we use a grace
    //    period of 30 seconds. The other knobs are illustrative and
    //    not workload-tuned — pick values that match your concurrency
    //    profile in production.
    {
        let storm = StormTrackingCache::builder()
            .entry_capacity(200)
            .entry_pruning_tail_size(16)
            .grace_period(30)
            .grace_interval(5)
            .fan_out(8)
            .inflight_ttl(15)
            .sleep_milli(20)
            .build()?;
        let keyring = mpl
            .create_aws_kms_hierarchical_keyring()
            .key_store(keystore)
            .branch_key_id(config.branch_key_id.clone())
            .ttl_seconds(600)
            .cache(CacheType::StormTracking(storm))
            .partition_id("mpl-example-cache-storm-tracking")
            .send()?;
        round_trip(&keyring, demo_encryption_context(&[("cache", "storm")])).await?;
        println!("    ✓ storm-tracking cache — round-trip succeeded");
    }

    Ok(())
}
