// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The cryptographic materials caches.

use super::*;
#[cfg(feature = "rt-tokio")]
use aws_crypto_mpl::cmc::{DefaultCmc, StormTrackingCmc, StormTrackingCmcBuilder};
use aws_crypto_mpl::cmc::{LocalCmc, SharedCmc};
#[cfg(feature = "rt-tokio")]
use std::time::Duration;

// Only the hierarchical keyring reads a cache.
#[cfg_attr(not(all(feature = "kms", feature = "ddb")), allow(dead_code))]
pub(super) struct CryptographicMaterialsCache {
    pub(super) inner: SharedCmc,
}

pub(super) fn cache_count(field: &str, v: u32, op: &str) -> Result<usize, String> {
    i32::try_from(v)
        .ok()
        .and_then(|bounded| usize::try_from(bounded).ok())
        .ok_or_else(|| {
            shim_err(
                ffi::ShimErrorKind::Validation,
                op,
                format!("{field} {v} exceeds the bridge's supported maximum"),
            )
        })
}

/// Apply each set option to `builder`.
#[cfg(feature = "rt-tokio")]
pub(super) fn apply_storm_tracking_options(
    builder: StormTrackingCmcBuilder,
    options: &ffi::StormTrackingCmcOptions,
) -> Result<StormTrackingCmcBuilder, String> {
    let op = "create_storm_tracking_cmc";
    let count = |field: &str, v: Option<u32>| -> Result<Option<usize>, String> {
        v.map(|v| cache_count(field, v, op)).transpose()
    };
    let duration = |field: &str, d: Option<ffi::Duration>| -> Result<Option<Duration>, String> {
        d.map(|d| from_ffi_duration(d, field, op)).transpose()
    };
    Ok(builder
        .set_entry_capacity(count("entry_capacity", options.entry_capacity.to_option())?)
        .set_entry_pruning_tail_size(count(
            "entry_pruning_tail_size",
            options.entry_pruning_tail_size.to_option(),
        )?)
        .set_grace_period(duration("grace_period", options.grace_period.to_option())?)
        .set_grace_interval(duration(
            "grace_interval",
            options.grace_interval.to_option(),
        )?)
        .set_fan_out(count("fan_out", options.fan_out.to_option())?)
        .set_in_flight_ttl(duration(
            "in_flight_ttl",
            options.in_flight_ttl.to_option(),
        )?)
        .set_sleep(duration("sleep", options.sleep.to_option())?))
}

//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//= reason=Each cache kind has its own create_* function, so the target selects a kind by calling that kind's function.
//# - The shim MUST provide an operation that creates a cryptographic materials
//# cache of a target-selected kind, backed by the core ESDK.
//
//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//= type=implication
//= reason=The cache kinds are the create_* functions the bridge exports, so a kind the bridge does not export cannot be requested.
//# - The shim MUST return an error when the target cache kind is not a supported
//# value.
//
//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//= type=exception
//= reason=Will be added in the future
//# - The shim MUST support creating a cache that performs no caching.
//
//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//# - The shim MUST support creating a storm tracking cache.
#[cfg(feature = "rt-tokio")]
pub(super) fn create_storm_tracking_cmc(
    options: &ffi::StormTrackingCmcOptions,
) -> Result<Box<CryptographicMaterialsCache>, String> {
    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //# - Creating a cryptographic materials cache MUST provide the target-supplied
    //# cache type, with its values, to the core ESDK.
    let cache = apply_storm_tracking_options(StormTrackingCmc::builder(), options)?
        .build()
        .map_err(core_err)?;
    Ok(Box::new(CryptographicMaterialsCache {
        inner: SharedCmc::new(cache),
    }))
}

//= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
//# - The shim MUST support creating a default cache.
#[cfg(feature = "rt-tokio")]
pub(super) fn create_default_cmc(
    entry_capacity: u32,
) -> Result<Box<CryptographicMaterialsCache>, String> {
    let op = "create_default_cmc";
    let cache = DefaultCmc::builder()
        .entry_capacity(cache_count("entry_capacity", entry_capacity, op)?)
        .build()
        .map_err(core_err)?;
    Ok(Box::new(CryptographicMaterialsCache {
        inner: SharedCmc::new(cache),
    }))
}

pub(super) fn create_local_cmc(
    entry_capacity: u32,
) -> Result<Box<CryptographicMaterialsCache>, String> {
    let op = "create_local_cmc";
    let cache = LocalCmc::builder()
        .entry_capacity(cache_count("entry_capacity", entry_capacity, op)?)
        .build()
        .map_err(core_err)?;
    Ok(Box::new(CryptographicMaterialsCache {
        inner: SharedCmc::new(cache),
    }))
}
