// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cache configuration for Cryptographic Materials Providers.
//!
//! [`CacheType`] is how a CMP is told which cache to use: one it builds and
//! owns, or one the caller supplies and may share. The two owned variants
//! carry the parameters for the corresponding cache — [`DefaultCache`] for a
//! [`LocalCmc`](super::LocalCmc), [`StormTrackingCache`] for a
//! [`StormTrackingCmc`](super::StormTrackingCmc).
//!
//! These types are deliberately independent of any one CMP so that a keyring
//! and a caching CMM configure a cache the same way.

use std::sync::Arc;

use crate::cmc::{Cmc, TimeUnits};
use crate::structures::MaterialsError;

/// Default entry capacity for a CMP-local cache.
const DEFAULT_CACHE_ENTRY_CAPACITY: usize = 1000;

/// Default entry-pruning tail size for a CMP-local cache. 64 strikes a
/// reasonable balance between pruning amortization and per-`get` work.
const DEFAULT_CACHE_PRUNING_TAIL_SIZE: usize = 64;

/// Configuration for a CMP-local "default" Cryptographic Materials Cache
/// (a wrapped [`LocalCmc`](super::LocalCmc)). Carried by
/// [`CacheType::Default`].
///
/// Use [`DefaultCache::default()`] to get the default entry capacity (1000)
/// and a sensible pruning tail size; use [`DefaultCache::builder`] to
/// customize either field.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DefaultCache {
    /// Maximum number of entries the cache holds. Defaults to 1000 when
    /// none is provided.
    pub entry_capacity: usize,
    /// Number of LRU entries scanned per get for TTL-aware pruning.
    /// Defaults to 64, balancing pruning amortization against per-`get`
    /// work.
    pub entry_pruning_tail_size: usize,
}

impl Default for DefaultCache {
    fn default() -> Self {
        Self {
            entry_capacity: DEFAULT_CACHE_ENTRY_CAPACITY,
            entry_pruning_tail_size: DEFAULT_CACHE_PRUNING_TAIL_SIZE,
        }
    }
}

impl DefaultCache {
    /// Construct a `DefaultCache` with explicit capacity and pruning tail size.
    #[must_use]
    pub const fn new(entry_capacity: usize, entry_pruning_tail_size: usize) -> Self {
        Self {
            entry_capacity,
            entry_pruning_tail_size,
        }
    }

    /// Start a fluent builder for `DefaultCache`. Unset fields fall back to
    /// the defaults (entry_capacity = 1000, entry_pruning_tail_size = 64).
    #[must_use]
    pub fn builder() -> DefaultCacheBuilder {
        DefaultCacheBuilder::default()
    }
}

/// Fluent builder for [`DefaultCache`]. Call [`Self::build`] to produce the
/// configured `DefaultCache`; unset fields fall back to the defaults.
#[derive(Debug, Clone, Default)]
pub struct DefaultCacheBuilder {
    entry_capacity: Option<usize>,
    entry_pruning_tail_size: Option<usize>,
}

impl DefaultCacheBuilder {
    /// Override the maximum number of entries held by the cache.
    #[must_use]
    pub const fn entry_capacity(mut self, n: usize) -> Self {
        self.entry_capacity = Some(n);
        self
    }

    /// Override the number of LRU entries scanned per `get` for pruning.
    #[must_use]
    pub const fn entry_pruning_tail_size(mut self, n: usize) -> Self {
        self.entry_pruning_tail_size = Some(n);
        self
    }

    /// Finalize the builder into a [`DefaultCache`].
    #[must_use]
    pub fn build(self) -> DefaultCache {
        DefaultCache {
            entry_capacity: self.entry_capacity.unwrap_or(DEFAULT_CACHE_ENTRY_CAPACITY),
            entry_pruning_tail_size: self
                .entry_pruning_tail_size
                .unwrap_or(DEFAULT_CACHE_PRUNING_TAIL_SIZE),
        }
    }
}

/// Configuration for a CMP-local Storm-tracking Cryptographic Materials
/// Cache. Carried by [`CacheType::StormTracking`].
///
/// Mirrors the parameter set accepted by
/// [`StormTrackingCmc::new`](super::StormTrackingCmc::new); bundled into a
/// struct so the [`CacheType::StormTracking`] variant stays ergonomic. Use
/// [`StormTrackingCache::builder`] for a fluent constructor, or set the
/// fields directly.
#[derive(Debug, Clone)]
pub struct StormTrackingCache {
    /// Maximum number of entries the underlying
    /// [`LocalCmc`](super::LocalCmc) holds.
    pub entry_capacity: usize,
    /// Number of LRU entries scanned per get for TTL-aware pruning.
    pub entry_pruning_tail_size: usize,
    /// Window during which a soon-to-expire entry is still served.
    pub grace_period: u64,
    /// Window during which a recent NoSuchEntry is treated as inflight.
    pub grace_interval: u64,
    /// Maximum concurrent in-flight refresh fan-out.
    pub fan_out: usize,
    /// Maximum time an inflight entry may remain inflight before failing.
    pub inflight_ttl: u64,
    /// Sleep granularity (always milliseconds).
    pub sleep_milli: u64,
    /// Time unit for the duration parameters above. Defaults to seconds.
    pub time_units: Option<TimeUnits>,
}

impl StormTrackingCache {
    /// Start a fluent builder for `StormTrackingCache`. All numeric fields
    /// must be supplied via the builder before [`StormTrackingCacheBuilder::build`]
    /// is called; `time_units` is optional and defaults to seconds.
    #[must_use]
    pub fn builder() -> StormTrackingCacheBuilder {
        StormTrackingCacheBuilder::default()
    }
}

/// Fluent builder for [`StormTrackingCache`]. All seven numeric fields
/// (`entry_capacity`, `entry_pruning_tail_size`, `grace_period`,
/// `grace_interval`, `fan_out`, `inflight_ttl`, `sleep_milli`) are
/// required; [`StormTrackingCacheBuilder::build`] returns an error if any
/// were left unset. `time_units` is optional.
#[derive(Debug, Clone, Default)]
pub struct StormTrackingCacheBuilder {
    entry_capacity: Option<usize>,
    entry_pruning_tail_size: Option<usize>,
    grace_period: Option<u64>,
    grace_interval: Option<u64>,
    fan_out: Option<usize>,
    inflight_ttl: Option<u64>,
    sleep_milli: Option<u64>,
    time_units: Option<TimeUnits>,
}

impl StormTrackingCacheBuilder {
    /// Set `entry_capacity`. See [`StormTrackingCache::entry_capacity`].
    #[must_use]
    pub const fn entry_capacity(mut self, n: usize) -> Self {
        self.entry_capacity = Some(n);
        self
    }

    /// Set `entry_pruning_tail_size`.
    #[must_use]
    pub const fn entry_pruning_tail_size(mut self, n: usize) -> Self {
        self.entry_pruning_tail_size = Some(n);
        self
    }

    /// Set `grace_period`.
    #[must_use]
    pub const fn grace_period(mut self, n: u64) -> Self {
        self.grace_period = Some(n);
        self
    }

    /// Set `grace_interval`.
    #[must_use]
    pub const fn grace_interval(mut self, n: u64) -> Self {
        self.grace_interval = Some(n);
        self
    }

    /// Set `fan_out`.
    #[must_use]
    pub const fn fan_out(mut self, n: usize) -> Self {
        self.fan_out = Some(n);
        self
    }

    /// Set `inflight_ttl`.
    #[must_use]
    pub const fn inflight_ttl(mut self, n: u64) -> Self {
        self.inflight_ttl = Some(n);
        self
    }

    /// Set `sleep_milli`.
    #[must_use]
    pub const fn sleep_milli(mut self, n: u64) -> Self {
        self.sleep_milli = Some(n);
        self
    }

    /// Set `time_units` (defaults to seconds when unset).
    #[must_use]
    pub const fn time_units(mut self, u: TimeUnits) -> Self {
        self.time_units = Some(u);
        self
    }

    /// Finalize the builder. Returns an error naming the first missing
    /// required field if any of the seven numeric fields were left unset.
    pub fn build(self) -> Result<StormTrackingCache, MaterialsError> {
        Ok(StormTrackingCache {
            entry_capacity: self.entry_capacity.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: entry_capacity is required")
            })?,
            entry_pruning_tail_size: self.entry_pruning_tail_size.ok_or_else(|| {
                MaterialsError::new(
                    "StormTrackingCacheBuilder: entry_pruning_tail_size is required",
                )
            })?,
            grace_period: self.grace_period.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: grace_period is required")
            })?,
            grace_interval: self.grace_interval.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: grace_interval is required")
            })?,
            fan_out: self.fan_out.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: fan_out is required")
            })?,
            inflight_ttl: self.inflight_ttl.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: inflight_ttl is required")
            })?,
            sleep_milli: self.sleep_milli.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: sleep_milli is required")
            })?,
            time_units: self.time_units,
        })
    }
}

/// Cache configuration for a Cryptographic Materials Provider.
///
/// The three variants are a CMP-local default cache, an externally-supplied
/// `Shared` cache that may be reused across multiple Hierarchical Keyrings or
/// Cryptographic Material Providers, and a CMP-local Storm-tracking cache for
/// high-fan-out workloads.
#[non_exhaustive]
pub enum CacheType {
    /// A CMP-local [`LocalCmc`](super::LocalCmc) configured by the carried
    /// [`DefaultCache`]. Use [`DefaultCache::default()`] for a max cache
    /// size of 1000.
    Default(DefaultCache),
    /// Use the caller-supplied [`Cmc`] impl directly. Common when one
    /// cache is shared across multiple Hierarchical Keyrings (or other
    /// CMPs).
    Shared(Arc<dyn Cmc>),
    /// Build a CMP-local [`StormTrackingCmc`](super::StormTrackingCmc) with
    /// the carried [`StormTrackingCache`] parameters. The consuming CMP
    /// validates that `grace_period < cache limit TTL`.
    StormTracking(StormTrackingCache),
}
