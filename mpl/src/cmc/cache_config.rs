// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cache configuration for Cryptographic Materials Providers.
//!
//! [`CacheType`] is how a CMP is told which cache to use: one it builds and
//! owns, or one the caller supplies and may share. The owned variants carry the
//! parameters for the corresponding cache — [`DefaultCache`],
//! [`SingleThreadedCache`] and [`MultiThreadedCache`] for a
//! [`LocalCmc`](super::LocalCmc), [`StormTrackingCache`] for a
//! [`StormTrackingCmc`](super::StormTrackingCmc) — while
//! [`CacheType::No`] needs none.
//!
//! These types are deliberately independent of any one CMP so that a keyring
//! and a caching CMM configure a cache the same way.


use std::sync::Arc;

use crate::cmc::{Cmc, TimeUnits};
use crate::structures::MaterialsError;

/// Entry capacity a CMP uses when the caller configures no cache at all.
///
/// Not a default on [`DefaultCache`] itself: the Smithy model marks
/// `DefaultCache.entryCapacity` `@required`, and places this number on the
/// consuming CMP instead — the Hierarchical Keyring's `cache` member documents
/// "If not set, a DefaultCache is initialized ... with entryCapacity = 1000".
pub(crate) const DEFAULT_CACHE_ENTRY_CAPACITY: usize = 1000;

/// Number of least-recently-used entries a CMP-local cache scans per `get`,
/// evicting any that are TTL-expired.
///
/// Deliberately not caller-configurable. The Smithy model does not give
/// `DefaultCache` this member, and every path in the Dafny implementation uses
/// 1 — `LocalCMC`'s constructor default, `StormTracker.DefaultStorm()`, and
/// each `entryPruningTailSize.UnwrapOr(1)` at the create-cache switch. Matching
/// that keeps pruning behaviour identical across implementations.
pub(crate) const CACHE_PRUNING_TAIL_SIZE: usize = 1;

/// Configuration for a CMP-local cache that the model describes as not safe
/// for use in a multi-threaded environment. Carried by
/// [`CacheType::SingleThreaded`].
///
/// Mirrors the Smithy `SingleThreadedCache`: `entryCapacity` is required and
/// `entryPruningTailSize` is optional. In this implementation it builds the
/// same [`LocalCmc`](super::LocalCmc) as [`CacheType::MultiThreaded`]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SingleThreadedCache {
    /// Maximum number of entries the cache holds.
    pub entry_capacity: usize,
    /// Number of LRU entries scanned per get for TTL-aware pruning. Optional
    /// in the Smithy model; when `None` it resolves to 1, the value every path
    /// in the Dafny implementation uses.
    pub entry_pruning_tail_size: Option<usize>,
}

impl SingleThreadedCache {
    /// Construct a `SingleThreadedCache` with an explicit maximum entry count
    /// and no pruning tail size, which resolves to 1.
    #[must_use]
    pub const fn new(entry_capacity: usize) -> Self {
        Self {
            entry_capacity,
            entry_pruning_tail_size: None,
        }
    }
}

/// Configuration for a CMP-local cache that is safe for use in a
/// multi-threaded environment, with no extra behaviour beyond that. Carried by
/// [`CacheType::MultiThreaded`].
///
/// Mirrors the Smithy `MultiThreadedCache`: `entryCapacity` is required and
/// `entryPruningTailSize` is optional.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MultiThreadedCache {
    /// Maximum number of entries the cache holds.
    pub entry_capacity: usize,
    /// Number of LRU entries scanned per get for TTL-aware pruning. Optional
    /// in the Smithy model; when `None` it resolves to 1, the value every path
    /// in the Dafny implementation uses.
    pub entry_pruning_tail_size: Option<usize>,
}

impl MultiThreadedCache {
    /// Construct a `MultiThreadedCache` with an explicit maximum entry count
    /// and no pruning tail size, which resolves to 1.
    #[must_use]
    pub const fn new(entry_capacity: usize) -> Self {
        Self {
            entry_capacity,
            entry_pruning_tail_size: None,
        }
    }
}

/// Configuration for a CMP-local "default" Cryptographic Materials Cache
/// (a wrapped [`LocalCmc`](super::LocalCmc)). Carried by
/// [`CacheType::Default`].
///
/// Mirrors the Smithy `DefaultCache`, whose only member is a required
/// `entryCapacity`. There is deliberately no `Default` impl: the model requires
/// the capacity, and the "1000 when unset" behaviour belongs to the consuming
/// CMP's absent-cache path, not to this type. Pruning tail size is not a
/// member here for the same reason — the model does not expose it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DefaultCache {
    /// Maximum number of entries the cache holds.
    pub entry_capacity: usize,
}

impl DefaultCache {
    /// Construct a `DefaultCache` with an explicit maximum entry count.
    #[must_use]
    pub const fn new(entry_capacity: usize) -> Self {
        Self { entry_capacity }
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
    /// Number of LRU entries scanned per get for TTL-aware pruning. Optional
    /// in the Smithy model; when left unset on
    /// [`StormTrackingCacheBuilder`] it defaults to 1, the value every path
    /// in the Dafny implementation uses.
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
    /// Start a fluent builder for `StormTrackingCache`. The six required
    /// numeric fields must be supplied via the builder before
    /// [`StormTrackingCacheBuilder::build`] is called;
    /// `entry_pruning_tail_size` and `time_units` are optional.
    #[must_use]
    pub fn builder() -> StormTrackingCacheBuilder {
        StormTrackingCacheBuilder::default()
    }
}

/// Fluent builder for [`StormTrackingCache`]. The six required numeric fields
/// (`entry_capacity`, `grace_period`, `grace_interval`, `fan_out`,
/// `inflight_ttl`, `sleep_milli`) must be set;
/// [`StormTrackingCacheBuilder::build`] returns an error if any were left
/// unset. `entry_pruning_tail_size` is optional and defaults to 1, matching
/// the Smithy model, which does not mark it `@required`. `time_units` is
/// optional and defaults to seconds.
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
    /// required field if any of the six required numeric fields were left
    /// unset. `entry_pruning_tail_size` and `time_units` are optional.
    pub fn build(self) -> Result<StormTrackingCache, MaterialsError> {
        Ok(StormTrackingCache {
            entry_capacity: self.entry_capacity.ok_or_else(|| {
                MaterialsError::new("StormTrackingCacheBuilder: entry_capacity is required")
            })?,
            entry_pruning_tail_size: self
                .entry_pruning_tail_size
                .unwrap_or(CACHE_PRUNING_TAIL_SIZE),
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
    /// [`DefaultCache`], whose `entry_capacity` the model requires the caller
    /// to state. Omitting the cache entirely is what selects the CMP's own
    /// default capacity.
    Default(DefaultCache),
    /// Nothing is ever cached. Builds a [`LocalCmc`](super::LocalCmc) with an
    /// entry capacity of zero, which stores no entries at all — the same
    /// construction the Dafny implementation uses for this variant.
    ///
    /// The Smithy `NoCache` structure has no members, so this variant carries
    /// no payload rather than an empty struct the caller would have to name.
    No,
    /// A CMP-local [`LocalCmc`](super::LocalCmc) configured by the carried
    /// [`SingleThreadedCache`].
    ///
    /// The model distinguishes this from [`CacheType::MultiThreaded`] because
    /// the Dafny implementation has a cache that is not thread-safe and wraps
    /// it in a synchronizing layer for the multi-threaded case. This
    /// implementation has no such distinction to offer: `LocalCmc` keeps all
    /// shared state behind a `Mutex`, so it is already the synchronized one and
    /// both variants build it identically. The variant is modelled anyway so
    /// configuration written against the model is accepted here.
    SingleThreaded(SingleThreadedCache),
    /// A CMP-local [`LocalCmc`](super::LocalCmc) configured by the carried
    /// [`MultiThreadedCache`]. Builds the same cache as
    /// [`CacheType::SingleThreaded`] — see the note there.
    MultiThreaded(MultiThreadedCache),
    /// Use the caller-supplied [`Cmc`] impl directly. Common when one
    /// cache is shared across multiple Hierarchical Keyrings (or other
    /// CMPs).
    Shared(Arc<dyn Cmc>),
    /// Build a CMP-local [`StormTrackingCmc`](super::StormTrackingCmc) with
    /// the carried [`StormTrackingCache`] parameters. The consuming CMP
    /// validates that `grace_period < cache limit TTL`.
    StormTracking(StormTrackingCache),
}
