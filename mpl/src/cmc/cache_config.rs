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

// TODO: finish conforming this module to the Smithy `CacheType` union, which
// has six variants: Default, No, SingleThreaded, MultiThreaded, StormTracking
// and Shared. `No`, `SingleThreaded` and `MultiThreaded` are not modelled here
// yet. Also unaddressed: the model's `Default` variant builds a
// storm-tracking cache (StormTracker.DefaultStorm) rather than the plain
// LocalCmc built here. Follow-up PR.

use std::time::Duration;

use crate::cmc::{LocalCmc, SharedCmc, StormTrackingCmc};
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

/// Default [`StormTrackingCache::grace_period`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_GRACE_PERIOD: Duration = Duration::from_secs(10);
/// Default [`StormTrackingCache::grace_interval`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_GRACE_INTERVAL: Duration = Duration::from_secs(1);
/// Default [`StormTrackingCache::fan_out`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_FAN_OUT: usize = 20;
/// Default [`StormTrackingCache::inflight_ttl`], from Dafny's
/// `StormTracker.DefaultStorm()`.
///
/// The spec lists 20, which exceeds the default grace period
/// and so breaks the spec's own "Inflight TTL MUST be less than or equal to the Grace Period" rule.
pub const DEFAULT_STORM_INFLIGHT_TTL: Duration = Duration::from_secs(10);
/// Default [`StormTrackingCache::sleep`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_SLEEP: Duration = Duration::from_millis(20);

/// Configuration for a CMP-local Storm-tracking Cryptographic Materials
/// Cache. Carried by [`CacheType::StormTracking`].
///
/// Construct with [`StormTrackingCache::builder`].
/// The builder defaults every unset value and rejects inconsistent settings,
/// so every `StormTrackingCache` is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StormTrackingCache {
    entry_capacity: usize,
    entry_pruning_tail_size: usize,
    grace_period: Duration,
    grace_interval: Duration,
    fan_out: usize,
    inflight_ttl: Duration,
    sleep: Duration,
}

impl StormTrackingCache {
    /// Start a builder for `StormTrackingCache`. Every setter is optional.
    #[must_use]
    pub fn builder() -> StormTrackingCacheBuilder {
        StormTrackingCacheBuilder::default()
    }

    /// Maximum number of entries the underlying [`LocalCmc`] holds.
    #[must_use]
    pub const fn entry_capacity(&self) -> usize {
        self.entry_capacity
    }

    /// Number of least-recently-used entries each get checks for expired
    /// entries to evict.
    #[must_use]
    pub const fn entry_pruning_tail_size(&self) -> usize {
        self.entry_pruning_tail_size
    }

    /// Window before expiry during which the cache attempts a refresh.
    #[must_use]
    pub const fn grace_period(&self) -> Duration {
        self.grace_period
    }

    /// Time after which an inflight refresh is no longer considered
    /// inflight.
    #[must_use]
    pub const fn grace_interval(&self) -> Duration {
        self.grace_interval
    }

    /// Maximum number of keys that can have a refresh inflight at once.
    #[must_use]
    pub const fn fan_out(&self) -> usize {
        self.fan_out
    }

    /// Time a waiting request may stay inflight before it fails.
    #[must_use]
    pub const fn inflight_ttl(&self) -> Duration {
        self.inflight_ttl
    }

    /// Time a blocked request sleeps before reexamining the cache.
    #[must_use]
    pub const fn sleep(&self) -> Duration {
        self.sleep
    }
}

/// Builder for [`StormTrackingCache`].
/// Every setter is optional;
/// [`build`](Self::build) applies the default documented on each setter to any value left unset.
#[derive(Debug, Clone, Default)]
pub struct StormTrackingCacheBuilder {
    entry_capacity: Option<usize>,
    entry_pruning_tail_size: Option<usize>,
    grace_period: Option<Duration>,
    grace_interval: Option<Duration>,
    fan_out: Option<usize>,
    inflight_ttl: Option<Duration>,
    sleep: Option<Duration>,
}

impl StormTrackingCacheBuilder {
    /// Set the maximum number of entries. Defaults to 1000.
    #[must_use]
    pub const fn entry_capacity(mut self, n: usize) -> Self {
        self.entry_capacity = Some(n);
        self
    }

    /// Set the number of least-recently-used entries each get checks for
    /// expired entries to evict. Defaults to 1.
    #[must_use]
    pub const fn entry_pruning_tail_size(mut self, n: usize) -> Self {
        self.entry_pruning_tail_size = Some(n);
        self
    }

    /// Set the grace period. Defaults to 10 seconds.
    #[must_use]
    pub const fn grace_period(mut self, d: Duration) -> Self {
        self.grace_period = Some(d);
        self
    }

    /// Set the grace interval. Defaults to 1 second.
    #[must_use]
    pub const fn grace_interval(mut self, d: Duration) -> Self {
        self.grace_interval = Some(d);
        self
    }

    /// Set the fan-out. Defaults to 20. Must be at least 1.
    #[must_use]
    pub const fn fan_out(mut self, n: usize) -> Self {
        self.fan_out = Some(n);
        self
    }

    /// Set the inflight TTL. Defaults to 10 seconds.
    #[must_use]
    pub const fn inflight_ttl(mut self, d: Duration) -> Self {
        self.inflight_ttl = Some(d);
        self
    }

    /// Set how long a blocked request sleeps before reexamining the cache.
    /// Defaults to 20 milliseconds.
    #[must_use]
    pub const fn sleep(mut self, d: Duration) -> Self {
        self.sleep = Some(d);
        self
    }

    /// Set or clear `entry_capacity`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`entry_capacity`](Self::entry_capacity).
    #[must_use]
    pub const fn set_entry_capacity(mut self, v: Option<usize>) -> Self {
        self.entry_capacity = v;
        self
    }

    /// Set or clear `entry_pruning_tail_size`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`entry_pruning_tail_size`](Self::entry_pruning_tail_size).
    #[must_use]
    pub const fn set_entry_pruning_tail_size(mut self, v: Option<usize>) -> Self {
        self.entry_pruning_tail_size = v;
        self
    }

    /// Set or clear `grace_period`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`grace_period`](Self::grace_period).
    #[must_use]
    pub const fn set_grace_period(mut self, v: Option<Duration>) -> Self {
        self.grace_period = v;
        self
    }

    /// Set or clear `grace_interval`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`grace_interval`](Self::grace_interval).
    #[must_use]
    pub const fn set_grace_interval(mut self, v: Option<Duration>) -> Self {
        self.grace_interval = v;
        self
    }

    /// Set or clear `fan_out`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`fan_out`](Self::fan_out).
    #[must_use]
    pub const fn set_fan_out(mut self, v: Option<usize>) -> Self {
        self.fan_out = v;
        self
    }

    /// Set or clear `inflight_ttl`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`inflight_ttl`](Self::inflight_ttl).
    #[must_use]
    pub const fn set_inflight_ttl(mut self, v: Option<Duration>) -> Self {
        self.inflight_ttl = v;
        self
    }

    /// Set or clear `sleep`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`sleep`](Self::sleep).
    #[must_use]
    pub const fn set_sleep(mut self, v: Option<Duration>) -> Self {
        self.sleep = v;
        self
    }

    /// Apply defaults and validate the settings.
    ///
    /// # Errors
    ///
    /// Returns a [`MaterialsErrorKind::Validation`](crate::structures::MaterialsErrorKind::Validation) error if:
    /// - `fan_out`, `inflight_ttl`, or `sleep` is 0, or
    /// - `grace_interval` exceeds `inflight_ttl`.
    pub fn build(self) -> Result<StormTrackingCache, MaterialsError> {
        let config = StormTrackingCache {
            entry_capacity: self.entry_capacity.unwrap_or(DEFAULT_CACHE_ENTRY_CAPACITY),
            entry_pruning_tail_size: self
                .entry_pruning_tail_size
                .unwrap_or(CACHE_PRUNING_TAIL_SIZE),
            grace_period: self.grace_period.unwrap_or(DEFAULT_STORM_GRACE_PERIOD),
            grace_interval: self.grace_interval.unwrap_or(DEFAULT_STORM_GRACE_INTERVAL),
            fan_out: self.fan_out.unwrap_or(DEFAULT_STORM_FAN_OUT),
            inflight_ttl: self.inflight_ttl.unwrap_or(DEFAULT_STORM_INFLIGHT_TTL),
            sleep: self.sleep.unwrap_or(DEFAULT_STORM_SLEEP),
        };

        if config.fan_out == 0 {
            return Err(invalid("fan_out must be at least 1"));
        }
        if config.inflight_ttl.is_zero() {
            return Err(invalid("inflight_ttl must be greater than zero"));
        }
        if config.sleep.is_zero() {
            return Err(invalid("sleep must be greater than zero"));
        }
        if config.grace_interval > config.inflight_ttl {
            return Err(invalid(format!(
                "grace_interval ({:?}) must be less than or equal to inflight_ttl ({:?})",
                config.grace_interval, config.inflight_ttl
            )));
        }

        Ok(config)
    }
}

fn invalid(message: impl Into<String>) -> MaterialsError {
    MaterialsError::new(format!("StormTrackingCache: {}", message.into()))
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
    /// Use the cache the caller passed in.
    /// Common when one cache is shared across multiple Hierarchical Keyrings (or other CMPs).
    Shared(SharedCmc),
    /// Build a CMP-local [`StormTrackingCmc`](super::StormTrackingCmc) with
    /// the carried [`StormTrackingCache`] parameters. The consuming CMP
    /// validates that `grace_period < cache limit TTL`.
    StormTracking(StormTrackingCache),
}

/// Helper function that turns [`CacheType`] into a concrete cache.
///
/// # Errors
///
/// Returns an error if the underlying cache rejects the supplied parameters.
pub fn create_cryptographic_materials_cache(
    cache_type: CacheType,
) -> Result<SharedCmc, MaterialsError> {
    match cache_type {
        CacheType::Default(default_cache) => {
            let local = LocalCmc::new(default_cache.entry_capacity, CACHE_PRUNING_TAIL_SIZE)
                .map_err(|e| {
                    MaterialsError::new(format!("failed to initialize default LocalCmc: {e}"))
                })?;
            Ok(SharedCmc::new(local))
        }
        CacheType::Shared(cache) => Ok(cache),
        CacheType::StormTracking(params) => {
            let storm = StormTrackingCmc::new(&params).map_err(|e| {
                MaterialsError::new(format!("failed to initialize StormTrackingCmc: {e}"))
            })?;
            Ok(SharedCmc::new(storm))
        }
    }
}
