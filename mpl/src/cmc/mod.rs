// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Cmc` trait — the abstract contract every Cryptographic Materials
//! Cache MUST implement.
//!
//! # Why `async_trait` and not native AFIT
//!
//! The same dyn-compatibility rationale recorded in [`crate::keyring`] and
//! [`crate::cmm`] applies here: AFIT traits are not stable-dyn-compatible,
//! the MPL needs `dyn Cmc` and `Box<dyn Cmc>` for plug-in caches (LocalCmc,
//! SynchronizedLocalCmc, StormTrackerCmc, custom user CMCs) so that a
//! caching CMM can hold an arbitrary, runtime-configured cache.
//! `async_trait` boxes the future to make `dyn Cmc` work today.
//!
//! # Concrete-CMC implementations
//!
//! [`LocalCmc`] is the first concrete CMC in the MPL — an in-memory
//! least-recently-used cache with TTL-aware pruning. The behavioral MUSTs
//! on `put_cache_entry` / `get_cache_entry` (TTL enforcement, "must create
//! a new entry", "must include all usage metadata") and the
//! `usage-metadata` SHOULD-be-atomic clause are therefore satisfied by
//! `LocalCmc`'s methods and verified by `tests/test_local_cmc.rs`.
//!
//! Multi-thread visibility MAYs and storm-tracker permissions remain
//! `type=exception` on the trait until SynchronizedLocalCmc and
//! StormTrackerCmc land — those concrete caches will earn
//! `type=implementation,test` for the visibility clauses when added.

pub mod entry;
pub mod local;
pub mod storm_tracking;

use async_trait::async_trait;

pub use entry::{BytesUsage, CacheEntry, CachedMaterials, MessageUsage, UsageMetadata};
pub use local::LocalCmc;
pub use storm_tracking::{StormTrackingCmc, TimeUnits};

use std::fmt;
use std::sync::Arc;

/// Categorisation of a `CmcError`. New kinds may be added in minor
/// releases, hence `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmcErrorKind {
    /// A concrete CMC's underlying storage failed (lock poisoned, IO error,
    /// etc.). The `message` field carries the cause.
    StorageFailed,
    /// A concrete CMC could not honor the request because the entry shape
    /// supplied by the caller is invalid (missing usage metadata at put
    /// time, expiry-before-creation, etc.).
    InvalidEntry,
}

/// Error type for `Cmc` trait operations. Mirrors the
/// `MaterialsError`/`MaterialsErrorKind` shape used elsewhere in the MPL so
/// callers have a single `kind` enum to match against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmcError {
    /// Categorisation of this error. Stable for matching at call sites.
    pub kind: CmcErrorKind,
    /// Free-form human-readable message describing this specific failure.
    pub message: String,
}

impl CmcError {
    /// Construct a `StorageFailed` error.
    pub fn storage_failed(reason: impl Into<String>) -> Self {
        Self {
            kind: CmcErrorKind::StorageFailed,
            message: reason.into(),
        }
    }

    /// Construct an `InvalidEntry` error.
    pub fn invalid_entry(reason: impl Into<String>) -> Self {
        Self {
            kind: CmcErrorKind::InvalidEntry,
            message: reason.into(),
        }
    }

    /// Borrow the categorisation of this error.
    pub const fn kind(&self) -> &CmcErrorKind {
        &self.kind
    }
}

impl fmt::Display for CmcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CmcError({:?}): {}", self.kind, self.message)
    }
}

impl std::error::Error for CmcError {}

//= ../spec/framework/cryptographic-materials-cache.md#overview
//= type=implication
//# This document describes the interface that all CMCs MUST implement.
//
//= ../spec/framework/cryptographic-materials-cache.md#background-processing
//= type=exception
//= reason=Per-get pruning in LocalCmc::get_cache_entry bounds the staleness of long-idle expired entries to the N least-recently-used window on every get; a separate background sweeper is out of scope for the abstract trait and for the basic LocalCmc, and belongs to a higher-level wrapper such as SynchronizedLocalCmc.
//# An implementation SHOULD provide a way to avoid this, for example,
//# by spawning a background thread to occasionally remove expired entries.
#[async_trait]
pub trait Cmc: Send + Sync {
    /// Insert (or replace) the cache entry for the supplied cache identifier.
    /// Mirrors the `Put Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#put-cache-entry).
    //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
    //= type=implication
    //# This operation MUST NOT return the inserted cache entry.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
    //= type=exception
    //= reason=Visibility MAY — realized by StormTrackingCmc which acquires its inflight Mutex on every put then forwards to LocalCmc; cross-thread visibility for the next get follows from the Mutex release/acquire happens-before edge.
    //# If used in a multi-threaded context,
    //# the next [Get Cache Entry](#get-cache-entry) operation
    //# MAY not return the entry just added.
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), CmcError>;

    /// Retrieve the cache entry for the supplied cache identifier, returning
    /// `None` on cache miss. Mirrors the `Get Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#get-cache-entry).
    //= ../spec/framework/cryptographic-materials-cache.md#get-cache-entry
    //= type=exception
    //= reason=Permission MAY — realized by StormTrackingCmc::get_cache_entry's "within grace period AND not inflight → return NoSuchEntry" branch (10.4) and equivalent inflight-update branches (10.6, 10.11).
    //# - Get Cache Entry MAY return a cache miss when the TTL has net yet been exceeded.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#get-cache-entry
    //= type=exception
    //= reason=Permission MAY — realized by StormTrackingCmc::get_cache_entry's blocking branches (10.7, 10.10) which spin on sleep_milli intervals until either the FanOut slot opens or the key appears.
    //# - Get Cache Entry MAY not return immediately if no cache entry exists for the specified cache ID,
    //# and a cache miss was recently returned for another thread.
    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError>;

    /// Delete the cache entry for the supplied cache identifier. Returns
    /// successfully whether or not an entry was present. Mirrors the
    /// `Delete Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#delete-cache-entry).
    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), CmcError>;
}
