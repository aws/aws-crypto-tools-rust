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
//! # Concrete-CMC-deferred clauses (`type=exception`)
//!
//! This commit introduces the abstract `Cmc` trait scaffolding plus the
//! `CacheEntry` data type only — no concrete CMC (LocalCmc, StormTrackerCmc,
//! …) is implemented yet. Behavioral MUSTs on `put_cache_entry` /
//! `get_cache_entry` (TTL enforcement, "must create a new entry", "must
//! include all usage metadata"), the SHOULD on background processing, and
//! the multi-thread MAYs are therefore annotated `type=exception` here.
//! They are exercised TODAY by the mock-driven contract harness in
//! `tests/test_cmc_contract.rs`, but those tests intentionally carry no
//! `type=test` annotations: when each concrete CMC is added in a future
//! commit, the matching exception below will be replaced with
//! `type=implementation` on the concrete method, and `type=test` will be
//! placed on the contract test that proves it.

pub mod entry;

use async_trait::async_trait;

pub use entry::{BytesUsage, CacheEntry, CachedMaterials, MessageUsage, UsageMetadata};

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
//= reason=SHOULD applies to concrete CMCs, not the abstract trait. A future LocalCmc may spawn a sweeper thread or expose a `clear_expired()` method; that concrete impl will earn `type=implementation,test` for this requirement.
//# An implementation SHOULD provide a way to avoid this, for example,
//# by spawning a background thread to occasionally remove expired entries.
#[async_trait]
pub trait Cmc: Send + Sync {
    /// Insert (or replace) the cache entry for the supplied cache identifier.
    /// Mirrors the `Put Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#put-cache-entry).
    //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMC exists in this commit. Behavior is exercised today by mock-driven contract tests in tests/test_cmc_contract.rs. When a concrete CMC (e.g., LocalCmc) is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# The CMC MUST create a new cache entry for the specified cache ID.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
    //= type=implication
    //# This operation MUST NOT return the inserted cache entry.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMC exists in this commit. The signature accepts a fully-formed CacheEntry whose UsageMetadata is set at construction; the concrete LocalCmc will earn `type=implementation,test` when it stores the entry verbatim.
    //# The cache entry MUST include all [usage metadata](#usage-metadata)
    //# since this information can not be updated after the put operation.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
    //= type=exception
    //= reason=Visibility MAY — depends on the concrete cache's locking/visibility model. SynchronizedLocalCmc and StormTrackerCmc will each define their own cross-thread visibility guarantee when added.
    //# If used in a multi-threaded context,
    //# the next [Get Cache Entry](#get-cache-entry) operation
    //# MAY not return the entry just added.
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), CmcError>;

    /// Retrieve the cache entry for the supplied cache identifier, returning
    /// `None` on cache miss. Mirrors the `Get Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#get-cache-entry).
    //= ../spec/framework/cryptographic-materials-cache.md#time-to-live-ttl
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMC exists in this commit. The TTL-expired-MUST-NOT-return rule is exercised today by mock-driven contract tests in tests/test_cmc_contract.rs that advance a mock clock past the entry's expiry. When a concrete CMC (e.g., LocalCmc) is added, this exception will be replaced with `type=implementation` on the concrete `get_cache_entry` and `type=test` on the contract test that proves it.
    //# After a cache entry's TTL has elapsed,
    //# we say that the entry is _TTL-expired_,
    //# and a CMC MUST NOT return the entry to any caller.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#get-cache-entry
    //= type=exception
    //= reason=Abstract trait contract; no concrete CMC exists in this commit. The TTL-validation MUST is exercised today by mock-driven contract tests in tests/test_cmc_contract.rs. When a concrete CMC is added, this exception will be replaced with `type=implementation` on the concrete method and `type=test` on the contract test that proves it.
    //# The CMC MUST validate that the cache entry
    //# has not exceeded it's stored [TTL](#time-to-live-ttl).
    //
    //= ../spec/framework/cryptographic-materials-cache.md#get-cache-entry
    //= type=exception
    //= reason=Permission MAY — concrete cache choice (e.g., a stale-tolerant tier MAY return miss). StormTrackerCmc will exercise this branch when added.
    //# - Get Cache Entry MAY return a cache miss when the TTL has net yet been exceeded.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#get-cache-entry
    //= type=exception
    //= reason=Permission MAY — concrete cache choice (storm-tracker pattern). StormTrackerCmc will exercise this delayed-return branch when added.
    //# - Get Cache Entry MAY not return immediately if no cache entry exists for the specified cache ID,
    //# and a cache miss was recently returned for another thread.
    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError>;

    /// Delete the cache entry for the supplied cache identifier. Returns
    /// successfully whether or not an entry was present. Mirrors the
    /// `Delete Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#delete-cache-entry).
    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), CmcError>;
}
