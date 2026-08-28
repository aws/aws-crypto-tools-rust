// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Cmc` trait — the abstract contract every Cryptographic Materials
//! Cache MUST implement.
//!
//! The MPL needs `dyn Cmc` and `Box<dyn Cmc>` for plug-in caches so that a
//! caching CMM can hold an arbitrary, runtime-configured cache.
//! `async_trait` allows us to get a `dyn Cmc` and `Box<dyn Cmc>`.

pub mod cache_config;
pub mod entry;
pub mod local;
pub mod storm_tracking;

use async_trait::async_trait;

pub use cache_config::{CacheType, DefaultCache, StormTrackingCache, StormTrackingCacheBuilder};
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

//= spec/framework/cryptographic-materials-cache.md#overview
//= type=implication
//# This document describes the interface that all CMCs MUST implement.
#[async_trait]
pub trait Cmc: Send + Sync {
    /// Insert (or replace) the cache entry for the supplied cache identifier.
    /// Mirrors the `Put Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#put-cache-entry).
    //= spec/framework/cryptographic-materials-cache.md#put-cache-entry
    //= type=implication
    //# This operation MUST NOT return the inserted cache entry.
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), CmcError>;

    /// Retrieve the cache entry for the supplied cache identifier, returning
    /// `None` on cache miss. Mirrors the `Get Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#get-cache-entry).
    //
    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError>;

    /// Delete the cache entry for the supplied cache identifier. Returns
    /// successfully whether or not an entry was present. Mirrors the
    /// `Delete Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#delete-cache-entry).
    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), CmcError>;
}
