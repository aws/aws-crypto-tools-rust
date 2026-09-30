// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Cmc` trait — the abstract contract every Cryptographic Materials
//! Cache MUST implement.
//!
//! The MPL needs `dyn Cmc` and `Box<dyn Cmc>` for plug-in caches so that a
//! caching CMM can hold an arbitrary, runtime-configured cache.
//! `async_trait` allows us to get a `dyn Cmc` and `Box<dyn Cmc>`.

pub mod default;
pub mod entry;
pub mod local;
pub mod storm_tracking;

use std::sync::Arc;

use crate::Error;
use async_trait::async_trait;

pub use default::{DefaultCmc, DefaultCmcBuilder};
pub use entry::{BytesUsage, CacheEntry, CachedMaterials, MessageUsage, UsageMetadata};
pub use local::{LocalCmc, LocalCmcBuilder};
pub use storm_tracking::{StormTrackingCmc, StormTrackingCmcBuilder};

use std::time::Duration;

//
/// To hold a cache whose concrete type is chosen at runtime, use [`SharedCmc`].
#[async_trait]
pub trait Cmc: Send + Sync {
    /// Insert (or replace) the cache entry for the supplied cache identifier.
    /// Mirrors the `Put Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#put-cache-entry).
    //
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), Error>;

    /// Retrieve the cache entry for the supplied cache identifier, returning
    /// `None` on cache miss. Mirrors the `Get Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#get-cache-entry).
    //
    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, Error>;

    /// Delete the cache entry for the supplied cache identifier. Returns
    /// successfully whether or not an entry was present. Mirrors the
    /// `Delete Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#delete-cache-entry).
    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), Error>;

    /// The storm-tracking grace period, for a cache that refreshes entries
    /// this long before they expire. `None` for a cache without one.
    fn grace_period(&self) -> Option<Duration> {
        None
    }
}

crate::shared::shared_handle!(
    /// A cache whose concrete type is chosen at runtime.
    ///
    /// It implements [`Cmc`], so it can be passed anywhere a cache is accepted.
    /// Callers that know their cache's type pass it directly and never need this one.
    ///
    /// A clone of a `SharedCmc` refers to the same cache, not a copy of it.
    /// Give several keyrings clones of one handle
    /// and they read and write the same entries.
    SharedCmc,
    Cmc
);

#[async_trait]
impl Cmc for SharedCmc {
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), Error> {
        self.0.put_cache_entry(cache_id, entry).await
    }

    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, Error> {
        self.0.get_cache_entry(cache_id).await
    }

    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), Error> {
        self.0.delete_cache_entry(cache_id).await
    }

    fn grace_period(&self) -> Option<Duration> {
        self.0.grace_period()
    }
}
