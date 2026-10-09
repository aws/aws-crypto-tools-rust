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
mod operation;
pub mod storm_tracking;

use crate::Error;
use async_trait::async_trait;

pub use default::{DefaultCmc, DefaultCmcBuilder};
pub use entry::{
    BytesUsage, CacheEntry, CacheEntryBuilder, CachedMaterials, MessageUsage, UsageMetadata,
    UsageMetadataBuilder,
};
pub use local::{LocalCmc, LocalCmcBuilder};
pub use operation::{
    DeleteCacheEntryInput, DeleteCacheEntryInputBuilder, DeleteCacheEntryOutput,
    DeleteCacheEntryOutputBuilder, GetCacheEntryInput, GetCacheEntryInputBuilder,
    GetCacheEntryOutput, GetCacheEntryOutputBuilder, PutCacheEntryInput, PutCacheEntryInputBuilder,
    PutCacheEntryOutput, PutCacheEntryOutputBuilder, UpdateUsageMetadataInput,
    UpdateUsageMetadataInputBuilder, UpdateUsageMetadataOutput, UpdateUsageMetadataOutputBuilder,
};
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
    async fn put_cache_entry(
        &self,
        input: PutCacheEntryInput,
    ) -> Result<PutCacheEntryOutput, Error>;

    /// Retrieve the cache entry for the supplied cache identifier.
    /// The output's entry is `None` on a cache miss.
    /// Mirrors the `Get Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#get-cache-entry).
    //
    async fn get_cache_entry(
        &self,
        input: GetCacheEntryInput,
    ) -> Result<GetCacheEntryOutput, Error>;

    /// Delete the cache entry for the supplied cache identifier. Returns
    /// successfully whether or not an entry was present. Mirrors the
    /// `Delete Cache Entry` behavior of the
    /// [CMC interface specification](../../../spec/framework/cryptographic-materials-cache.md#delete-cache-entry).
    async fn delete_cache_entry(
        &self,
        input: DeleteCacheEntryInput,
    ) -> Result<DeleteCacheEntryOutput, Error>;

    /// Count one more message of `bytes_used` plaintext bytes against the entry for the identifier.
    /// Does nothing if there is no entry.
    /// Deletes the entry if either counter would overflow.
    /// A caching CMM calls this each time it reuses cached encryption materials.
    async fn update_usage_metadata(
        &self,
        input: UpdateUsageMetadataInput,
    ) -> Result<UpdateUsageMetadataOutput, Error>;

    /// How long before an entry expires the cache sends one caller to refresh it.
    /// Return `None`, the default, if the cache does not refresh early.
    ///
    /// A hierarchical keyring requires this to be less than its TTL.
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
    async fn put_cache_entry(
        &self,
        input: PutCacheEntryInput,
    ) -> Result<PutCacheEntryOutput, Error> {
        self.0.put_cache_entry(input).await
    }

    async fn get_cache_entry(
        &self,
        input: GetCacheEntryInput,
    ) -> Result<GetCacheEntryOutput, Error> {
        self.0.get_cache_entry(input).await
    }

    async fn delete_cache_entry(
        &self,
        input: DeleteCacheEntryInput,
    ) -> Result<DeleteCacheEntryOutput, Error> {
        self.0.delete_cache_entry(input).await
    }

    async fn update_usage_metadata(
        &self,
        input: UpdateUsageMetadataInput,
    ) -> Result<UpdateUsageMetadataOutput, Error> {
        self.0.update_usage_metadata(input).await
    }

    fn grace_period(&self) -> Option<Duration> {
        self.0.grace_period()
    }
}
