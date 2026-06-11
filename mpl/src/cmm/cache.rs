// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic Materials Cache trait + supporting types.

use std::time::Duration;

use async_trait::async_trait;

use crate::structures::{DecryptionMaterials, EncryptionMaterials};

/// Opaque cache entry identifier — the SHA-384 (48-byte) digest produced by
/// the caching CMM's [Appendix A formulas](../../../spec/framework/caching-cmm.md#appendix-a-cache-entry-identifier-formulas).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheEntryId(pub [u8; 48]);

impl CacheEntryId {
    /// Borrow the raw 48-byte digest.
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

/// Per-cache-entry usage statistics tracked by the caching CMM. The caching
/// CMM stamps zeros into a fresh entry on store and increments these counters
/// on each cache hit so that the entry can be retired once it crosses its
/// configured `limit_bytes` / `limit_messages` thresholds.
//= ../spec/framework/caching-cmm.md#limit-messages
//= type=implication
//# The caching CMM MUST provide a structure as defined below,
//# to track usage statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsageStats {
    /// Number of messages encrypted with the cache entry's data key.
    pub messages_encrypted: u64,
    /// Number of plaintext bytes encrypted with the cache entry's data key.
    pub bytes_encrypted: u64,
}

/// The Cryptographic Materials Cache (CMC) trait — the storage tier the
/// caching CMM uses to memoize materials by cache entry identifier.
///
/// The CMC's own specification (`cryptographic-materials-cache.md`) is NOT
/// registered with this MPL crate's duvet config; this trait carries no duvet
/// annotations. It exists to give the caching CMM a typed dependency that can
/// be mocked in tests.
#[async_trait]
pub trait CryptographicMaterialsCache: Send + Sync {
    /// Look up encryption materials for the given cache entry id. Returns
    /// `None` when no entry exists or the entry has expired.
    async fn get_encrypt(&self, id: &CacheEntryId) -> Option<EncryptionMaterials>;

    /// Store fresh encryption materials with the given initial usage stats and TTL.
    async fn put_encrypt(
        &self,
        id: &CacheEntryId,
        materials: EncryptionMaterials,
        stats: UsageStats,
        ttl: Duration,
    );

    /// Increment the usage stats associated with a cached encryption entry.
    async fn update_usage_encrypt(&self, id: &CacheEntryId, messages_delta: u64, bytes_delta: u64);

    /// Look up decryption materials for the given cache entry id. Returns
    /// `None` when no entry exists or the entry has expired.
    async fn get_decrypt(&self, id: &CacheEntryId) -> Option<DecryptionMaterials>;

    /// Store fresh decryption materials with the given TTL.
    async fn put_decrypt(&self, id: &CacheEntryId, materials: DecryptionMaterials, ttl: Duration);
}
