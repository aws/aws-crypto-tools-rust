// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local Cryptographic Materials Cache — concrete `Cmc` impl backed by an
//! in-memory least-recently-used (LRU) store with TTL-aware pruning.
//!
//! `LocalCmc` is the first concrete CMC in the MPL and satisfies the
//! abstract `Cmc` trait contract in [`super`]. It implements the behaviors
//! defined in `../spec/framework/local-cryptographic-materials-cache.md`:
//!
//! - **Entry capacity** — caller-provided maximum number of stored entries.
//! - **Entry pruning tail size** — how many least-recently-used entries the
//!   cache scans for TTL-expired evictees during pruning.
//! - **Put** does not prune; MAY temporarily exceed capacity; MUST evict
//!   LRU entries before returning so the post-condition is `len <= capacity`.
//! - **Get** prunes the tail window for TTL-expired entries first, then
//!   returns the requested entry only if it has not itself TTL-expired.
//! - **Pruning** evicts every TTL-expired entry among the `N` LRU entries.
//!
//! The cache holds entries by `Arc<CacheEntry>` so `get_cache_entry` can
//! return `Some(Arc<CacheEntry>)` without cloning the underlying materials.
//! All shared state lives behind a single `Mutex<LocalCmcInner>`; updates
//! are therefore serialized at the cache layer.
//!
//! For deterministic TTL/pruning tests, [`LocalCmc::with_clock`] accepts an
//! injected clock function. Production callers use [`LocalCmc::new`], which
//! defaults to `SystemTime::now`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;

use super::{CacheEntry, Cmc, CmcError};

/// Internal storage for `LocalCmc`. A `HashMap` provides O(1) lookup by
/// cache identifier and a parallel `Vec` records the LRU ordering with
/// `lru[0]` as the least-recently-used cache identifier and `lru.last()`
/// as the most-recently-used one.
struct LocalCmcInner {
    /// Cache identifier → entry map. `Arc<CacheEntry>` lets `get` hand
    /// out a reference-counted clone without copying the materials.
    entries: HashMap<Vec<u8>, Arc<CacheEntry>>,
    /// LRU ordering. Front = least recently used, back = most recently
    /// used. The cache identifier strings are stored verbatim alongside
    /// the keys in `entries`; the two collections are kept in sync.
    lru: Vec<Vec<u8>>,
}

impl LocalCmcInner {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lru: Vec::new(),
        }
    }

    /// Move the supplied cache identifier to the most-recently-used end of
    /// the LRU vector. No-op if the identifier is not present.
    fn touch(&mut self, cache_id: &[u8]) {
        if let Some(pos) = self.lru.iter().position(|id| id.as_slice() == cache_id) {
            let id = self.lru.remove(pos);
            self.lru.push(id);
        }
    }

    /// Insert (or replace) the entry for `cache_id`. The identifier is
    /// placed at the most-recently-used end of the LRU vector. If an
    /// entry already exists for this identifier its prior LRU position
    /// is dropped before the new position is appended.
    fn insert(&mut self, cache_id: Vec<u8>, entry: Arc<CacheEntry>) {
        if self.entries.contains_key(&cache_id)
            && let Some(pos) = self.lru.iter().position(|id| id == &cache_id)
        {
            self.lru.remove(pos);
        }
        self.entries.insert(cache_id.clone(), entry);
        self.lru.push(cache_id);
    }

    /// Remove the entry and LRU slot for `cache_id`, if present.
    fn remove(&mut self, cache_id: &[u8]) {
        self.entries.remove(cache_id);
        if let Some(pos) = self.lru.iter().position(|id| id.as_slice() == cache_id) {
            self.lru.remove(pos);
        }
    }

    /// Number of currently stored entries.
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Pop the least-recently-used cache identifier off the LRU vector and
    /// return it (or `None` if the cache is empty). The corresponding
    /// entry in `entries` is also removed.
    fn pop_lru(&mut self) -> Option<Vec<u8>> {
        if self.lru.is_empty() {
            return None;
        }
        let id = self.lru.remove(0);
        self.entries.remove(&id);
        Some(id)
    }
}

/// Concrete in-memory LRU Cryptographic Materials Cache.
///
/// `LocalCmc` is parameterised by an `entry_capacity` (caller-supplied
/// upper bound on the number of stored entries) and an
/// `entry_pruning_tail_size` (number of least-recently-used entries the
/// cache scans for TTL-expired evictees during pruning). It implements the
/// abstract [`Cmc`] trait so callers can plug it into a caching CMM.
//= ../spec/framework/local-cryptographic-materials-cache.md#pruning
//= type=exception
//= reason=Per-get pruning (see LocalCmc::get_cache_entry, which calls prune_tail before every read) bounds the staleness of long-idle expired entries to the N least-recently-used window on every get. A separate background sweeper is out of scope for this concrete LocalCmc and belongs to a higher-level wrapper such as SynchronizedLocalCmc; LocalCmc holds no background tasks and exposes no Drop-time invariants beyond Mutex unwind.
//# The local CMC SHOULD also periodically evict all TTL-expired entries
//# among the `N` least recently used entries.
pub struct LocalCmc {
    /// Configured maximum number of stored entries. The cache MUST NOT
    /// exceed this value except temporarily while a put is in progress.
    entry_capacity: usize,
    /// Number of least-recently-used entries scanned during pruning.
    entry_pruning_tail_size: usize,
    /// All shared state lives behind a single `Mutex` so updates are
    /// serialized at the cache layer.
    inner: Mutex<LocalCmcInner>,
    /// Clock seam — `SystemTime::now` in production, an injected closure
    /// in tests so TTL/pruning behavior can be exercised deterministically.
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl LocalCmc {
    /// Construct a `LocalCmc` configured with the supplied entry capacity
    /// and entry pruning tail size. The cache uses `SystemTime::now` as its
    /// clock; tests requiring deterministic TTL behavior should use
    /// [`LocalCmc::with_clock`] instead.
    ///
    /// `entry_capacity` is accepted for any value in `[0, usize::MAX]`
    /// (the implementation-defined maximum is `usize::MAX`).
    //= ../spec/framework/local-cryptographic-materials-cache.md#initialization
    //# On initialization of the local CMC,
    //# the caller MUST provide the following:
    pub fn new(entry_capacity: usize, entry_pruning_tail_size: usize) -> Result<Self, CmcError> {
        Self::with_clock(entry_capacity, entry_pruning_tail_size, SystemTime::now)
    }

    /// Construct a `LocalCmc` with an injected clock. Used by tests to
    /// fast-forward past entry TTLs without sleeping. Production callers
    /// should use [`LocalCmc::new`].
    pub fn with_clock<F>(
        entry_capacity: usize,
        entry_pruning_tail_size: usize,
        now: F,
    ) -> Result<Self, CmcError>
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        Ok(Self {
            //= ../spec/framework/local-cryptographic-materials-cache.md#entry-capacity
            //# The local CMC MUST accept entry capacity values between zero
            //# and an implementation-defined maximum, inclusive.
            entry_capacity,
            //= ../spec/framework/local-cryptographic-materials-cache.md#initialization
            //# The local CMC MUST also define the following:
            entry_pruning_tail_size,
            inner: Mutex::new(LocalCmcInner::new()),
            now: Arc::new(now),
        })
    }

    /// Configured entry capacity.
    pub const fn entry_capacity(&self) -> usize {
        self.entry_capacity
    }

    /// Configured entry pruning tail size.
    pub const fn entry_pruning_tail_size(&self) -> usize {
        self.entry_pruning_tail_size
    }

    /// Number of currently stored entries. Useful for tests asserting
    /// capacity invariants.
    pub fn len(&self) -> Result<usize, CmcError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| CmcError::storage_failed(format!("LocalCmc lock poisoned: {e}")))?;
        Ok(inner.len())
    }

    /// Whether the cache currently holds zero entries.
    pub fn is_empty(&self) -> Result<bool, CmcError> {
        Ok(self.len()? == 0)
    }

    /// Walk the `entry_pruning_tail_size` least-recently-used entries and
    /// drop any that have TTL-expired. Holds the inner Mutex for the
    /// duration of the walk.
    fn prune_tail(&self, inner: &mut LocalCmcInner) {
        let now = (self.now)();
        let take_n = self.entry_pruning_tail_size.min(inner.lru.len());
        let mut to_remove: Vec<Vec<u8>> = Vec::new();
        //= ../spec/framework/local-cryptographic-materials-cache.md#entry-pruning-tail-size
        //# The _entry pruning tail size_
        //# is the number of least recently used entries that the local CMC
        //# MUST check during [pruning](#pruning)
        //# for TTL-expired entries to evict.
        for cache_id in inner.lru.iter().take(take_n) {
            if let Some(entry) = inner.entries.get(cache_id)
                && entry.expiry_time <= now
            {
                to_remove.push(cache_id.clone());
            }
        }
        for cache_id in to_remove {
            //= ../spec/framework/local-cryptographic-materials-cache.md#pruning
            //# To prune TTL-expired cache entries,
            //# the local CMC MUST evict all TTL-expired entries
            //# among the `N` least recently used entries,
            //# where `N` is the [Entry Pruning Tail Size](#entry-pruning-tail-size).
            inner.remove(&cache_id);
        }
    }
}

#[async_trait]
impl Cmc for LocalCmc {
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), CmcError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| CmcError::storage_failed(format!("LocalCmc lock poisoned: {e}")))?;

        //= ../spec/framework/local-cryptographic-materials-cache.md#put-cache-entry
        //# While performing a Put Cache Entry operation,
        //# the local CMC MAY store more entries than the entry capacity.
        //
        //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
        //# The CMC MUST create a new cache entry for the specified cache ID.
        //
        //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
        //= type=implication
        //# The cache entry MUST include all [usage metadata](#usage-metadata)
        //# since this information can not be updated after the put operation.
        //
        //= ../spec/framework/cryptographic-materials-cache.md#usage-metadata
        //# Updating usage metadata SHOULD be atomic.
        inner.insert(cache_id.to_vec(), Arc::new(entry));

        //= ../spec/framework/local-cryptographic-materials-cache.md#entry-capacity
        //# The local CMC MUST NOT store more entries than this value,
        //# except temporarily while performing a Put Cache Entry operation.
        //
        //= ../spec/framework/local-cryptographic-materials-cache.md#put-cache-entry
        //# However, before returning, the local CMC MUST evict least-recently used entries
        //# until the number of stored entries does not exceed the entry capacity.
        while inner.len() > self.entry_capacity {
            if inner.pop_lru().is_none() {
                break;
            }
        }
        Ok(())
    }

    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| CmcError::storage_failed(format!("LocalCmc lock poisoned: {e}")))?;

        //= ../spec/framework/local-cryptographic-materials-cache.md#get-cache-entry
        //# When performing a Get Cache Entry operation,
        //# the local CMC MUST [prune TTL-expired cache entries](#pruning).
        self.prune_tail(&mut inner);

        let now = (self.now)();
        match inner.entries.get(cache_id).cloned() {
            Some(entry) => {
                if entry.expiry_time <= now {
                    //= ../spec/framework/local-cryptographic-materials-cache.md#get-cache-entry
                    //# The local CMC MUST NOT return any TTL-expired entry.
                    //
                    //= ../spec/framework/cryptographic-materials-cache.md#time-to-live-ttl
                    //# After a cache entry's TTL has elapsed,
                    //# we say that the entry is _TTL-expired_,
                    //# and a CMC MUST NOT return the entry to any caller.
                    //
                    //= ../spec/framework/cryptographic-materials-cache.md#get-cache-entry
                    //# The CMC MUST validate that the cache entry
                    //# has not exceeded it's stored [TTL](#time-to-live-ttl).
                    inner.remove(cache_id);
                    Ok(None)
                } else {
                    inner.touch(cache_id);
                    Ok(Some(entry))
                }
            }
            None => Ok(None),
        }
    }

    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), CmcError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| CmcError::storage_failed(format!("LocalCmc lock poisoned: {e}")))?;
        inner.remove(cache_id);
        Ok(())
    }
}
