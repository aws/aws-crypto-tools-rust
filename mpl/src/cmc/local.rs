// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local Cryptographic Materials Cache — an in-memory, LRU-ordered `Cmc`
//! implementation with TTL-aware pruning, backed by the [`lru`] crate.
//!
//! See [`LocalCmc`] for the public API. Behavioral requirements are
//! specified in `../spec/framework/local-cryptographic-materials-cache.md`.

use crate::Error;
use crate::error::Kind;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;
use lru::LruCache;

use super::{CacheEntry, Cmc};

/// Internal storage type — the `lru` crate's `LruCache` keyed by cache id
/// with `Arc<CacheEntry>` values so `get` can hand out a reference-counted
/// clone without copying the underlying materials.
type Inner = LruCache<Vec<u8>, Arc<CacheEntry>>;

/// Concrete in-memory LRU Cryptographic Materials Cache.
///
/// `LocalCmc` is parameterised by an `entry_capacity` (caller-supplied
/// upper bound on the number of stored entries) and an
/// `entry_pruning_tail_size` (number of least-recently-used entries the
/// cache scans for TTL-expired evictees during pruning). It implements the
/// abstract [`Cmc`] trait so callers can plug it into a caching CMM.
#[derive(Clone)]
pub struct LocalCmc {
    inner: Arc<LocalCmcInner>,
}

struct LocalCmcInner {
    /// Configured maximum number of stored entries. The cache MUST NOT
    /// exceed this value once `put` has returned.
    entry_capacity: usize,
    /// Number of least-recently-used entries scanned during pruning.
    entry_pruning_tail_size: usize,
    /// All shared state lives behind a single `Mutex` so updates are
    /// serialized at the cache layer. `None` when `entry_capacity == 0`
    /// (no-store cache); `Some(LruCache)` otherwise.
    store: Mutex<Option<Inner>>,
    /// Clock seam — `SystemTime::now`.
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl LocalCmc {
    /// Construct a `LocalCmc` with the supplied entry capacity and entry
    /// pruning tail size.
    ///
    /// A capacity of `0` yields a no-store cache: `put` is a silent no-op
    /// and `get` always returns `None`.
    pub fn new(entry_capacity: usize, entry_pruning_tail_size: usize) -> Result<Self, Error> {
        Self::with_clock_impl(entry_capacity, entry_pruning_tail_size, SystemTime::now)
    }

    /// Test-only constructor with clock injection. Gated behind the
    /// `test-utils` feature so it is not exposed to library consumers.
    /// Tests use this to fast-forward past entry TTLs without sleeping.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn with_clock<F>(
        entry_capacity: usize,
        entry_pruning_tail_size: usize,
        now: F,
    ) -> Result<Self, Error>
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        Self::with_clock_impl(entry_capacity, entry_pruning_tail_size, now)
    }

    /// Internal constructor that accepts an arbitrary clock. `pub(crate)`
    /// so `StormTrackingCmc` can construct its inner `LocalCmc` without
    /// depending on the `test-utils`-gated public `with_clock`; not part
    /// of the public API.
    pub(crate) fn with_clock_impl<F>(
        entry_capacity: usize,
        entry_pruning_tail_size: usize,
        now: F,
    ) -> Result<Self, Error>
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        // `NonZeroUsize::new` returns `None` for `0`; the resulting
        // `Option<LruCache>` is `None` for the no-store cache and
        // `Some(LruCache::new(cap))` otherwise.
        let inner = NonZeroUsize::new(entry_capacity).map(LruCache::new);
        Ok(Self {
            inner: Arc::new(LocalCmcInner {
                entry_capacity,
                entry_pruning_tail_size,
                store: Mutex::new(inner),
                now: Arc::new(now),
            }),
        })
    }

    /// Configured entry capacity.
    pub fn entry_capacity(&self) -> usize {
        self.inner.entry_capacity
    }

    /// Configured entry pruning tail size.
    pub fn entry_pruning_tail_size(&self) -> usize {
        self.inner.entry_pruning_tail_size
    }

    /// Number of currently stored entries. Useful for tests asserting
    /// capacity invariants.
    pub fn len(&self) -> Result<usize, Error> {
        let inner = self
            .inner
            .store
            .lock()
            .map_err(|_| Error::new(Kind::Internal, "cache lock poisoned"))?;
        Ok(inner.as_ref().map_or(0, LruCache::len))
    }

    /// Whether the cache currently holds zero entries.
    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }

    /// Walk the `entry_pruning_tail_size` least-recently-used entries and
    /// drop any that have TTL-expired. Holds the inner Mutex for the
    /// duration of the walk.
    ///
    /// [`LruCache::iter`] yields entries in most-recently-used-first order
    /// and is a `DoubleEndedIterator`, so `iter().rev().take(N)` gives
    /// the `N` least-recently-used entries.
    fn prune_tail(&self, cache: &mut Inner) {
        let take_n = self.inner.entry_pruning_tail_size.min(cache.len());
        if take_n == 0 {
            return;
        }
        let now = (self.inner.now)();
        let to_remove: Vec<Vec<u8>> = cache
            .iter()
            .rev()
            .take(take_n)
            .filter(|(_, entry)| entry.expiry_time <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for cache_id in &to_remove {
            cache.pop(cache_id);
        }
    }
}

#[async_trait]
impl Cmc for LocalCmc {
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), Error> {
        let mut inner = self
            .inner
            .store
            .lock()
            .map_err(|_| Error::new(Kind::Internal, "cache lock poisoned"))?;
        let Some(cache) = inner.as_mut() else {
            // Zero-capacity cache: never store. Silently drop the entry so
            // the post-condition `len == 0 <= entry_capacity` holds.
            return Ok(());
        };
        // `LruCache::put` evicts the LRU entry before insertion when the
        // cache is at capacity, keeping `len <= entry_capacity` at all
        // observation points.
        cache.put(cache_id.to_vec(), Arc::new(entry));
        Ok(())
    }

    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, Error> {
        let mut inner = self
            .inner
            .store
            .lock()
            .map_err(|_| Error::new(Kind::Internal, "cache lock poisoned"))?;
        let Some(cache) = inner.as_mut() else {
            return Ok(None);
        };

        self.prune_tail(cache);

        let now = (self.inner.now)();
        // Peek first (no LRU promotion) so a TTL-expired entry is not
        // promoted before being evicted.
        let is_fresh = cache.peek(cache_id).map(|entry| entry.expiry_time > now);
        match is_fresh {
            // Fresh: promote to MRU via `get` and hand back an Arc clone.
            Some(true) => Ok(cache.get(cache_id).cloned()),
            // Expired: evict and report a miss. The prune step above may
            // have already removed this entry if it was in the tail
            // window; if so, `pop` is a no-op.
            Some(false) => {
                cache.pop(cache_id);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), Error> {
        let mut inner = self
            .inner
            .store
            .lock()
            .map_err(|_| Error::new(Kind::Internal, "cache lock poisoned"))?;
        let Some(cache) = inner.as_mut() else {
            return Ok(());
        };
        cache.pop(cache_id);
        Ok(())
    }
}
