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

use super::{
    CacheEntry, Cmc, DeleteCacheEntryInput, DeleteCacheEntryOutput, GetCacheEntryInput,
    GetCacheEntryOutput, PutCacheEntryInput, PutCacheEntryOutput,
};

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

impl std::fmt::Debug for LocalCmc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCmc")
            .field("entry_capacity", &self.inner.entry_capacity)
            .field(
                "entry_pruning_tail_size",
                &self.inner.entry_pruning_tail_size,
            )
            .finish_non_exhaustive()
    }
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
    now: Clock,
}

/// Number of least-recently-used entries a cache scans per `get`,
/// evicting any that are TTL-expired, when the builder leaves it unset.
///
/// Every path in the Dafny implementation uses 1: `LocalCMC`'s constructor default,
/// `StormTracker.DefaultStorm()`, and each `entryPruningTailSize.UnwrapOr(1)`
/// at the create-cache switch.
pub(crate) const CACHE_PRUNING_TAIL_SIZE: usize = 1;

/// The clock a cache reads the current time from.
pub(crate) type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

impl LocalCmc {
    /// Start a builder for `LocalCmc`.
    #[must_use]
    pub fn builder() -> LocalCmcBuilder {
        LocalCmcBuilder::default()
    }

    /// Constructor that accepts an arbitrary clock, shared with
    /// `StormTrackingCmc` so its inner `LocalCmc` reads the same clock.
    pub(crate) fn with_clock(
        entry_capacity: usize,
        entry_pruning_tail_size: usize,
        now: Clock,
    ) -> Self {
        // `NonZeroUsize::new` returns `None` for `0`; the resulting
        // `Option<LruCache>` is `None` for the no-store cache and
        // `Some(LruCache::new(cap))` otherwise.
        let inner = NonZeroUsize::new(entry_capacity).map(LruCache::new);
        Self {
            inner: Arc::new(LocalCmcInner {
                entry_capacity,
                entry_pruning_tail_size,
                store: Mutex::new(inner),
                now,
            }),
        }
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

    /// Look up a fresh entry, pruning the tail and evicting the entry if it
    /// has TTL-expired.
    pub(crate) fn get_fresh(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, Error> {
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
        let is_fresh = cache.peek(cache_id).map(|entry| entry.expiry_time() > now);
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
            .filter(|(_, entry)| entry.expiry_time() <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for cache_id in &to_remove {
            cache.pop(cache_id);
        }
    }
}

/// Builder for [`LocalCmc`], returned by [`LocalCmc::builder`].
#[derive(Clone, Default)]
pub struct LocalCmcBuilder {
    entry_capacity: Option<usize>,
    entry_pruning_tail_size: Option<usize>,
    clock: Option<Clock>,
}

impl std::fmt::Debug for LocalCmcBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCmcBuilder")
            .field("entry_capacity", &self.entry_capacity)
            .field("entry_pruning_tail_size", &self.entry_pruning_tail_size)
            .finish_non_exhaustive()
    }
}

impl LocalCmcBuilder {
    /// Set the maximum number of entries. Required.
    ///
    /// A capacity of `0` yields a no-store cache: `put` is a silent no-op
    /// and `get` always returns `None`.
    #[must_use]
    pub const fn entry_capacity(mut self, n: usize) -> Self {
        self.entry_capacity = Some(n);
        self
    }

    /// Set or clear the maximum number of entries, for forwarding an existing `Option`.
    #[must_use]
    pub const fn set_entry_capacity(mut self, n: Option<usize>) -> Self {
        self.entry_capacity = n;
        self
    }

    /// Set the number of least-recently-used entries each get checks for
    /// expired entries to evict. Defaults to 1.
    #[must_use]
    pub const fn entry_pruning_tail_size(mut self, n: usize) -> Self {
        self.entry_pruning_tail_size = Some(n);
        self
    }

    /// Set or clear `entry_pruning_tail_size`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`entry_pruning_tail_size`](Self::entry_pruning_tail_size).
    #[must_use]
    pub const fn set_entry_pruning_tail_size(mut self, n: Option<usize>) -> Self {
        self.entry_pruning_tail_size = n;
        self
    }

    /// Replace the cache's clock, so tests can fast-forward past entry TTLs
    /// without sleeping. Defaults to `SystemTime::now`.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    #[must_use]
    pub fn clock<F>(mut self, now: F) -> Self
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        self.clock = Some(Arc::new(now));
        self
    }

    /// Construct the cache.
    ///
    /// # Errors
    ///
    /// Returns a [`Kind::Validation`](crate::ErrorKind::Validation)
    /// error if `entry_capacity` is unset.
    pub fn build(self) -> Result<LocalCmc, Error> {
        let Some(entry_capacity) = self.entry_capacity else {
            return Err(Error::new(
                Kind::Validation,
                "an entry capacity is required",
            ));
        };
        Ok(LocalCmc::with_clock(
            entry_capacity,
            self.entry_pruning_tail_size
                .unwrap_or(CACHE_PRUNING_TAIL_SIZE),
            self.clock.unwrap_or_else(|| Arc::new(SystemTime::now)),
        ))
    }
}

#[async_trait]
impl Cmc for LocalCmc {
    async fn put_cache_entry(
        &self,
        input: PutCacheEntryInput,
    ) -> Result<PutCacheEntryOutput, Error> {
        let (identifier, entry) = input.into_parts();
        let mut inner = self
            .inner
            .store
            .lock()
            .map_err(|_| Error::new(Kind::Internal, "cache lock poisoned"))?;
        let Some(cache) = inner.as_mut() else {
            // Zero-capacity cache: never store. Silently drop the entry so
            // the post-condition `len == 0 <= entry_capacity` holds.
            return Ok(PutCacheEntryOutput::default());
        };
        // `LruCache::put` evicts the LRU entry before insertion when the
        // cache is at capacity, keeping `len <= entry_capacity` at all
        // observation points.
        cache.put(identifier, Arc::new(entry));
        Ok(PutCacheEntryOutput::default())
    }

    async fn get_cache_entry(
        &self,
        input: GetCacheEntryInput,
    ) -> Result<GetCacheEntryOutput, Error> {
        GetCacheEntryOutput::builder()
            .set_entry(self.get_fresh(input.identifier())?)
            .build()
    }

    async fn delete_cache_entry(
        &self,
        input: DeleteCacheEntryInput,
    ) -> Result<DeleteCacheEntryOutput, Error> {
        let mut inner = self
            .inner
            .store
            .lock()
            .map_err(|_| Error::new(Kind::Internal, "cache lock poisoned"))?;
        if let Some(cache) = inner.as_mut() {
            cache.pop(input.identifier());
        }
        Ok(DeleteCacheEntryOutput::default())
    }
}
