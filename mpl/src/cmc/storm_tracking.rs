// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Storm-tracking Cryptographic Materials Cache — thread-safe wrapper around
//! `LocalCmc` that prevents cache-miss stampedes via per-key inflight tracking.
//!
//! `StormTrackingCmc` wraps a `LocalCmc` and adds storm-tracking semantics:
//! when an entry is close to expiry (within the grace period) it returns
//! `NoSuchEntry` to one thread (marking the key "inflight") and serves the
//! existing cached materials to all other threads within the grace interval.
//! This prevents many threads from simultaneously refreshing the same key.
//!
//! Concurrency model: a single Mutex lock guards the inflight map.
//! The lock is for the whole map, not per-key, and the lock
//! is never held across `.await`.
//!
//! `get_cache_entry` runs in two phases: (1) call the inner
//! `LocalCmc` (which has its own separate `Mutex`, so there is no nested
//! locking and no deadlock between the two caches); then (2) take the
//! storm-tracking mutex just long enough to classify the request into
//! either an immediate result or a `Wait` action. The waiting branch,
//! `wait_for_leader`, polls in a loop that re-acquires the mutex briefly on
//! each iteration to check whether this waiter can now become the next
//! refresh leader, releasing it before the next sleep, so a thread waiting
//! to refresh key A does not block a lookup for key B.
//! Cached entries are handed out as clones,
//! so no materials data is copied under the lock.
//!
//! Runtime requirement: `wait_for_leader` calls `tokio::time::sleep`, which
//! requires an active Tokio runtime. Callers using a different async runtime
//! (e.g. `async-std`, `smol`) will hit a runtime panic when a get triggers
//! the blocking path.

use crate::{Error, ErrorKind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use super::local::{CACHE_PRUNING_TAIL_SIZE, Clock};
use super::{CacheEntry, Cmc, LocalCmc};

/// Per-key inflight tracking state, held under a `Mutex`.
struct StormTrackingState {
    /// Maps cache-id → the wall-clock instant the most recent `NoSuchEntry`
    /// was returned for that key.
    inflight: HashMap<Vec<u8>, SystemTime>,
}

/// The action to take after classification under the lock.
enum GetDecision {
    /// Return this value immediately from `get_cache_entry`. `Some(e)` is a
    /// cache hit; `None` is "NoSuchEntry" (with the key already marked
    /// inflight if the classifier decided a new refresh leader was needed).
    Ready(Option<Arc<CacheEntry>>),
    /// Enter the polling loop. `deadline = Some(_)` gives this waiter a
    /// per-waiter TTL. `deadline = None` is the "cache miss,
    /// key not inflight, fan-out saturated" case — the waiter holds no
    /// leader slot, so it has no per-waiter TTL and gives up only when the
    /// caller times out.
    Wait { deadline: Option<SystemTime> },
}

/// Storm-tracking Cryptographic Materials Cache.
///
/// Wraps a [`LocalCmc`] and adds grace-period / grace-interval storm
/// protection.  See the module-level docs and
/// `spec/framework/storm-tracking-cryptographic-materials-cache.md` for the
/// full behavioral specification.
#[derive(Clone)]
pub struct StormTrackingCmc {
    inner: Arc<StormTrackingCmcInner>,
}

impl std::fmt::Debug for StormTrackingCmc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StormTrackingCmc")
            .field("entry_capacity", &self.entry_capacity())
            .field("entry_pruning_tail_size", &self.entry_pruning_tail_size())
            .field("grace_period", &self.inner.grace_period)
            .field("grace_interval", &self.inner.grace_interval)
            .field("fan_out", &self.inner.fan_out)
            .field("inflight_ttl", &self.inner.inflight_ttl)
            .field("sleep", &self.inner.sleep)
            .finish_non_exhaustive()
    }
}

struct StormTrackingCmcInner {
    local: LocalCmc,
    grace_period: Duration,
    grace_interval: Duration,
    fan_out: usize,
    inflight_ttl: Duration,
    sleep: Duration,
    state: Mutex<StormTrackingState>,
    now: Clock,
}

/// Default [`StormTrackingCmcBuilder::entry_capacity`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_ENTRY_CAPACITY: usize = 1000;
/// Default [`StormTrackingCmcBuilder::grace_period`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_GRACE_PERIOD: Duration = Duration::from_secs(10);
/// Default [`StormTrackingCmcBuilder::grace_interval`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_GRACE_INTERVAL: Duration = Duration::from_secs(1);
/// Default [`StormTrackingCmcBuilder::fan_out`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_FAN_OUT: usize = 20;
/// Default [`StormTrackingCmcBuilder::inflight_ttl`], from Dafny's
/// `StormTracker.DefaultStorm()`.
///
/// The spec lists 20, which exceeds the default grace period
/// and so breaks the spec's own "Inflight TTL MUST be less than or equal to the Grace Period" rule.
pub const DEFAULT_STORM_INFLIGHT_TTL: Duration = Duration::from_secs(10);
/// Default [`StormTrackingCmcBuilder::sleep`], from Dafny's
/// `StormTracker.DefaultStorm()`.
pub const DEFAULT_STORM_SLEEP: Duration = Duration::from_millis(20);

impl StormTrackingCmc {
    /// Start a builder for `StormTrackingCmc`. Every setter is optional.
    #[must_use]
    pub fn builder() -> StormTrackingCmcBuilder {
        StormTrackingCmcBuilder::default()
    }

    /// Maximum number of entries the inner [`LocalCmc`] holds.
    pub fn entry_capacity(&self) -> usize {
        self.inner.local.entry_capacity()
    }

    /// Number of least-recently-used entries each get checks for expired
    /// entries to evict.
    pub fn entry_pruning_tail_size(&self) -> usize {
        self.inner.local.entry_pruning_tail_size()
    }

    /// Window before expiry during which the cache attempts a refresh.
    pub fn grace_period(&self) -> Duration {
        self.inner.grace_period
    }

    /// Time after which an inflight refresh is no longer considered
    /// inflight.
    pub fn grace_interval(&self) -> Duration {
        self.inner.grace_interval
    }

    /// Maximum number of keys that can have a refresh inflight at once.
    pub fn fan_out(&self) -> usize {
        self.inner.fan_out
    }

    /// Time a waiting request may stay inflight before it fails.
    pub fn inflight_ttl(&self) -> Duration {
        self.inner.inflight_ttl
    }

    /// Time a blocked request sleeps before reexamining the cache.
    pub fn sleep(&self) -> Duration {
        self.inner.sleep
    }

    /// Borrow the inner `LocalCmc`. Useful in tests to verify that the
    /// wrapper delegates storage to the inner cache.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn inner(&self) -> &LocalCmc {
        &self.inner.local
    }

    /// Peek the inflight map for `cache_id`. Returns the most recent time
    /// a `NoSuchEntry` was returned for that key, or `None` if the key is
    /// not currently inflight. Exposed for test observability; does NOT
    /// prune stale entries, so tests see the raw map state.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn peek_inflight(&self, cache_id: &[u8]) -> Option<SystemTime> {
        let state = self
            .inner
            .state
            .lock()
            .expect("StormTrackingCmc lock poisoned");
        state.inflight.get(cache_id).copied()
    }

    /// Number of currently inflight keys. Exposed for test observability;
    /// does NOT prune stale entries.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn inflight_count(&self) -> usize {
        let state = self
            .inner
            .state
            .lock()
            .expect("StormTrackingCmc lock poisoned");
        state.inflight.len()
    }

    /// Directly insert an inflight entry at a given time. Exposed for tests
    /// to pre-populate the inflight map without going through
    /// `get_cache_entry`.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn mark_inflight(&self, cache_id: &[u8], when: SystemTime) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("StormTrackingCmc lock poisoned");
        state.inflight.insert(cache_id.to_vec(), when);
    }

    /// Acquire the state mutex, prune inflight entries that have exceeded
    /// `inflight_ttl` (skipping `skip_key` so the caller's own TTL check
    /// still fires against a fresh view of that key), and return the guard.
    ///
    /// All non-observability state-touching paths use this helper so
    /// pruning stays uniform across the classifier, the wait loop, and
    /// `put_cache_entry`. Poisoned-mutex errors are surfaced as
    /// `Error::storage_failed` instead of panics.
    fn state_locked(
        &self,
        now: SystemTime,
        skip_key: &[u8],
    ) -> Result<MutexGuard<'_, StormTrackingState>, Error> {
        let mut guard = self.inner.state.lock().map_err(|e| {
            Error::new(
                ErrorKind::Internal,
                format!("StormTrackingCmc lock poisoned: {e}"),
            )
        })?;
        let ttl = self.inner.inflight_ttl;
        guard.inflight.retain(|k, t| {
            k.as_slice() == skip_key
                || now
                    .duration_since(*t)
                    .map_or(true, |elapsed| elapsed <= ttl)
        });
        Ok(guard)
    }

    /// Classify a `get_cache_entry` call under the (already-locked) state
    /// mutex, mutating `state.inflight` as needed, and return the action
    /// to take. This is not a pure function: the `Ready(None)` branches
    /// insert into `state.inflight` first, marking this getter as the
    /// current refresh leader.
    fn classify_and_mark(
        &self,
        state: &mut StormTrackingState,
        cache_id: &[u8],
        cached: &Option<Arc<CacheEntry>>,
        now: SystemTime,
    ) -> Result<GetDecision, Error> {
        match cached {
            Some(entry) => {
                // Cache hit.
                if state.inflight.len() >= self.inner.fan_out {
                    // Fan-out saturated: serve the cached entry even if
                    // within the grace period; storm tracking is disabled
                    // until slots free up.
                    return Ok(GetDecision::Ready(Some(Arc::clone(entry))));
                }

                if !within_grace_period(entry.expiry_time, now, self.inner.grace_period) {
                    return Ok(GetDecision::Ready(Some(Arc::clone(entry))));
                }

                match state.inflight.get(cache_id).copied() {
                    None => {
                        // Within grace period, not inflight: this getter
                        // is the new refresh leader.
                        state.inflight.insert(cache_id.to_vec(), now);
                        Ok(GetDecision::Ready(None))
                    }
                    Some(inflight_t) => {
                        if within_grace_interval(inflight_t, now, self.inner.grace_interval) {
                            // Another thread is already refreshing; serve
                            // the cached copy.
                            Ok(GetDecision::Ready(Some(Arc::clone(entry))))
                        } else {
                            // Grace interval elapsed since the last leader
                            // was marked; take the leader slot.
                            state.inflight.insert(cache_id.to_vec(), now);
                            Ok(GetDecision::Ready(None))
                        }
                    }
                }
            }
            None => {
                // Cache miss.
                match state.inflight.get(cache_id).copied() {
                    None => {
                        if state.inflight.len() >= self.inner.fan_out {
                            // No slot; do not mark inflight yet — the wait
                            // loop will mark once a slot opens.
                            Ok(GetDecision::Wait { deadline: None })
                        } else {
                            state.inflight.insert(cache_id.to_vec(), now);
                            Ok(GetDecision::Ready(None))
                        }
                    }
                    Some(inflight_t) => {
                        let elapsed = now.duration_since(inflight_t).unwrap_or(Duration::ZERO);

                        if elapsed > self.inner.inflight_ttl {
                            return Err(Error::new(ErrorKind::Internal, "InFlightTTL exceeded"));
                        }

                        if within_grace_interval(inflight_t, now, self.inner.grace_interval) {
                            // Another thread is fetching; wait until it
                            // completes or its grace interval elapses.
                            // The per-waiter deadline mirrors the Dafny
                            // reference extern: computed once here, checked
                            // each iteration in `wait_for_leader`.
                            Ok(GetDecision::Wait {
                                deadline: Some(now + self.inner.inflight_ttl),
                            })
                        } else {
                            // Grace interval elapsed; take the leader slot.
                            state.inflight.insert(cache_id.to_vec(), now);
                            Ok(GetDecision::Ready(None))
                        }
                    }
                }
            }
        }
    }

    /// Poll until this waiter can either (a) return a fresh cache entry
    /// (some leader completed its refresh), (b) become the next refresh
    /// leader, or (c) fail because its per-waiter deadline has elapsed.
    ///
    /// A waiter becomes leader when the fan-out has an open slot AND the
    /// key is either no longer inflight or its grace interval has elapsed.
    /// This unified condition covers both entry classifications:
    ///
    /// - "cache miss, key not inflight, fan-out saturated" (`deadline =
    ///   None`): the key is not in the inflight map when the waiter
    ///   entered, so the leader-permitted check trivially passes and the
    ///   condition reduces to `slot_open`.
    /// - "cache miss, key inflight, within grace interval" (`deadline =
    ///   Some(_)`): both parts of the condition must hold.
    async fn wait_for_leader(
        &self,
        cache_id: &[u8],
        deadline: Option<SystemTime>,
    ) -> Result<Option<Arc<CacheEntry>>, Error> {
        loop {
            tokio::time::sleep(self.inner.sleep).await;

            if let Some(hit) = self.inner.local.get_cache_entry(cache_id).await? {
                return Ok(Some(hit));
            }

            let now = (self.inner.now)();

            // Per-waiter TTL check (only present for the "key inflight"
            // classification). Fires if this getter has been in the loop
            // longer than `inflight_ttl`, regardless of the map's current
            // inflight_t.
            if let Some(deadline) = deadline
                && now >= deadline
            {
                return Err(Error::new(ErrorKind::Internal, "InFlightTTL exceeded"));
            }

            // Re-classify per Dafny `CheckNewEntry`: become leader when
            // fan-out has space AND (key not inflight OR grace interval
            // elapsed). Prune runs inside `state_locked` so the fan-out
            // check reflects live state.
            let mut state = self.state_locked(now, cache_id)?;
            let slot_open = state.inflight.len() < self.inner.fan_out;
            let leader_permitted = state
                .inflight
                .get(cache_id)
                .copied()
                .is_none_or(|t| !within_grace_interval(t, now, self.inner.grace_interval));

            if slot_open && leader_permitted {
                state.inflight.insert(cache_id.to_vec(), now);
                return Ok(None);
            }
        }
    }
}

/// Builder for [`StormTrackingCmc`], returned by [`StormTrackingCmc::builder`].
/// Every setter is optional;
/// [`build`](Self::build) applies the default documented on each setter to any value left unset.
#[derive(Clone, Default)]
pub struct StormTrackingCmcBuilder {
    entry_capacity: Option<usize>,
    entry_pruning_tail_size: Option<usize>,
    grace_period: Option<Duration>,
    grace_interval: Option<Duration>,
    fan_out: Option<usize>,
    inflight_ttl: Option<Duration>,
    sleep: Option<Duration>,
    clock: Option<Clock>,
}

impl std::fmt::Debug for StormTrackingCmcBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StormTrackingCmcBuilder")
            .field("entry_capacity", &self.entry_capacity)
            .field("entry_pruning_tail_size", &self.entry_pruning_tail_size)
            .field("grace_period", &self.grace_period)
            .field("grace_interval", &self.grace_interval)
            .field("fan_out", &self.fan_out)
            .field("inflight_ttl", &self.inflight_ttl)
            .field("sleep", &self.sleep)
            .finish_non_exhaustive()
    }
}

impl StormTrackingCmcBuilder {
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

    /// Replace the cache's clock, so tests can advance time without sleeping.
    /// Defaults to `SystemTime::now`.
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

    /// Apply defaults, validate the settings, and construct the cache.
    ///
    /// # Errors
    ///
    /// Returns a [`ErrorKind::Validation`](crate::ErrorKind::Validation) error if:
    /// - `fan_out`, `inflight_ttl`, or `sleep` is 0, or
    /// - `grace_interval` exceeds `inflight_ttl`.
    pub fn build(self) -> Result<StormTrackingCmc, Error> {
        let fan_out = self.fan_out.unwrap_or(DEFAULT_STORM_FAN_OUT);
        let grace_period = self.grace_period.unwrap_or(DEFAULT_STORM_GRACE_PERIOD);
        let grace_interval = self.grace_interval.unwrap_or(DEFAULT_STORM_GRACE_INTERVAL);
        let inflight_ttl = self.inflight_ttl.unwrap_or(DEFAULT_STORM_INFLIGHT_TTL);
        let sleep = self.sleep.unwrap_or(DEFAULT_STORM_SLEEP);

        if fan_out == 0 {
            return Err(invalid("fan_out must be at least 1"));
        }
        if inflight_ttl.is_zero() {
            return Err(invalid("inflight_ttl must be greater than zero"));
        }
        if sleep.is_zero() {
            return Err(invalid("sleep must be greater than zero"));
        }
        if grace_interval > inflight_ttl {
            return Err(invalid(format!(
                "grace_interval ({grace_interval:?}) must be less than or equal to inflight_ttl ({inflight_ttl:?})"
            )));
        }

        let now = self.clock.unwrap_or_else(|| Arc::new(SystemTime::now));
        let local = LocalCmc::with_clock(
            self.entry_capacity.unwrap_or(DEFAULT_STORM_ENTRY_CAPACITY),
            self.entry_pruning_tail_size
                .unwrap_or(CACHE_PRUNING_TAIL_SIZE),
            Arc::clone(&now),
        );

        Ok(StormTrackingCmc {
            inner: Arc::new(StormTrackingCmcInner {
                local,
                grace_period,
                grace_interval,
                fan_out,
                inflight_ttl,
                sleep,
                state: Mutex::new(StormTrackingState {
                    inflight: HashMap::new(),
                }),
                now,
            }),
        })
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(
        ErrorKind::Validation,
        format!("StormTrackingCmc: {}", message.into()),
    )
}

/// Returns `true` if `now` is within the grace period for an entry expiring
/// at `expiry`.
///
/// Spec formula: `(expiry - gracePeriod) <= now`
pub fn within_grace_period(expiry: SystemTime, now: SystemTime, grace_period: Duration) -> bool {
    expiry
        .checked_sub(grace_period)
        .is_none_or(|threshold| threshold <= now)
}

/// Returns `true` if `now` is within the grace interval of an inflight entry
/// that was first marked at `inflight`.
///
/// Spec formula: `now < (inflight + graceInterval)`
pub fn within_grace_interval(
    inflight: SystemTime,
    now: SystemTime,
    grace_interval: Duration,
) -> bool {
    now < inflight + grace_interval
}

#[async_trait]
impl Cmc for StormTrackingCmc {
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), Error> {
        // Write to the inner cache FIRST, then clear inflight. Reversing
        // this order opens a race window where a blocked getter can
        // observe `cache miss + not inflight` between the two operations
        // and start a redundant refresh — defeating storm-tracking
        // coalescing. It also preserves inflight state if the inner put
        // fails, so a failed refresh doesn't lose the leader signal.
        self.inner.local.put_cache_entry(cache_id, entry).await?;

        let now = (self.inner.now)();
        let mut state = self.state_locked(now, cache_id)?;
        state.inflight.remove(cache_id);
        Ok(())
    }

    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, Error> {
        let cached = self.inner.local.get_cache_entry(cache_id).await?;
        let now = (self.inner.now)();

        // Classify with the lock held; drop the lock before any await.
        let decision = {
            let mut state = self.state_locked(now, cache_id)?;
            self.classify_and_mark(&mut state, cache_id, &cached, now)?
        };

        match decision {
            GetDecision::Ready(opt) => Ok(opt),
            GetDecision::Wait { deadline } => self.wait_for_leader(cache_id, deadline).await,
        }
    }

    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), Error> {
        self.inner.local.delete_cache_entry(cache_id).await
    }

    fn grace_period(&self) -> Option<Duration> {
        Some(self.inner.grace_period)
    }
}
