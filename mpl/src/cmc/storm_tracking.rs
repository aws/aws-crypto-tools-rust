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

use crate::Error;
use crate::error::Kind;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use super::local::{CACHE_PRUNING_TAIL_SIZE, Clock};
use super::{
    CacheEntry, Cmc, DeleteCacheEntryInput, DeleteCacheEntryOutput, GetCacheEntryInput,
    GetCacheEntryOutput, LocalCmc, PutCacheEntryInput, PutCacheEntryOutput,
    UpdateUsageMetadataInput, UpdateUsageMetadataOutput,
};

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
    Ready(Option<CacheEntry>),
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
            .field("in_flight_ttl", &self.inner.in_flight_ttl)
            .field("sleep", &self.inner.sleep)
            .finish_non_exhaustive()
    }
}

struct StormTrackingCmcInner {
    local: crate::shared::Builtin<LocalCmc>,
    grace_period: Duration,
    grace_interval: Duration,
    fan_out: usize,
    in_flight_ttl: Duration,
    sleep: Duration,
    state: Mutex<StormTrackingState>,
    now: Clock,
}

// The defaults match Dafny's `StormTracker.DefaultStorm()`.

/// Default [`StormTrackingCmcBuilder::entry_capacity`].
pub const DEFAULT_STORM_ENTRY_CAPACITY: usize = 1000;
/// Default [`StormTrackingCmcBuilder::grace_period`].
pub const DEFAULT_STORM_GRACE_PERIOD: Duration = Duration::from_secs(10);
/// Default [`StormTrackingCmcBuilder::grace_interval`].
pub const DEFAULT_STORM_GRACE_INTERVAL: Duration = Duration::from_secs(1);
/// Default [`StormTrackingCmcBuilder::fan_out`].
pub const DEFAULT_STORM_FAN_OUT: usize = 20;
/// Default [`StormTrackingCmcBuilder::in_flight_ttl`].
// Not the spec's 20 s, which would break the spec's rule
// "Inflight TTL MUST be less than or equal to the Grace Period" with the 10 s default grace period.
pub const DEFAULT_STORM_INFLIGHT_TTL: Duration = Duration::from_secs(10);
/// Default [`StormTrackingCmcBuilder::sleep`].
pub const DEFAULT_STORM_SLEEP: Duration = Duration::from_millis(20);

/// The error when another caller holds the in-flight slot for this key past `in_flight_ttl`.
/// This is contention, not a fault: the next attempt usually finds the entry filled.
fn in_flight_ttl_exceeded() -> Error {
    Error::new(
        Kind::Throttling,
        "timed out waiting for another caller to fill the cache entry",
    )
    .about(
        None,
        Some(crate::error::Resource::Cache(crate::error::Cache::new())),
    )
}

impl StormTrackingCmc {
    /// Start a builder for `StormTrackingCmc`.
    #[must_use]
    pub fn builder() -> StormTrackingCmcBuilder {
        StormTrackingCmcBuilder::default()
    }

    /// Maximum number of entries the inner [`LocalCmc`] holds.
    #[must_use]
    pub fn entry_capacity(&self) -> usize {
        self.inner.local.entry_capacity()
    }

    /// How many least-recently-used entries each get checks for expired entries to evict.
    #[must_use]
    pub fn entry_pruning_tail_size(&self) -> usize {
        self.inner.local.entry_pruning_tail_size()
    }

    /// How long one caller has to refresh an entry before another caller may try.
    #[must_use]
    pub fn grace_interval(&self) -> Duration {
        self.inner.grace_interval
    }

    /// Maximum number of refreshes in flight at once.
    #[must_use]
    pub fn fan_out(&self) -> usize {
        self.inner.fan_out
    }

    /// How long a caller waits for another caller's refresh before failing.
    #[must_use]
    pub fn in_flight_ttl(&self) -> Duration {
        self.inner.in_flight_ttl
    }

    /// How long a waiting caller sleeps between checks of the cache.
    #[must_use]
    pub fn sleep(&self) -> Duration {
        self.inner.sleep
    }

    /// Borrow the inner `LocalCmc`. Useful in tests to verify that the
    /// wrapper delegates storage to the inner cache.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    #[must_use]
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
    #[must_use]
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
    /// `in_flight_ttl` (skipping `skip_key` so the caller's own TTL check
    /// still fires against a fresh view of that key), and return the guard.
    ///
    /// All non-observability state-touching paths use this helper so
    /// pruning stays uniform across the classifier, the wait loop, and
    /// `put_cache_entry`.
    /// Returns an `Internal` error if the mutex is poisoned.
    fn state_locked(
        &self,
        now: SystemTime,
        skip_key: &[u8],
    ) -> Result<MutexGuard<'_, StormTrackingState>, Error> {
        let mut guard = self
            .inner
            .state
            .lock()
            .map_err(|_| Error::new(Kind::Internal, "cache lock poisoned"))?;
        let ttl = self.inner.in_flight_ttl;
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
        cached: &Option<CacheEntry>,
        now: SystemTime,
    ) -> Result<GetDecision, Error> {
        match cached {
            Some(entry) => {
                // Cache hit.
                if state.inflight.len() >= self.inner.fan_out {
                    // Fan-out saturated: serve the cached entry even if
                    // within the grace period; storm tracking is disabled
                    // until slots free up.
                    return Ok(GetDecision::Ready(Some(entry.clone())));
                }

                if !within_grace_period(entry.expiry_time(), now, self.inner.grace_period) {
                    return Ok(GetDecision::Ready(Some(entry.clone())));
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
                            Ok(GetDecision::Ready(Some(entry.clone())))
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

                        if elapsed > self.inner.in_flight_ttl {
                            return Err(in_flight_ttl_exceeded());
                        }

                        if within_grace_interval(inflight_t, now, self.inner.grace_interval) {
                            // Another thread is fetching; wait until it
                            // completes or its grace interval elapses.
                            // The per-waiter deadline mirrors the Dafny
                            // reference extern: computed once here, checked
                            // each iteration in `wait_for_leader`.
                            Ok(GetDecision::Wait {
                                deadline: Some(now + self.inner.in_flight_ttl),
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
    ) -> Result<Option<CacheEntry>, Error> {
        loop {
            tokio::time::sleep(self.inner.sleep).await;

            if let Some(hit) = self.inner.local.get_fresh(cache_id)? {
                return Ok(Some(hit));
            }

            let now = (self.inner.now)();

            // Per-waiter TTL check (only present for the "key inflight"
            // classification). Fires if this getter has been in the loop
            // longer than `in_flight_ttl`, regardless of the map's current
            // inflight_t.
            if let Some(deadline) = deadline
                && now >= deadline
            {
                return Err(in_flight_ttl_exceeded());
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
/// Every setter is optional; an unset value takes the default documented on its setter.
#[derive(Clone, Default)]
pub struct StormTrackingCmcBuilder {
    entry_capacity: Option<usize>,
    entry_pruning_tail_size: Option<usize>,
    grace_period: Option<Duration>,
    grace_interval: Option<Duration>,
    fan_out: Option<usize>,
    in_flight_ttl: Option<Duration>,
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
            .field("in_flight_ttl", &self.in_flight_ttl)
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

    /// Set how many least-recently-used entries each get checks for expired entries to evict.
    /// Defaults to 1.
    #[must_use]
    pub const fn entry_pruning_tail_size(mut self, n: usize) -> Self {
        self.entry_pruning_tail_size = Some(n);
        self
    }

    /// Set how long before an entry expires the cache sends one caller to refresh it.
    /// Defaults to 10 seconds.
    #[must_use]
    pub const fn grace_period(mut self, d: Duration) -> Self {
        self.grace_period = Some(d);
        self
    }

    /// Set how long one caller has to refresh an entry before another caller may try.
    /// Defaults to 1 second.
    #[must_use]
    pub const fn grace_interval(mut self, d: Duration) -> Self {
        self.grace_interval = Some(d);
        self
    }

    /// Set the maximum number of refreshes in flight at once.
    /// Defaults to 20. Must be at least 1.
    #[must_use]
    pub const fn fan_out(mut self, n: usize) -> Self {
        self.fan_out = Some(n);
        self
    }

    /// Set how long a caller waits for another caller's refresh before failing.
    /// Defaults to 10 seconds.
    #[must_use]
    pub const fn in_flight_ttl(mut self, d: Duration) -> Self {
        self.in_flight_ttl = Some(d);
        self
    }

    /// Set how long a waiting caller sleeps between checks of the cache.
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

    /// The entry capacity, if set.
    #[must_use]
    pub const fn get_entry_capacity(&self) -> &Option<usize> {
        &self.entry_capacity
    }

    /// Set or clear `entry_pruning_tail_size`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`entry_pruning_tail_size`](Self::entry_pruning_tail_size).
    #[must_use]
    pub const fn set_entry_pruning_tail_size(mut self, v: Option<usize>) -> Self {
        self.entry_pruning_tail_size = v;
        self
    }

    /// The entry pruning tail size, if set.
    #[must_use]
    pub const fn get_entry_pruning_tail_size(&self) -> &Option<usize> {
        &self.entry_pruning_tail_size
    }

    /// Set or clear `grace_period`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`grace_period`](Self::grace_period).
    #[must_use]
    pub const fn set_grace_period(mut self, v: Option<Duration>) -> Self {
        self.grace_period = v;
        self
    }

    /// The grace period, if set.
    #[must_use]
    pub const fn get_grace_period(&self) -> &Option<Duration> {
        &self.grace_period
    }

    /// Set or clear `grace_interval`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`grace_interval`](Self::grace_interval).
    #[must_use]
    pub const fn set_grace_interval(mut self, v: Option<Duration>) -> Self {
        self.grace_interval = v;
        self
    }

    /// The grace interval, if set.
    #[must_use]
    pub const fn get_grace_interval(&self) -> &Option<Duration> {
        &self.grace_interval
    }

    /// Set or clear `fan_out`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`fan_out`](Self::fan_out).
    #[must_use]
    pub const fn set_fan_out(mut self, v: Option<usize>) -> Self {
        self.fan_out = v;
        self
    }

    /// The fan-out, if set.
    #[must_use]
    pub const fn get_fan_out(&self) -> &Option<usize> {
        &self.fan_out
    }

    /// Set or clear `in_flight_ttl`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`in_flight_ttl`](Self::in_flight_ttl).
    #[must_use]
    pub const fn set_in_flight_ttl(mut self, v: Option<Duration>) -> Self {
        self.in_flight_ttl = v;
        self
    }

    /// The inflight TTL, if set.
    #[must_use]
    pub const fn get_in_flight_ttl(&self) -> &Option<Duration> {
        &self.in_flight_ttl
    }

    /// Set or clear `sleep`, for forwarding an existing `Option`.
    /// `None` applies the default documented on [`sleep`](Self::sleep).
    #[must_use]
    pub const fn set_sleep(mut self, v: Option<Duration>) -> Self {
        self.sleep = v;
        self
    }

    /// The sleep duration, if set.
    #[must_use]
    pub const fn get_sleep(&self) -> &Option<Duration> {
        &self.sleep
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

    /// Construct the cache.
    ///
    /// # Errors
    ///
    /// Returns a validation error ([`Error::is_validation`]) if:
    /// - `fan_out`, `in_flight_ttl`, or `sleep` is 0, or
    /// - `grace_interval` exceeds `in_flight_ttl`.
    pub fn build(self) -> Result<StormTrackingCmc, Error> {
        let fan_out = self.fan_out.unwrap_or(DEFAULT_STORM_FAN_OUT);
        let grace_period = self.grace_period.unwrap_or(DEFAULT_STORM_GRACE_PERIOD);
        let grace_interval = self.grace_interval.unwrap_or(DEFAULT_STORM_GRACE_INTERVAL);
        let in_flight_ttl = self.in_flight_ttl.unwrap_or(DEFAULT_STORM_INFLIGHT_TTL);
        let sleep = self.sleep.unwrap_or(DEFAULT_STORM_SLEEP);

        if fan_out == 0 {
            return Err(invalid("fan_out must be at least 1"));
        }
        if in_flight_ttl.is_zero() {
            return Err(invalid("in_flight_ttl must be greater than zero"));
        }
        if sleep.is_zero() {
            return Err(invalid("sleep must be greater than zero"));
        }
        if grace_interval > in_flight_ttl {
            return Err(invalid(format!(
                "grace_interval ({grace_interval:?}) must be less than or equal to in_flight_ttl ({in_flight_ttl:?})"
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
                local: crate::shared::Builtin(local),
                grace_period,
                grace_interval,
                fan_out,
                in_flight_ttl,
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
    Error::new(Kind::Validation, message)
}

/// Returns `true` if `now` is within the grace period for an entry expiring
/// at `expiry`.
///
/// Spec formula: `(expiry - gracePeriod) <= now`
pub(crate) fn within_grace_period(
    expiry: SystemTime,
    now: SystemTime,
    grace_period: Duration,
) -> bool {
    expiry
        .checked_sub(grace_period)
        .is_none_or(|threshold| threshold <= now)
}

/// Returns `true` if `now` is within the grace interval of an inflight entry
/// that was first marked at `inflight`.
///
/// Spec formula: `now < (inflight + graceInterval)`
pub(crate) fn within_grace_interval(
    inflight: SystemTime,
    now: SystemTime,
    grace_interval: Duration,
) -> bool {
    now < inflight + grace_interval
}

/// Storm-tracking internals reachable from integration tests.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod __test_internals {
    use std::time::{Duration, SystemTime};

    /// See `within_grace_period`.
    pub fn within_grace_period(
        expiry: SystemTime,
        now: SystemTime,
        grace_period: Duration,
    ) -> bool {
        super::within_grace_period(expiry, now, grace_period)
    }

    /// See `within_grace_interval`.
    pub fn within_grace_interval(
        inflight: SystemTime,
        now: SystemTime,
        grace_interval: Duration,
    ) -> bool {
        super::within_grace_interval(inflight, now, grace_interval)
    }
}

#[async_trait]
impl Cmc for crate::shared::Builtin<StormTrackingCmc> {
    async fn put_cache_entry(
        &self,
        input: PutCacheEntryInput,
    ) -> Result<PutCacheEntryOutput, Error> {
        let cache_id = input.identifier().to_vec();
        // Write to the inner cache FIRST, then clear inflight. Reversing
        // this order opens a race window where a blocked getter can
        // observe `cache miss + not inflight` between the two operations
        // and start a redundant refresh — defeating storm-tracking
        // coalescing. It also preserves inflight state if the inner put
        // fails, so a failed refresh doesn't lose the leader signal.
        Cmc::put_cache_entry(&self.inner.local, input).await?;

        let now = (self.inner.now)();
        let mut state = self.state_locked(now, &cache_id)?;
        state.inflight.remove(&cache_id);
        Ok(PutCacheEntryOutput::default())
    }

    async fn get_cache_entry(
        &self,
        input: GetCacheEntryInput,
    ) -> Result<GetCacheEntryOutput, Error> {
        let cache_id = input.identifier();
        let cached = self.inner.local.get_fresh(cache_id)?;
        let now = (self.inner.now)();

        // Classify with the lock held; drop the lock before any await.
        let decision = {
            let mut state = self.state_locked(now, cache_id)?;
            self.classify_and_mark(&mut state, cache_id, &cached, now)?
        };

        let entry = match decision {
            GetDecision::Ready(opt) => opt,
            GetDecision::Wait { deadline } => self.wait_for_leader(cache_id, deadline).await?,
        };
        GetCacheEntryOutput::builder().set_entry(entry).build()
    }

    async fn delete_cache_entry(
        &self,
        input: DeleteCacheEntryInput,
    ) -> Result<DeleteCacheEntryOutput, Error> {
        Cmc::delete_cache_entry(&self.inner.local, input).await
    }

    async fn update_usage_metadata(
        &self,
        input: UpdateUsageMetadataInput,
    ) -> Result<UpdateUsageMetadataOutput, Error> {
        Cmc::update_usage_metadata(&self.inner.local, input).await
    }

    fn grace_period(&self) -> Option<Duration> {
        self.0.grace_period()
    }
}

impl StormTrackingCmc {
    /// How long before an entry expires the cache starts refreshing it.
    #[must_use]
    pub fn grace_period(&self) -> Option<Duration> {
        Some(self.inner.grace_period)
    }
}
