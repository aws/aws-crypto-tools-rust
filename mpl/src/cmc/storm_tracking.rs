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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use super::{CacheEntry, Cmc, CmcError, LocalCmc};

/// Which unit the caller uses for the numeric time knobs.
///
/// Applies to `grace_period`, `grace_interval`, and `inflight_ttl`.
/// Does NOT apply to `sleep_milli` (always milliseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeUnits {
    /// Interpret numeric values as seconds (the default).
    #[default]
    Seconds,
    /// Interpret numeric values as milliseconds.
    Milliseconds,
}

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
    /// per-waiter TTL, mirroring the Dafny reference extern
    /// `StormTrackingCMC.cs` (`max_in_flight = DateTime.Now + inFlightTTL`
    /// computed once at loop entry). `deadline = None` is the "cache miss,
    /// key not inflight, fan-out saturated" case — the waiter holds no
    /// leader slot, so it has no per-waiter TTL and gives up only when the
    /// caller times out.
    Wait { deadline: Option<SystemTime> },
}

/// The result of validating and interpreting a raw `StormTrackingCmc` config.
struct ValidatedConfig {
    grace_period: Duration,
    grace_interval: Duration,
    inflight_ttl: Duration,
    sleep_milli: Duration,
    fan_out: usize,
    time_units: TimeUnits,
}

impl ValidatedConfig {
    /// Validate raw config values and produce the interpreted `Duration`s.
    ///
    /// Spec: `grace_period`, `grace_interval`, `inflight_ttl`, `sleep_milli`,
    /// and `fan_out` all MUST be at least 1. Enforcing these lower bounds
    /// up front turns silent runtime pathologies (deadlocks, hot spins,
    /// spurious InFlightTTL errors, storm tracking that never engages) into
    /// caller-visible validation errors.
    fn from_raw(
        grace_period: u64,
        grace_interval: u64,
        fan_out: usize,
        inflight_ttl: u64,
        sleep_milli: u64,
        time_units: Option<TimeUnits>,
    ) -> Result<Self, CmcError> {
        let time_units = time_units.unwrap_or_default();
        let to_duration = |v: u64| -> Duration {
            match time_units {
                TimeUnits::Seconds => Duration::from_secs(v),
                TimeUnits::Milliseconds => Duration::from_millis(v),
            }
        };

        // Lower bounds.
        if grace_period == 0 {
            return Err(CmcError::invalid_entry("grace_period must be at least 1"));
        }
        if grace_interval == 0 {
            return Err(CmcError::invalid_entry("grace_interval must be at least 1"));
        }
        if inflight_ttl == 0 {
            return Err(CmcError::invalid_entry("inflight_ttl must be at least 1"));
        }
        if fan_out == 0 {
            return Err(CmcError::invalid_entry("fan_out must be at least 1"));
        }
        if sleep_milli == 0 {
            return Err(CmcError::invalid_entry("sleep_milli must be at least 1"));
        }

        let grace_period = to_duration(grace_period);
        let grace_interval = to_duration(grace_interval);
        let inflight_ttl = to_duration(inflight_ttl);

        // Ordering: grace_interval <= inflight_ttl <= grace_period.
        if grace_interval > grace_period {
            return Err(CmcError::invalid_entry(
                "grace_interval must be <= grace_period",
            ));
        }
        if inflight_ttl > grace_period {
            return Err(CmcError::invalid_entry(
                "inflight_ttl must be <= grace_period",
            ));
        }
        if grace_interval > inflight_ttl {
            return Err(CmcError::invalid_entry(
                "grace_interval must be <= inflight_ttl",
            ));
        }

        Ok(Self {
            grace_period,
            grace_interval,
            inflight_ttl,
            sleep_milli: Duration::from_millis(sleep_milli),
            fan_out,
            time_units,
        })
    }
}

/// Storm-tracking Cryptographic Materials Cache.
///
/// Wraps a [`LocalCmc`] and adds grace-period / grace-interval storm
/// protection.  See the module-level docs and
/// `spec/framework/storm-tracking-cryptographic-materials-cache.md` for the
/// full behavioral specification.
pub struct StormTrackingCmc {
    inner: LocalCmc,
    grace_period: Duration,
    grace_interval: Duration,
    fan_out: usize,
    inflight_ttl: Duration,
    sleep_milli: Duration,
    time_units: TimeUnits,
    state: Mutex<StormTrackingState>,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl StormTrackingCmc {
    /// Construct a `StormTrackingCmc` using `SystemTime::now` as the clock.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entry_capacity: usize,
        entry_pruning_tail_size: usize,
        grace_period: u64,
        grace_interval: u64,
        fan_out: usize,
        inflight_ttl: u64,
        sleep_milli: u64,
        time_units: Option<TimeUnits>,
    ) -> Result<Self, CmcError> {
        Self::with_clock_impl(
            entry_capacity,
            entry_pruning_tail_size,
            grace_period,
            grace_interval,
            fan_out,
            inflight_ttl,
            sleep_milli,
            time_units,
            SystemTime::now,
        )
    }

    /// Test-only constructor with clock injection. Gated behind the
    /// `test-utils` feature so it is not exposed to library consumers.
    /// Tests use this to advance time deterministically without sleeping.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn with_clock<F>(
        entry_capacity: usize,
        entry_pruning_tail_size: usize,
        grace_period: u64,
        grace_interval: u64,
        fan_out: usize,
        inflight_ttl: u64,
        sleep_milli: u64,
        time_units: Option<TimeUnits>,
        now: F,
    ) -> Result<Self, CmcError>
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        Self::with_clock_impl(
            entry_capacity,
            entry_pruning_tail_size,
            grace_period,
            grace_interval,
            fan_out,
            inflight_ttl,
            sleep_milli,
            time_units,
            now,
        )
    }

    /// Internal constructor that accepts an arbitrary clock. `pub(crate)`
    /// to mirror `LocalCmc::with_clock_impl`'s visibility for consistency
    /// across the two cache implementations; not part of the public API.
    /// Callers use `new` (production) or `with_clock` (test-utils feature).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_clock_impl<F>(
        entry_capacity: usize,
        entry_pruning_tail_size: usize,
        grace_period: u64,
        grace_interval: u64,
        fan_out: usize,
        inflight_ttl: u64,
        sleep_milli: u64,
        time_units: Option<TimeUnits>,
        now: F,
    ) -> Result<Self, CmcError>
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        let cfg = ValidatedConfig::from_raw(
            grace_period,
            grace_interval,
            fan_out,
            inflight_ttl,
            sleep_milli,
            time_units,
        )?;

        let now_arc: Arc<dyn Fn() -> SystemTime + Send + Sync> = Arc::new(now);
        let inner_clock = Arc::clone(&now_arc);

        let inner =
            LocalCmc::with_clock_impl(entry_capacity, entry_pruning_tail_size, move || {
                inner_clock()
            })?;

        Ok(Self {
            inner,
            grace_period: cfg.grace_period,
            grace_interval: cfg.grace_interval,
            fan_out: cfg.fan_out,
            inflight_ttl: cfg.inflight_ttl,
            sleep_milli: cfg.sleep_milli,
            time_units: cfg.time_units,
            state: Mutex::new(StormTrackingState {
                inflight: HashMap::new(),
            }),
            now: now_arc,
        })
    }

    /// The configured grace period as a `Duration`.
    pub fn grace_period(&self) -> Duration {
        self.grace_period
    }

    /// The configured grace interval as a `Duration`.
    pub fn grace_interval(&self) -> Duration {
        self.grace_interval
    }

    /// The configured fan-out limit.
    pub fn fan_out(&self) -> usize {
        self.fan_out
    }

    /// The configured inflight TTL as a `Duration`.
    pub fn inflight_ttl(&self) -> Duration {
        self.inflight_ttl
    }

    /// The configured sleep-between-polls duration (always milliseconds).
    pub fn sleep_milli(&self) -> Duration {
        self.sleep_milli
    }

    /// The configured time units.
    pub fn time_units(&self) -> TimeUnits {
        self.time_units
    }

    /// Borrow the inner `LocalCmc`. Useful in tests to verify that the
    /// wrapper delegates storage to the inner cache.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn inner(&self) -> &LocalCmc {
        &self.inner
    }

    /// Peek the inflight map for `cache_id`. Returns the most recent time
    /// a `NoSuchEntry` was returned for that key, or `None` if the key is
    /// not currently inflight. Exposed for test observability; does NOT
    /// prune stale entries, so tests see the raw map state.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn peek_inflight(&self, cache_id: &[u8]) -> Option<SystemTime> {
        let state = self.state.lock().expect("StormTrackingCmc lock poisoned");
        state.inflight.get(cache_id).copied()
    }

    /// Number of currently inflight keys. Exposed for test observability;
    /// does NOT prune stale entries.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn inflight_count(&self) -> usize {
        let state = self.state.lock().expect("StormTrackingCmc lock poisoned");
        state.inflight.len()
    }

    /// Directly insert an inflight entry at a given time. Exposed for tests
    /// to pre-populate the inflight map without going through
    /// `get_cache_entry`.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn mark_inflight(&self, cache_id: &[u8], when: SystemTime) {
        let mut state = self.state.lock().expect("StormTrackingCmc lock poisoned");
        state.inflight.insert(cache_id.to_vec(), when);
    }

    /// Acquire the state mutex, prune inflight entries that have exceeded
    /// `inflight_ttl` (skipping `skip_key` so the caller's own TTL check
    /// still fires against a fresh view of that key), and return the guard.
    ///
    /// All non-observability state-touching paths use this helper so
    /// pruning stays uniform across the classifier, the wait loop, and
    /// `put_cache_entry`. Poisoned-mutex errors are surfaced as
    /// `CmcError::storage_failed` instead of panics.
    fn state_locked(
        &self,
        now: SystemTime,
        skip_key: &[u8],
    ) -> Result<MutexGuard<'_, StormTrackingState>, CmcError> {
        let mut guard = self.state.lock().map_err(|e| {
            CmcError::storage_failed(format!("StormTrackingCmc lock poisoned: {e}"))
        })?;
        let ttl = self.inflight_ttl;
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
    ) -> Result<GetDecision, CmcError> {
        match cached {
            Some(entry) => {
                // Cache hit.
                if state.inflight.len() >= self.fan_out {
                    // Fan-out saturated: serve the cached entry even if
                    // within the grace period; storm tracking is disabled
                    // until slots free up.
                    return Ok(GetDecision::Ready(Some(Arc::clone(entry))));
                }

                if !within_grace_period(entry.expiry_time, now, self.grace_period) {
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
                        if within_grace_interval(inflight_t, now, self.grace_interval) {
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
                        if state.inflight.len() >= self.fan_out {
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

                        if elapsed > self.inflight_ttl {
                            return Err(CmcError::storage_failed("InFlightTTL exceeded"));
                        }

                        if within_grace_interval(inflight_t, now, self.grace_interval) {
                            // Another thread is fetching; wait until it
                            // completes or its grace interval elapses.
                            // The per-waiter deadline mirrors the Dafny
                            // reference extern: computed once here, checked
                            // each iteration in `wait_for_leader`.
                            Ok(GetDecision::Wait {
                                deadline: Some(now + self.inflight_ttl),
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
    ) -> Result<Option<Arc<CacheEntry>>, CmcError> {
        loop {
            tokio::time::sleep(self.sleep_milli).await;

            if let Some(hit) = self.inner.get_cache_entry(cache_id).await? {
                return Ok(Some(hit));
            }

            let now = (self.now)();

            // Per-waiter TTL check (only present for the "key inflight"
            // classification). Fires if this getter has been in the loop
            // longer than `inflight_ttl`, regardless of the map's current
            // inflight_t.
            if let Some(deadline) = deadline
                && now >= deadline
            {
                return Err(CmcError::storage_failed("InFlightTTL exceeded"));
            }

            // Re-classify per Dafny `CheckNewEntry`: become leader when
            // fan-out has space AND (key not inflight OR grace interval
            // elapsed). Prune runs inside `state_locked` so the fan-out
            // check reflects live state.
            let mut state = self.state_locked(now, cache_id)?;
            let slot_open = state.inflight.len() < self.fan_out;
            let leader_permitted = state
                .inflight
                .get(cache_id)
                .copied()
                .is_none_or(|t| !within_grace_interval(t, now, self.grace_interval));

            if slot_open && leader_permitted {
                state.inflight.insert(cache_id.to_vec(), now);
                return Ok(None);
            }
        }
    }
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
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), CmcError> {
        // Write to the inner cache FIRST, then clear inflight. Reversing
        // this order opens a race window where a blocked getter can
        // observe `cache miss + not inflight` between the two operations
        // and start a redundant refresh — defeating storm-tracking
        // coalescing. It also preserves inflight state if the inner put
        // fails, so a failed refresh doesn't lose the leader signal.
        self.inner.put_cache_entry(cache_id, entry).await?;

        let now = (self.now)();
        let mut state = self.state_locked(now, cache_id)?;
        state.inflight.remove(cache_id);
        Ok(())
    }

    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError> {
        let cached = self.inner.get_cache_entry(cache_id).await?;
        let now = (self.now)();

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

    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), CmcError> {
        self.inner.delete_cache_entry(cache_id).await
    }
}
