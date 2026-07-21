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
//! Concurrency model: a single `std::sync::Mutex<StormTrackingState>` guards
//! the inflight map (`HashMap<cache_id, SystemTime>`). The lock is
//! coarse-grained — one mutex for the whole map, not per-key — but the
//! critical section is always pure-CPU work (a hashmap lookup, at most one
//! insert, and a branch decision), and the lock is never held across
//! `.await`. `get_cache_entry` runs in two phases: (1) call the inner
//! `LocalCmc` (which has its own separate `Mutex`, so there is no nested
//! locking and no deadlock between the two caches); then (2) take the
//! storm-tracking mutex just long enough to compute a `GetDecision`, drop
//! it, and only then perform any `tokio::time::sleep`. The blocking
//! branches (`10.7`, `10.10`) re-acquire the mutex briefly on each poll to
//! check `inflight.len() < fan_out` and release it before the next sleep,
//! so a thread waiting to refresh key A does not block a lookup for key B.
//! Cached entries are handed out as `Arc<CacheEntry>` clones, so no
//! materials data is copied under the lock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

/// The action to take after the lock-protected decision step.
/// This allows us to drop the `MutexGuard` before performing any `.await`.
enum GetDecision {
    /// Return the cached entry immediately.
    ReturnEntry(Arc<CacheEntry>),
    /// Return `NoSuchEntry` immediately (also records the inflight insert).
    ReturnNone,
    /// Spin until a FanOut slot opens or the key appears (10.7 — miss, not inflight, saturated).
    BlockMissNotInflight,
    /// Return an error (inflight TTL exceeded).
    Fail(CmcError),
    /// Spin until a FanOut slot opens or the key appears (10.10 — miss, inflight, within interval).
    BlockMissInflight { inflight_t: SystemTime },
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
        Self::with_clock(
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

    /// Construct a `StormTrackingCmc` with an injected clock. Tests use this
    /// to advance time deterministically without sleeping.
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
        let units = time_units.unwrap_or_default();
        let to_duration = |v: u64| -> Duration {
            //
            match units {
                TimeUnits::Seconds => Duration::from_secs(v),
                TimeUnits::Milliseconds => Duration::from_millis(v),
            }
        };

        let grace_period_dur = to_duration(grace_period);
        let grace_interval_dur = to_duration(grace_interval);
        let inflight_ttl_dur = to_duration(inflight_ttl);

        if grace_interval_dur > grace_period_dur {
            return Err(CmcError::invalid_entry(
                "grace_interval must be <= grace_period",
            ));
        }

        if inflight_ttl_dur > grace_period_dur {
            return Err(CmcError::invalid_entry(
                "inflight_ttl must be <= grace_period",
            ));
        }

        if grace_interval_dur > inflight_ttl_dur {
            return Err(CmcError::invalid_entry(
                "grace_interval must be <= inflight_ttl",
            ));
        }

        let now_arc: Arc<dyn Fn() -> SystemTime + Send + Sync> = Arc::new(now);
        let inner_clock = Arc::clone(&now_arc);

        let inner = LocalCmc::with_clock(entry_capacity, entry_pruning_tail_size, move || {
            inner_clock()
        })?;

        let sleep_milli_dur = Duration::from_millis(sleep_milli);

        Ok(Self {
            inner,
            grace_period: grace_period_dur,
            grace_interval: grace_interval_dur,
            fan_out,
            inflight_ttl: inflight_ttl_dur,
            sleep_milli: sleep_milli_dur,
            time_units: units,
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
    #[doc(hidden)]
    pub fn inner(&self) -> &LocalCmc {
        &self.inner
    }

    /// Peek the inflight map for `cache_id`. Returns the most recent time
    /// a `NoSuchEntry` was returned for that key, or `None` if the key is
    /// not currently inflight. Exposed for test observability.
    #[doc(hidden)]
    pub fn peek_inflight(&self, cache_id: &[u8]) -> Option<SystemTime> {
        let state = self.state.lock().expect("StormTrackingCmc lock poisoned");
        state.inflight.get(cache_id).copied()
    }

    /// Number of currently inflight keys. Exposed for test observability.
    #[doc(hidden)]
    pub fn inflight_count(&self) -> usize {
        let state = self.state.lock().expect("StormTrackingCmc lock poisoned");
        state.inflight.len()
    }

    /// Directly insert an inflight entry at a given time. Exposed for tests
    /// to pre-populate the inflight map without going through get_cache_entry.
    #[doc(hidden)]
    pub fn mark_inflight(&self, cache_id: &[u8], when: SystemTime) {
        let mut state = self.state.lock().expect("StormTrackingCmc lock poisoned");
        state.inflight.insert(cache_id.to_vec(), when);
    }

    /// Prune inflight entries that have exceeded the inflight TTL.
    /// Skips `skip_key` so that the current query can detect TTL violations.
    fn prune_stale_inflight(
        &self,
        state: &mut StormTrackingState,
        now: SystemTime,
        skip_key: &[u8],
    ) {
        let ttl = self.inflight_ttl;
        state.inflight.retain(|k, t| {
            k.as_slice() == skip_key
                || now
                    .duration_since(*t)
                    .map_or(true, |elapsed| elapsed <= ttl)
        });
    }

    /// Determine what action to take (lock-protected, no await).
    /// Performs any needed inflight map mutations and returns a `GetDecision`.
    fn decide(
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
                    return Ok(GetDecision::ReturnEntry(Arc::clone(entry)));
                }

                let within_grace = within_grace_period(entry.expiry_time, now, self.grace_period);

                if !within_grace {
                    return Ok(GetDecision::ReturnEntry(Arc::clone(entry)));
                }

                match state.inflight.get(cache_id).copied() {
                    None => {
                        //
                        state.inflight.insert(cache_id.to_vec(), now);
                        Ok(GetDecision::ReturnNone)
                    }
                    Some(inflight_t) => {
                        if within_grace_interval(inflight_t, now, self.grace_interval) {
                            Ok(GetDecision::ReturnEntry(Arc::clone(entry)))
                        } else {
                            state.inflight.insert(cache_id.to_vec(), now);
                            Ok(GetDecision::ReturnNone)
                        }
                    }
                }
            }
            None => {
                // Cache miss.
                match state.inflight.get(cache_id).copied() {
                    None => {
                        if state.inflight.len() >= self.fan_out {
                            // Do NOT insert into inflight yet — blocking branch will do it after slot opens.
                            Ok(GetDecision::BlockMissNotInflight)
                        } else {
                            state.inflight.insert(cache_id.to_vec(), now);
                            Ok(GetDecision::ReturnNone)
                        }
                    }
                    Some(inflight_t) => {
                        let elapsed = now.duration_since(inflight_t).unwrap_or(Duration::ZERO);

                        if elapsed > self.inflight_ttl {
                            return Ok(GetDecision::Fail(CmcError::storage_failed(
                                "InFlightTTL exceeded",
                            )));
                        }

                        if within_grace_interval(inflight_t, now, self.grace_interval) {
                            Ok(GetDecision::BlockMissInflight { inflight_t })
                        } else {
                            state.inflight.insert(cache_id.to_vec(), now);
                            Ok(GetDecision::ReturnNone)
                        }
                    }
                }
            }
        }
    }

    /// Execute the action determined by `decide`. May perform async sleeps.
    async fn execute_decision(
        &self,
        cache_id: &[u8],
        decision: GetDecision,
    ) -> Result<Option<Arc<CacheEntry>>, CmcError> {
        match decision {
            GetDecision::ReturnEntry(e) => Ok(Some(e)),
            GetDecision::ReturnNone => Ok(None),
            GetDecision::Fail(e) => Err(e),

            GetDecision::BlockMissNotInflight => {
                loop {
                    tokio::time::sleep(self.sleep_milli).await;

                    let cached_now = self.inner.get_cache_entry(cache_id).await?;
                    if cached_now.is_some() {
                        return Ok(cached_now);
                    }
                    let slot_open = {
                        let s = self.state.lock().map_err(|e| {
                            CmcError::storage_failed(format!("StormTrackingCmc lock poisoned: {e}"))
                        })?;
                        s.inflight.len() < self.fan_out
                    };
                    if slot_open {
                        break;
                    }
                }

                // Slot opened — insert inflight and return NoSuchEntry.
                let now2 = (self.now)();
                let mut state2 = self.state.lock().map_err(|e| {
                    CmcError::storage_failed(format!("StormTrackingCmc lock poisoned: {e}"))
                })?;
                self.prune_stale_inflight(&mut state2, now2, cache_id);
                state2.inflight.insert(cache_id.to_vec(), now2);
                Ok(None)
            }

            GetDecision::BlockMissInflight { inflight_t } => {
                loop {
                    tokio::time::sleep(self.sleep_milli).await;

                    let cached_now = self.inner.get_cache_entry(cache_id).await?;
                    if cached_now.is_some() {
                        return Ok(cached_now);
                    }

                    let now_loop = (self.now)();
                    let elapsed_loop = now_loop
                        .duration_since(inflight_t)
                        .unwrap_or(Duration::ZERO);

                    if elapsed_loop > self.inflight_ttl {
                        return Err(CmcError::storage_failed("InFlightTTL exceeded"));
                    }

                    let slot_open = {
                        let s = self.state.lock().map_err(|e| {
                            CmcError::storage_failed(format!("StormTrackingCmc lock poisoned: {e}"))
                        })?;
                        s.inflight.len() < self.fan_out
                    };
                    if slot_open {
                        break;
                    }
                }

                let now2 = (self.now)();
                let mut state2 = self.state.lock().map_err(|e| {
                    CmcError::storage_failed(format!("StormTrackingCmc lock poisoned: {e}"))
                })?;
                self.prune_stale_inflight(&mut state2, now2, cache_id);
                state2.inflight.insert(cache_id.to_vec(), now2);
                Ok(None)
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
        {
            let mut state = self.state.lock().map_err(|e| {
                CmcError::storage_failed(format!("StormTrackingCmc lock poisoned: {e}"))
            })?;

            state.inflight.remove(cache_id);
        }

        self.inner.put_cache_entry(cache_id, entry).await
    }

    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError> {
        let cached = self.inner.get_cache_entry(cache_id).await?;
        let now = (self.now)();

        // Collect the decision with the lock held, then drop the lock before any await.
        let decision = {
            let mut state = self.state.lock().map_err(|e| {
                CmcError::storage_failed(format!("StormTrackingCmc lock poisoned: {e}"))
            })?;
            self.prune_stale_inflight(&mut state, now, cache_id);
            self.decide(&mut state, cache_id, &cached, now)?
        };

        self.execute_decision(cache_id, decision).await
    }

    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), CmcError> {
        self.inner.delete_cache_entry(cache_id).await
    }
}
