// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `StormTrackingCmc`.
//!
//! Gated behind the `test-utils` feature because these tests rely on
//! `StormTrackingCmc::with_clock` and the `#[doc(hidden)]` inflight-map
//! test hooks (`inner`, `peek_inflight`, `inflight_count`, `mark_inflight`),
//! all of which are only compiled in when `test-utils` is enabled.

#![cfg(feature = "test-utils")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_crypto_mpl::cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, CmcErrorKind, LocalCmc, MessageUsage,
    StormTrackingCmc, TimeUnits, UsageMetadata,
};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptionContext, EncryptionMaterials,
};

// ── Fixtures ─────────────────────────────────────────────────────────────────

const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;

/// "Now" anchor for frozen-clock tests.
fn anchor_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// Grace period for most tests (seconds).
const GRACE_PERIOD_SECS: u64 = 10;
/// Grace interval (must be <= grace_period and <= inflight_ttl).
const GRACE_INTERVAL_SECS: u64 = 2;
/// Inflight TTL (must be <= grace_period and >= grace_interval).
const INFLIGHT_TTL_SECS: u64 = 5;
/// Fan-out limit.
const FAN_OUT: usize = 3;
/// Sleep between polls in tests (short so tests run fast).
const SLEEP_MILLI: u64 = 5;

fn make_encryption_materials() -> EncryptionMaterials {
    EncryptionMaterials::new(
        SUITE,
        vec![],
        EncryptionContext::new(),
        BTreeSet::new(),
        None,
        None,
        None,
    )
    .expect("constructing empty encryption materials")
}

fn make_decryption_materials() -> DecryptionMaterials {
    DecryptionMaterials::new(
        SUITE,
        EncryptionContext::new(),
        BTreeSet::new(),
        None,
        None,
        None,
    )
    .expect("constructing empty decryption materials")
}

fn make_branch_key_materials() -> BranchKeyMaterials {
    BranchKeyMaterials::new(
        [0u8; 32],
        "test-branch-key-id".to_string(),
        "00000000-0000-4000-8000-000000000000".to_string(),
        EncryptionContext::new(),
    )
    .expect("constructing branch key materials")
}

fn make_beacon_key_materials() -> BeaconKeyMaterials {
    BeaconKeyMaterials::new(
        "test-beacon-key-id".to_string(),
        EncryptionContext::new(),
        None,
        Option::<BTreeMap<String, Vec<u8>>>::None,
    )
}

fn make_entry_at(creation: SystemTime, expiry: SystemTime) -> CacheEntry {
    CacheEntry::new(
        CachedMaterials::Encryption(make_encryption_materials()),
        creation,
        expiry,
        UsageMetadata::new(MessageUsage(0), BytesUsage(0)),
    )
}

/// Construct a `StormTrackingCmc` with a frozen clock at `now`.
fn make_storm_tracking(now: SystemTime) -> StormTrackingCmc {
    StormTrackingCmc::with_clock(
        32,
        4,
        GRACE_PERIOD_SECS,
        GRACE_INTERVAL_SECS,
        FAN_OUT,
        INFLIGHT_TTL_SECS,
        SLEEP_MILLI,
        None,
        move || now,
    )
    .expect("StormTrackingCmc constructs")
}

// ── Group 1 — Initialization ──────────────────────────────────────────────────

#[tokio::test]
async fn test_initialization_accepts_local_cmc_parameters() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);

    let cmc = StormTrackingCmc::with_clock(
        8,
        2,
        GRACE_PERIOD_SECS,
        GRACE_INTERVAL_SECS,
        FAN_OUT,
        INFLIGHT_TTL_SECS,
        SLEEP_MILLI,
        None,
        move || now,
    )
    .expect("construction with explicit LocalCmc parameters succeeds");

    // Round-trip proves the inner LocalCmc was configured with those parameters.
    cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put succeeds");
    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");
    assert!(got.is_some(), "entry survives a put-get round-trip");
}

#[tokio::test]
async fn test_initialization_requires_storm_tracking_parameters() {
    let now = anchor_now();

    let cmc = StormTrackingCmc::with_clock(
        8,
        2,
        GRACE_PERIOD_SECS,
        GRACE_INTERVAL_SECS,
        FAN_OUT,
        INFLIGHT_TTL_SECS,
        SLEEP_MILLI,
        None,
        move || now,
    )
    .expect("construction succeeds");

    assert_eq!(cmc.grace_period(), Duration::from_secs(GRACE_PERIOD_SECS));
    assert_eq!(
        cmc.grace_interval(),
        Duration::from_secs(GRACE_INTERVAL_SECS)
    );
    assert_eq!(cmc.fan_out(), FAN_OUT);
    assert_eq!(cmc.inflight_ttl(), Duration::from_secs(INFLIGHT_TTL_SECS));
    assert_eq!(cmc.sleep_milli(), Duration::from_millis(SLEEP_MILLI));
}

#[tokio::test]
async fn test_initialization_time_units_is_optional() {
    let now = anchor_now();

    let cmc_default = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        5,
        SLEEP_MILLI,
        None, // None = unset
        move || now,
    )
    .expect("construction without time_units succeeds");
    assert_eq!(cmc_default.time_units(), TimeUnits::Seconds);

    let cmc_ms = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        5,
        SLEEP_MILLI,
        Some(TimeUnits::Milliseconds),
        move || now,
    )
    .expect("construction with Milliseconds time_units succeeds");
    assert_eq!(cmc_ms.time_units(), TimeUnits::Milliseconds);
}

#[tokio::test]
async fn test_initialization_instantiates_local_cmc() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);
    let cmc = make_storm_tracking(now);

    cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put succeeds");

    let got = cmc
        .inner()
        .get_cache_entry(b"k")
        .await
        .expect("inner get succeeds");
    assert!(
        got.is_some(),
        "entry written through the wrapper is visible in the inner LocalCmc, \
         proving a backing LocalCmc was instantiated"
    );
}

// ── Group 2 — Time Units ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_time_units_only_seconds_or_milliseconds() {
    let now = anchor_now();

    let cmc_s = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        5,
        SLEEP_MILLI,
        Some(TimeUnits::Seconds),
        move || now,
    )
    .expect("Seconds variant constructs");
    assert_eq!(cmc_s.time_units(), TimeUnits::Seconds);

    let cmc_ms = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        5,
        SLEEP_MILLI,
        Some(TimeUnits::Milliseconds),
        move || now,
    )
    .expect("Milliseconds variant constructs");
    assert_eq!(cmc_ms.time_units(), TimeUnits::Milliseconds);
}

#[tokio::test]
async fn test_time_units_seconds_means_seconds() {
    // grace_period=10 with Seconds → expiry-10s <= now to be in grace period.
    // expiry = anchor + 11s; grace_period = 10s
    // threshold = anchor + 11s - 10s = anchor + 1s
    // now = anchor + 1s  →  threshold <= now  →  within grace period ✓
    let anchor = anchor_now();
    let expiry = anchor + Duration::from_secs(11);
    let now_at_threshold = anchor + Duration::from_secs(1);

    let cmc = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        5,
        SLEEP_MILLI,
        None, // None == Seconds
        move || now_at_threshold,
    )
    .expect("construction succeeds");
    cmc.put_cache_entry(b"k", make_entry_at(anchor, expiry))
        .await
        .expect("put");
    // Within grace period → NoSuchEntry (marks inflight)
    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");

    assert!(
        got.is_none(),
        "grace_period interpreted as 10 seconds; at threshold entry is within grace period"
    );

    // Mirror: same numeric value 10 but with Milliseconds → threshold = 10ms after
    // anchor; now = anchor + 1s is WAY past the grace period → not within grace → Some(entry).
    let cmc_ms = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        5,
        SLEEP_MILLI,
        Some(TimeUnits::Milliseconds),
        move || now_at_threshold,
    )
    .expect("construction succeeds");
    cmc_ms
        .put_cache_entry(b"k", make_entry_at(anchor, expiry))
        .await
        .expect("put");
    let got_ms = cmc_ms.get_cache_entry(b"k").await.expect("get succeeds");
    assert!(
        got_ms.is_some(),
        "with Milliseconds, grace_period=10 ms << 1s, so entry is NOT within grace period"
    );
}

#[tokio::test]
async fn test_time_units_milliseconds_means_milliseconds() {
    // grace_period=10 with Milliseconds → 10 ms.
    // expiry = anchor + 11ms; threshold = anchor + 1ms; now = anchor + 1ms → within.
    let anchor = anchor_now();
    let expiry = anchor + Duration::from_millis(11);
    let now_ms = anchor + Duration::from_millis(1);

    let cmc = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        5,
        SLEEP_MILLI,
        Some(TimeUnits::Milliseconds),
        move || now_ms,
    )
    .expect("construction succeeds");
    cmc.put_cache_entry(b"k", make_entry_at(anchor, expiry))
        .await
        .expect("put");
    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");

    assert!(
        got.is_none(),
        "grace_period interpreted as 10 milliseconds; at threshold entry is within grace period"
    );
}

// ── Group 3 — SleepMilli ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_sleep_milli_unaffected_by_time_units() {
    let now = anchor_now();

    let cmc_s = StormTrackingCmc::with_clock(8, 2, 10, 2, FAN_OUT, 5, 20, None, move || now)
        .expect("Seconds variant");

    let cmc_ms = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        5,
        20,
        Some(TimeUnits::Milliseconds),
        move || now,
    )
    .expect("Milliseconds variant");

    assert_eq!(
        cmc_s.sleep_milli(),
        Duration::from_millis(20),
        "sleep_milli with Seconds time_units must be exactly 20ms"
    );
    assert_eq!(
        cmc_ms.sleep_milli(),
        Duration::from_millis(20),
        "sleep_milli with Milliseconds time_units must still be exactly 20ms"
    );
}

// ── Group 4 — Consistency ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_grace_interval_must_not_exceed_grace_period() {
    let now = anchor_now();

    let result = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        20,
        FAN_OUT,
        10,
        SLEEP_MILLI,
        None,
        move || now, // grace_interval=20 > grace_period=10
    );
    assert!(result.is_err(), "grace_interval > grace_period must fail");
    let err = result.err().expect("error value");
    assert_eq!(
        err.kind,
        CmcErrorKind::InvalidEntry,
        "expected InvalidEntry, got {err:?}"
    );
}

#[tokio::test]
async fn test_inflight_ttl_must_not_exceed_grace_period() {
    let now = anchor_now();

    let result = StormTrackingCmc::with_clock(
        8,
        2,
        10,
        2,
        FAN_OUT,
        30,
        SLEEP_MILLI,
        None,
        move || now, // inflight_ttl=30 > grace_period=10
    );
    assert!(result.is_err(), "inflight_ttl > grace_period must fail");
    let err = result.err().expect("error value");
    assert_eq!(
        err.kind,
        CmcErrorKind::InvalidEntry,
        "expected InvalidEntry, got {err:?}"
    );
}

#[tokio::test]
async fn test_grace_interval_must_not_exceed_inflight_ttl() {
    let now = anchor_now();

    let result = StormTrackingCmc::with_clock(
        8,
        2,
        20,
        15,
        FAN_OUT,
        10,
        SLEEP_MILLI,
        None,
        move || now, // grace_interval=15 > inflight_ttl=10
    );
    assert!(result.is_err(), "grace_interval > inflight_ttl must fail");
    let err = result.err().expect("error value");
    assert_eq!(
        err.kind,
        CmcErrorKind::InvalidEntry,
        "expected InvalidEntry, got {err:?}"
    );
}

// What: `StormTrackingCmc::with_clock_impl` must reject `fan_out == 0` at
// construction time by returning `InvalidEntry`.
//
// Why: the spec states `FanOut: A number (at least 1, default 20)`. Beyond
// the spec, the value drives internal control flow — the block loops check
// `inflight.len() < fan_out` to decide when a slot has opened, and that
// comparison is `usize < 0` when `fan_out == 0`, which is impossible for
// `usize`. So a `fan_out == 0` cache would deadlock any `get_cache_entry`
// that misses on a saturated map. Rejecting at construction turns a silent
// runtime deadlock into a caller-visible validation error.
#[tokio::test]
async fn test_fan_out_zero_is_rejected() {
    let now = anchor_now();

    let result = StormTrackingCmc::with_clock(
        8,
        2,
        GRACE_PERIOD_SECS,
        GRACE_INTERVAL_SECS,
        0, // fan_out = 0 — must be rejected
        INFLIGHT_TTL_SECS,
        SLEEP_MILLI,
        None,
        move || now,
    );
    assert!(result.is_err(), "fan_out = 0 must be rejected");
    let err = result.err().expect("error value");
    assert_eq!(
        err.kind,
        CmcErrorKind::InvalidEntry,
        "expected InvalidEntry, got {err:?}"
    );
}

// What: `grace_period == 0` must be rejected at construction.
//
// Why: the spec states `Grace Period: A number of seconds (at least 1,
// default 10)`. Beyond the spec, `within_grace_period(expiry, now, 0)`
// reduces to `expiry <= now`, i.e., every already-expired entry is
// trivially "within the grace period." Storm tracking would then kick in
// only for already-expired entries — the opposite of its intended
// pre-expiry refresh behavior.
#[tokio::test]
async fn test_grace_period_zero_is_rejected() {
    let now = anchor_now();
    let result = StormTrackingCmc::with_clock(
        8,
        2,
        0, // grace_period = 0
        0,
        FAN_OUT,
        0,
        SLEEP_MILLI,
        None,
        move || now,
    );
    assert!(result.is_err(), "grace_period = 0 must be rejected");
    assert_eq!(
        result.err().expect("error").kind,
        CmcErrorKind::InvalidEntry
    );
}

// What: `grace_interval == 0` must be rejected at construction.
//
// Why: the spec states `Grace Interval: A number of seconds (at least 1,
// default 1)`. `within_grace_interval(inflight, now, 0)` is `now <
// inflight + 0`, which is always false for `now >= inflight`. That means
// no thread would ever be served the cached entry during the grace
// interval — every getter would be told the key is inflight but never
// benefit from the fan-out coalescing that the grace interval enables.
#[tokio::test]
async fn test_grace_interval_zero_is_rejected() {
    let now = anchor_now();
    let result = StormTrackingCmc::with_clock(
        8,
        2,
        GRACE_PERIOD_SECS,
        0, // grace_interval = 0
        FAN_OUT,
        INFLIGHT_TTL_SECS,
        SLEEP_MILLI,
        None,
        move || now,
    );
    assert!(result.is_err(), "grace_interval = 0 must be rejected");
    assert_eq!(
        result.err().expect("error").kind,
        CmcErrorKind::InvalidEntry
    );
}

// What: `inflight_ttl == 0` must be rejected at construction.
//
// Why: the spec states `Inflight TTL: A number (at least 1, default 20)`.
// With `inflight_ttl == 0`, any inflight key with `elapsed > 0`
// immediately exceeds the TTL, so `decide` returns `InFlightTTL exceeded`
// for essentially every subsequent get on an inflight key. The
// storm-tracking mechanism becomes a synchronous error-generator instead
// of a refresh coordinator.
//
// Uses `grace_interval = 1` so the `inflight_ttl >= 1` lower-bound check
// fires directly — the earlier `grace_interval >= 1` check would mask it
// if both were zero.
#[tokio::test]
async fn test_inflight_ttl_zero_is_rejected() {
    let now = anchor_now();
    let result = StormTrackingCmc::with_clock(
        8,
        2,
        GRACE_PERIOD_SECS,
        1, // grace_interval = 1 (valid, so it doesn't mask the field under test)
        FAN_OUT,
        0, // inflight_ttl = 0 — the field under test
        SLEEP_MILLI,
        None,
        move || now,
    );
    assert!(result.is_err(), "inflight_ttl = 0 must be rejected");
    assert_eq!(
        result.err().expect("error").kind,
        CmcErrorKind::InvalidEntry
    );
}

// What: `sleep_milli == 0` must be rejected at construction.
//
// Why: the spec states `SleepMilli: A number of milliseconds (at least 1,
// default 20)`. `sleep_milli == 0` turns the block loops into a hot spin:
// `tokio::time::sleep(Duration::ZERO)` yields but returns immediately, so
// blocked getters would burn a CPU core repeatedly re-acquiring the
// storm-tracking mutex and hammering the inner cache. Any non-zero value
// gives the runtime a chance to schedule other work between polls.
#[tokio::test]
async fn test_sleep_milli_zero_is_rejected() {
    let now = anchor_now();
    let result = StormTrackingCmc::with_clock(
        8,
        2,
        GRACE_PERIOD_SECS,
        GRACE_INTERVAL_SECS,
        FAN_OUT,
        INFLIGHT_TTL_SECS,
        0, // sleep_milli = 0
        None,
        move || now,
    );
    assert!(result.is_err(), "sleep_milli = 0 must be rejected");
    assert_eq!(
        result.err().expect("error").kind,
        CmcErrorKind::InvalidEntry
    );
}

// ── Group 5 — Behaviors ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_cmc_trait_surface_matches_local_cmc() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);

    let storm: Box<dyn Cmc> = Box::new(make_storm_tracking(now));
    let local: Box<dyn Cmc> =
        Box::new(LocalCmc::with_clock(32, 4, move || now).expect("LocalCmc constructs"));

    for cmc in [&storm, &local] {
        cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
            .await
            .expect("put");
        let got = cmc.get_cache_entry(b"k").await.expect("get");
        assert!(got.is_some(), "put-then-get succeeds on both Cmc impls");
        cmc.delete_cache_entry(b"k").await.expect("delete");
        let after = cmc.get_cache_entry(b"k").await.expect("get after delete");
        assert!(
            after.is_none(),
            "entry absent after delete on both Cmc impls"
        );
    }
}

// ── Group 6 — In Flight ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_inflight_records_most_recent_nosuchentry_time() {
    // Two calls at different timestamps must record the SECOND timestamp.
    let t1 = anchor_now();

    let cmc = make_storm_tracking(t1);
    // Expiry within grace period at t1.
    let expiry = t1 + Duration::from_secs(GRACE_PERIOD_SECS - 1);
    cmc.put_cache_entry(b"k", make_entry_at(t1, expiry))
        .await
        .expect("put");

    // First get at t1 — key not inflight → NoSuchEntry, marked at t1.
    let _ = cmc.get_cache_entry(b"k").await.expect("first get");

    // Advance clock to t2, past grace_interval, and get again.
    // grace_interval = 2s, so use t1 + 3s to be outside the grace interval.
    let t2 = t1 + Duration::from_secs(3); // > grace_interval=2s
    let cmc2 = StormTrackingCmc::with_clock(
        32,
        4,
        GRACE_PERIOD_SECS,
        GRACE_INTERVAL_SECS,
        FAN_OUT,
        INFLIGHT_TTL_SECS,
        SLEEP_MILLI,
        None,
        move || t2,
    )
    .expect("constructs");
    cmc2.put_cache_entry(b"k", make_entry_at(t1, expiry))
        .await
        .expect("put");
    // Pre-mark as inflight at t1 so the second get triggers the "update" path.
    cmc2.mark_inflight(b"k", t1);

    let _ = cmc2.get_cache_entry(b"k").await.expect("second get");

    let recorded = cmc2.peek_inflight(b"k").expect("key must be inflight");
    assert_eq!(
        recorded, t2,
        "inflight time must be updated to the most recent NoSuchEntry time"
    );
}

// ── Group 7 — PutCacheEntry ───────────────────────────────────────────────────

#[tokio::test]
async fn test_put_clears_inflight_bit() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);
    let cmc = make_storm_tracking(now);

    // Mark key as inflight (simulates a prior get_cache_entry that returned NoSuchEntry).
    cmc.mark_inflight(b"k", now);
    assert!(
        cmc.peek_inflight(b"k").is_some(),
        "key is inflight before put"
    );

    cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put succeeds");
    assert!(
        cmc.peek_inflight(b"k").is_none(),
        "key must not be inflight after put_cache_entry"
    );
}

// ── Group 8 — Within Grace Period ────────────────────────────────────────────

#[tokio::test]
async fn test_within_grace_period_matches_spec_formula() {
    use aws_crypto_mpl::cmc::storm_tracking::within_grace_period;

    let anchor = anchor_now();
    let gp = Duration::from_secs(10);

    // threshold = expiry - gp = anchor + 20s - 10s = anchor + 10s

    // now == threshold: (expiry - gp) <= now → true (inclusive)
    let expiry = anchor + Duration::from_secs(20);
    let now_at_threshold = anchor + Duration::from_secs(10);

    assert!(
        within_grace_period(expiry, now_at_threshold, gp),
        "now == threshold must be within grace period (inclusive boundary)"
    );

    // now > threshold: strictly inside
    assert!(
        within_grace_period(expiry, anchor + Duration::from_secs(15), gp),
        "now > threshold must be within grace period"
    );

    // now < threshold: strictly outside
    assert!(
        !within_grace_period(expiry, anchor + Duration::from_secs(9), gp),
        "now < threshold must NOT be within grace period"
    );
}

// ── Group 9 — Within Grace Interval ─────────────────────────────────────────

#[tokio::test]
async fn test_within_grace_interval_matches_spec_formula() {
    use aws_crypto_mpl::cmc::storm_tracking::within_grace_interval;

    let inflight = anchor_now();
    let gi = Duration::from_secs(5);

    // now < inflight + gi: within
    let now_within = inflight + Duration::from_secs(4);
    let now_at_boundary = inflight + gi; // == not strictly less than → NOT within
    let now_outside = inflight + Duration::from_secs(6);

    assert!(
        within_grace_interval(inflight, now_within, gi),
        "now < inflight+gi must be within grace interval"
    );
    assert!(
        !within_grace_interval(inflight, now_at_boundary, gi),
        "now == inflight+gi is NOT within grace interval (strict less-than)"
    );
    assert!(
        !within_grace_interval(inflight, now_outside, gi),
        "now > inflight+gi must NOT be within grace interval"
    );
}

// ── Group 10 — GetCacheEntry ──────────────────────────────────────────────────

#[tokio::test]
async fn test_get_consults_inner_local_cmc() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);
    let cmc = make_storm_tracking(now);

    cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");

    // Read from the inner LocalCmc directly — proves the wrapper delegated to it.
    let got = cmc.inner().get_cache_entry(b"k").await.expect("inner get");
    assert!(
        got.is_some(),
        "entry written via the wrapper is visible in the inner LocalCmc"
    );
}

#[tokio::test]
async fn test_get_hit_returns_entry_when_fanout_saturated() {
    let now = anchor_now();
    // Expiry inside grace period (expiry - gp <= now).
    let expiry = now + Duration::from_secs(GRACE_PERIOD_SECS - 1);
    let cmc = make_storm_tracking(now);

    // Put the entry and saturate the inflight map.
    cmc.put_cache_entry(b"target", make_entry_at(now, expiry))
        .await
        .expect("put");
    for i in 0..FAN_OUT {
        cmc.mark_inflight(&[i as u8], now);
    }
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    let got = cmc.get_cache_entry(b"target").await.expect("get succeeds");
    assert!(
        got.is_some(),
        "when fan-out is saturated the entry MUST be returned even if within grace period"
    );
}

#[tokio::test]
async fn test_get_hit_returns_entry_when_outside_grace_period() {
    let now = anchor_now();
    // Expiry FAR in the future: expiry - gp >> now → NOT within grace period.
    let expiry = now + Duration::from_secs(3600);
    let cmc = make_storm_tracking(now);
    cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");

    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");
    assert!(
        got.is_some(),
        "entry outside grace period MUST be returned directly"
    );
}

#[tokio::test]
async fn test_get_hit_within_grace_not_inflight_returns_none_and_marks() {
    let now = anchor_now();
    // Expiry inside grace period.
    let expiry = now + Duration::from_secs(GRACE_PERIOD_SECS - 1);
    let cmc = make_storm_tracking(now);
    cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");

    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");
    assert!(
        got.is_none(),
        "entry within grace period and not inflight MUST return NoSuchEntry"
    );
    assert_eq!(
        cmc.peek_inflight(b"k"),
        Some(now),
        "key must be marked inflight at `now`"
    );
}

#[tokio::test]
async fn test_get_hit_within_grace_inflight_within_interval_returns_entry() {
    let now = anchor_now();
    // Expiry inside grace period.
    let expiry = now + Duration::from_secs(GRACE_PERIOD_SECS - 1);
    let cmc = make_storm_tracking(now);
    cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");
    // Mark as inflight very recently — well within grace_interval.
    let inflight_t = now - Duration::from_millis(100);
    cmc.mark_inflight(b"k", inflight_t);

    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");
    assert!(
        got.is_some(),
        "within grace period AND inflight within interval MUST return the cache entry"
    );
}

#[tokio::test]
async fn test_get_hit_within_grace_inflight_outside_interval_returns_none_and_updates() {
    let now = anchor_now();
    // Expiry inside grace period.
    let expiry = now + Duration::from_secs(GRACE_PERIOD_SECS - 1);
    let cmc = make_storm_tracking(now);
    cmc.put_cache_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");
    // Mark as inflight at a time OUTSIDE the grace interval but WITHIN inflight TTL.
    // grace_interval=2s, inflight_ttl=5s; set inflight_t 3s ago → outside interval, within TTL.
    let inflight_t = now - Duration::from_secs(3);
    cmc.mark_inflight(b"k", inflight_t);

    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");
    assert!(
        got.is_none(),
        "outside grace interval MUST return NoSuchEntry"
    );
    assert_eq!(
        cmc.peek_inflight(b"k"),
        Some(now),
        "inflight time must be UPDATED to `now`, not the original inflight_t"
    );
}

#[tokio::test]
async fn test_get_miss_blocks_when_fanout_saturated_until_key_appears() {
    // This test requires real concurrency — use real clock + tokio spawn + timeout.
    let cmc = Arc::new(
        StormTrackingCmc::new(
            32,
            4,
            GRACE_PERIOD_SECS,
            GRACE_INTERVAL_SECS,
            FAN_OUT,
            INFLIGHT_TTL_SECS,
            SLEEP_MILLI,
            None,
        )
        .expect("constructs"),
    );

    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(3600);

    // Saturate inflight with FAN_OUT distinct keys (not "target").
    for i in 0..FAN_OUT {
        cmc.mark_inflight(&[i as u8], now);
    }

    let cmc_getter = Arc::clone(&cmc);
    let getter = tokio::spawn(async move { cmc_getter.get_cache_entry(b"target").await });

    // Give the getter a moment to block, then put the entry.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let put_now = SystemTime::now();
    cmc.put_cache_entry(b"target", make_entry_at(put_now, expiry))
        .await
        .expect("put");

    let result = tokio::time::timeout(Duration::from_secs(5), getter)
        .await
        .expect("getter must complete within 5s")
        .expect("task joins")
        .expect("get_cache_entry succeeds");
    assert!(
        result.is_some(),
        "getter must receive the entry once the key appears in the cache"
    );
}

#[tokio::test]
async fn test_get_miss_not_inflight_returns_none_and_marks() {
    let now = anchor_now();
    let cmc = make_storm_tracking(now);
    // Do NOT put anything — cache is empty.

    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");
    assert!(
        got.is_none(),
        "cache miss with key not inflight MUST return NoSuchEntry"
    );
    assert_eq!(
        cmc.peek_inflight(b"k"),
        Some(now),
        "key must be marked inflight at `now`"
    );
}

#[tokio::test]
async fn test_get_miss_inflight_exceeds_ttl_fails() {
    let now = anchor_now();
    let cmc = make_storm_tracking(now);
    // Pre-mark inflight longer ago than inflight_ttl.
    let stale_t = now - Duration::from_secs(INFLIGHT_TTL_SECS + 1);
    cmc.mark_inflight(b"k", stale_t);

    let result = cmc.get_cache_entry(b"k").await;
    assert!(
        result.is_err(),
        "inflight TTL exceeded MUST return an error"
    );
    let err = result.expect_err("error");
    assert_eq!(
        err.kind,
        CmcErrorKind::StorageFailed,
        "expected StorageFailed, got {err:?}"
    );
    assert!(
        err.message.contains("InFlightTTL"),
        "error message must contain 'InFlightTTL', got: {}",
        err.message
    );
}

#[tokio::test]
async fn test_get_miss_inflight_within_interval_blocks_until_unblocked() {
    // Real concurrency test — pre-mark inflight just now (within grace interval),
    // saturate fan-out so the only unblock path is "key appears in cache".
    let cmc = Arc::new(
        StormTrackingCmc::new(
            32,
            4,
            GRACE_PERIOD_SECS,
            GRACE_INTERVAL_SECS,
            FAN_OUT,
            INFLIGHT_TTL_SECS,
            SLEEP_MILLI,
            None,
        )
        .expect("constructs"),
    );

    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(3600);
    // Mark "target" inflight at `now` — 0s elapsed, well within grace_interval=2s.
    cmc.mark_inflight(b"target", now);
    // Saturate remaining FAN_OUT-1 slots with other keys so slot_open is false.
    for i in 0..(FAN_OUT - 1) {
        cmc.mark_inflight(&[100 + i as u8], now);
    }
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    let cmc_getter = Arc::clone(&cmc);
    let getter = tokio::spawn(async move { cmc_getter.get_cache_entry(b"target").await });

    // Pause briefly, then put the entry (which also clears "target" from inflight).
    tokio::time::sleep(Duration::from_millis(50)).await;
    let put_now = SystemTime::now();
    cmc.put_cache_entry(b"target", make_entry_at(put_now, expiry))
        .await
        .expect("put");

    let result = tokio::time::timeout(Duration::from_secs(5), getter)
        .await
        .expect("getter must complete within 5s")
        .expect("task joins")
        .expect("get_cache_entry succeeds");
    assert!(
        result.is_some(),
        "getter must receive the entry once put completes"
    );
}

#[tokio::test]
async fn test_get_miss_inflight_outside_interval_returns_none_and_updates() {
    let now = anchor_now();
    let cmc = make_storm_tracking(now);
    // inflight_t outside grace interval but inside inflight TTL:
    // grace_interval=2s, inflight_ttl=5s → set inflight_t 3s ago.
    let inflight_t = now - Duration::from_secs(3);
    cmc.mark_inflight(b"k", inflight_t);

    let got = cmc.get_cache_entry(b"k").await.expect("get succeeds");
    assert!(
        got.is_none(),
        "inflight but outside grace interval MUST return NoSuchEntry"
    );
    assert_eq!(
        cmc.peek_inflight(b"k"),
        Some(now),
        "inflight time must be UPDATED to `now`, not the prior inflight_t"
    );
}

// What: when a waiter is in `BlockMissInflight` and its per-waiter
// deadline (`enter_time + inflight_ttl`) elapses without the entry
// appearing or a leader slot opening, the wait loop must return
// `StorageFailed("InFlightTTL exceeded")`.
//
// Why: the initial classifier's `elapsed > inflight_ttl` check only
// fires when `get_cache_entry` is called AFTER the map-level TTL has
// already been exceeded. A waiter that entered while the key was still
// within its TTL, then got stuck (fan-out saturated, key still inflight
// within grace interval), needs its own path to give up. Without a
// deadline-firing test the per-waiter TTL branch is unreachable at
// runtime and its error path is silently unverified.
#[tokio::test]
async fn test_block_miss_inflight_deadline_fires_when_exceeded() {
    use std::sync::Mutex as StdMutex;

    let start = anchor_now();
    let clock = Arc::new(StdMutex::new(start));
    let clock_reader = Arc::clone(&clock);

    let cmc = Arc::new(
        StormTrackingCmc::with_clock(
            32,
            4,
            GRACE_PERIOD_SECS,
            GRACE_INTERVAL_SECS,
            FAN_OUT,
            INFLIGHT_TTL_SECS,
            SLEEP_MILLI,
            None,
            move || *clock_reader.lock().expect("clock lock"),
        )
        .expect("constructs"),
    );

    // Saturate fan-out with target + two other keys, all inflight at start.
    // With fan-out saturated AND target within grace interval, the waiter
    // is stuck: cannot become leader (saturated), cannot serve cached
    // entry (nothing in cache), cannot fall through to insert (still in
    // grace interval).
    cmc.mark_inflight(b"target", start);
    cmc.mark_inflight(&[1], start);
    cmc.mark_inflight(&[2], start);
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    // Getter enters classify at start: cache miss, target inflight,
    // elapsed=0 (< TTL), within grace interval → Wait { deadline =
    // start + INFLIGHT_TTL_SECS = start + 5s }.
    let cmc_getter = Arc::clone(&cmc);
    let getter = tokio::spawn(async move { cmc_getter.get_cache_entry(b"target").await });

    // Let the getter reach the wait loop.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Advance the clock past the per-waiter deadline. The mark_inflight
    // times stay at `start`, so the map-level state is unchanged; only
    // wall-clock advanced. Next iteration: sleep, cache miss, now >=
    // deadline → return Err.
    *clock.lock().expect("clock lock") = start + Duration::from_secs(INFLIGHT_TTL_SECS + 1);

    let result = tokio::time::timeout(Duration::from_millis(500), getter)
        .await
        .expect("getter must complete after per-waiter deadline elapses")
        .expect("task joins");
    let err = result.expect_err("must be an error once the deadline fires");
    assert_eq!(
        err.kind,
        CmcErrorKind::StorageFailed,
        "expected StorageFailed, got {err:?}"
    );
    assert!(
        err.message.contains("InFlightTTL"),
        "error message must contain 'InFlightTTL', got: {}",
        err.message
    );
}

// ── Group 11 — Material Variant Coverage ─────────────────────────────────────

#[tokio::test]
async fn test_all_material_variants_round_trip() {
    // The wrapper's storage path is variant-agnostic — this test asserts
    // every `CachedMaterials` variant survives a put/get round-trip, not
    // only the `Encryption` variant exercised by the rest of this file.
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);
    let usage = UsageMetadata::new(MessageUsage(0), BytesUsage(0));

    for (label, materials) in [
        (
            "Encryption",
            CachedMaterials::Encryption(make_encryption_materials()),
        ),
        (
            "Decryption",
            CachedMaterials::Decryption(make_decryption_materials()),
        ),
        (
            "BranchKey",
            CachedMaterials::BranchKey(make_branch_key_materials()),
        ),
        (
            "BeaconKey",
            CachedMaterials::BeaconKey(make_beacon_key_materials()),
        ),
    ] {
        let cmc = make_storm_tracking(now);
        cmc.put_cache_entry(b"id", CacheEntry::new(materials, now, expiry, usage))
            .await
            .expect("put succeeds");

        let got = cmc
            .get_cache_entry(b"id")
            .await
            .expect("get succeeds")
            .unwrap_or_else(|| panic!("{label}: entry is present after put"));

        let got_variant = match &got.materials {
            CachedMaterials::Encryption(_) => "Encryption",
            CachedMaterials::Decryption(_) => "Decryption",
            CachedMaterials::BranchKey(_) => "BranchKey",
            CachedMaterials::BeaconKey(_) => "BeaconKey",
        };
        assert_eq!(
            got_variant, label,
            "materials variant must be preserved through put/get"
        );
        assert_eq!(
            got.creation_time, now,
            "{label}: creation_time must round-trip"
        );
        assert_eq!(
            got.expiry_time, expiry,
            "{label}: expiry_time must round-trip"
        );
        assert_eq!(
            got.usage_metadata, usage,
            "{label}: usage_metadata must round-trip"
        );
    }
}

// ── Group 12 — Bug Reproduction Tests (Copilot PR #33 review) ────────────────

// What: when every inflight entry in the fan-out map exceeds `inflight_ttl`
// while a thread is blocked in `BlockMissNotInflight`, the block loop must
// prune the stale entries, observe the freed fan-out slots, and return
// `NoSuchEntry` after marking its own key inflight at the current time.
//
// Why: without an in-loop prune, the only path that removes stale inflight
// entries is the `prune_stale_inflight` call at the top of the next
// `get_cache_entry`. If every inflight slot is held by a thread that has
// already returned (or errored) and no new caller enters `get_cache_entry`,
// the blocked getter has no way to observe the staleness — it spins on
// `inflight.len() < fan_out` (always false) until its caller times out.
// This turns a self-healing storm-tracking cache into one that requires
// external traffic to unstick.
#[tokio::test]
async fn test_block_miss_not_inflight_prunes_stale_entries_in_loop() {
    use std::sync::Mutex as StdMutex;

    let start = anchor_now();
    let clock = Arc::new(StdMutex::new(start));
    let clock_reader = Arc::clone(&clock);

    let cmc = Arc::new(
        StormTrackingCmc::with_clock(
            32,
            4,
            GRACE_PERIOD_SECS,
            GRACE_INTERVAL_SECS,
            FAN_OUT,
            INFLIGHT_TTL_SECS,
            SLEEP_MILLI,
            None,
            move || *clock_reader.lock().expect("clock lock"),
        )
        .expect("constructs"),
    );

    for i in 0..FAN_OUT {
        cmc.mark_inflight(&[i as u8], start);
    }
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    let cmc_getter = Arc::clone(&cmc);
    let getter = tokio::spawn(async move { cmc_getter.get_cache_entry(b"new-key").await });

    // Let the getter enter the block loop.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Every pre-marked entry is now stale relative to the advanced clock.
    *clock.lock().expect("clock lock") = start + Duration::from_secs(INFLIGHT_TTL_SECS + 10);

    let result = tokio::time::timeout(Duration::from_millis(500), getter)
        .await
        .expect("getter must complete after stale inflight entries expire")
        .expect("task joins")
        .expect("get_cache_entry Ok");
    assert!(
        result.is_none(),
        "expected NoSuchEntry once fan-out slot opens via prune"
    );
    assert_eq!(
        cmc.peek_inflight(b"new-key"),
        Some(start + Duration::from_secs(INFLIGHT_TTL_SECS + 10)),
        "new-key must be marked inflight at the current (advanced) time"
    );
}

// What: the BlockMissInflight polling loop must keep waiting when the
// target key is still inflight AND within its grace interval, even if
// fan-out slots free up (because another key's put completed). Exiting
// the loop on slot_open alone would let this getter steal leader status
// from the current refresher and kick off a redundant refresh — defeating
// per-key coalescing.
//
// Why: matches the Dafny reference (StormTracker.CheckNewEntry). The
// classification for "key not found in cache, key inflight, within grace
// interval" is EmptyWait, regardless of fan-out availability. Only once
// the grace interval elapses OR the key exits inflight state should the
// waiter become the next leader (return NoSuchEntry).
#[tokio::test]
async fn test_block_miss_inflight_keeps_waiting_when_slot_opens_but_key_still_inflight() {
    use std::sync::Mutex as StdMutex;

    // grace_interval and inflight_ttl large so we have room to observe the
    // "waiter should keep waiting when slot opens" behavior without other
    // exit paths firing first.
    const GI_SECS: u64 = 10;
    const TTL_SECS: u64 = 20;
    const GP_SECS: u64 = 30;

    let start = anchor_now();
    let clock = Arc::new(StdMutex::new(start));
    let clock_reader = Arc::clone(&clock);

    let cmc = Arc::new(
        StormTrackingCmc::with_clock(
            32,
            4,
            GP_SECS,
            GI_SECS,
            FAN_OUT,
            TTL_SECS,
            SLEEP_MILLI,
            None,
            move || *clock_reader.lock().expect("clock lock"),
        )
        .expect("constructs"),
    );

    // Saturate fan-out: target + 2 other keys, all inflight at start.
    cmc.mark_inflight(b"target", start);
    cmc.mark_inflight(&[1], start);
    cmc.mark_inflight(&[2], start);
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    let cmc_getter = Arc::clone(&cmc);
    let getter = tokio::spawn(async move { cmc_getter.get_cache_entry(b"target").await });

    // Let the getter enter the block loop.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Free two fan-out slots by putting the saturators. Under the fix,
    // put clears their inflight after writing cache — either way, once
    // both puts land the inflight map holds only `target`.
    let entry_expiry = start + Duration::from_secs(3600);
    cmc.put_cache_entry(&[1], make_entry_at(start, entry_expiry))
        .await
        .expect("put saturator 1");
    cmc.put_cache_entry(&[2], make_entry_at(start, entry_expiry))
        .await
        .expect("put saturator 2");
    assert_eq!(
        cmc.inflight_count(),
        1,
        "only target should remain inflight"
    );

    // Give the loop iterations to observe the freed slots.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Under bug: getter's next iteration sees slot_open, breaks, marks
    // itself inflight at ~start (clock still at start), returns Ok(None)
    // — redundant refresh scenario.
    //
    // Under fix: getter re-classifies: fan_out has space, target is still
    // inflight, still within grace interval (0s elapsed) → keep waiting.
    // Now advance the clock past grace interval so the fix's next
    // iteration transitions to "become leader" and returns Ok(None).
    *clock.lock().expect("clock lock") = start + Duration::from_secs(GI_SECS + 1);

    let result = tokio::time::timeout(Duration::from_millis(500), getter)
        .await
        .expect("getter must complete within 500ms after grace interval elapses")
        .expect("task joins")
        .expect("get_cache_entry Ok");
    assert!(
        result.is_none(),
        "expected NoSuchEntry once getter becomes leader"
    );

    // Verify getter marked target inflight AFTER the grace interval
    // elapsed, proving it waited rather than exiting early on slot_open.
    let inflight_time = cmc.peek_inflight(b"target").expect("target inflight");
    assert!(
        inflight_time >= start + Duration::from_secs(GI_SECS),
        "target must be marked inflight after grace interval elapsed \
         (got {inflight_time:?}, expected >= start + {GI_SECS}s); \
         this proves the getter kept waiting instead of exiting on slot_open"
    );
}

// What: the BlockMissInflight loop's InFlightTTL check must fire based on
// the WAITER's enter time + inflight_ttl (per-waiter deadline), not the
// key's map inflight_t. A subsequent refresh of the map inflight_t must
// NOT extend this waiter's TTL budget.
//
// Why: matches the Dafny reference extern (StormTrackingCMC.cs):
//   `max_in_flight = DateTime.Now + inFlightTTL`
// computed ONCE at loop entry, checked each iteration. The spec text
// confirms per-waiter semantics: "If a thread has been sleeping [...] it
// will give up and return an error after this amount of time."
#[tokio::test]
async fn test_block_miss_inflight_uses_per_waiter_deadline_not_per_key() {
    use std::sync::Mutex as StdMutex;

    const GI_SECS: u64 = 10;
    const TTL_SECS: u64 = 10;
    const GP_SECS: u64 = 30;

    let start = anchor_now();
    let clock = Arc::new(StdMutex::new(start));
    let clock_reader = Arc::clone(&clock);

    let cmc = Arc::new(
        StormTrackingCmc::with_clock(
            32,
            4,
            GP_SECS,
            GI_SECS,
            FAN_OUT,
            TTL_SECS,
            SLEEP_MILLI,
            None,
            move || *clock_reader.lock().expect("clock lock"),
        )
        .expect("constructs"),
    );

    // Mark target inflight at start; saturate fan-out with other keys.
    cmc.mark_inflight(b"target", start);
    cmc.mark_inflight(&[1], start);
    cmc.mark_inflight(&[2], start);

    // Advance clock 5s. Target has now been inflight (per map) for 5s
    // (still within TTL=10s, so decide passes and returns BlockMissInflight).
    *clock.lock().expect("clock lock") = start + Duration::from_secs(5);

    // Spawn getter. decide reads captured inflight_t = start, elapsed=5.
    // Getter's enter_time is start+5 → per-waiter deadline = start+15.
    let cmc_getter = Arc::clone(&cmc);
    let getter = tokio::spawn(async move { cmc_getter.get_cache_entry(b"target").await });

    tokio::time::sleep(Duration::from_millis(30)).await;

    // Refresh target's inflight_t to start+5 (simulating another thread
    // noticing the key needs a refresh). This preserves the classification's
    // "within grace interval" branch throughout the rest of the test — the
    // grace interval now elapses at start+5+GI = start+15 (aligned with the
    // per-waiter deadline). Without this refresh, target's grace interval
    // would elapse at start+GI = start+10, and the getter would legitimately
    // become the next leader at that point (no bug involved).
    cmc.mark_inflight(b"target", start + Duration::from_secs(5));

    // Advance clock to start+13.
    // - Bug (captured/per-key logic): elapsed_loop = 13 - 0 = 13 > 10 →
    //   fires TTL error prematurely.
    // - Fix (per-waiter deadline start+15): 13 < 15 → keeps waiting.
    *clock.lock().expect("clock lock") = start + Duration::from_secs(13);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Put target. Under fix, getter is still waiting; the put unblocks it
    // with Ok(Some). Under bug, getter already errored out at start+13.
    let entry_expiry = start + Duration::from_secs(3600);
    cmc.put_cache_entry(
        b"target",
        make_entry_at(start + Duration::from_secs(13), entry_expiry),
    )
    .await
    .expect("put succeeds");

    let result = tokio::time::timeout(Duration::from_millis(500), getter)
        .await
        .expect("getter must complete within 500ms after put")
        .expect("task joins")
        .expect(
            "get_cache_entry must Ok — at clock=start+13 the per-waiter deadline \
             (start+15) has NOT elapsed and the TTL check must not fire",
        );
    assert!(
        result.is_some(),
        "expected the entry once put unblocks the loop"
    );
}

// ── Group 13 — Storm Coalescing ──────────────────────────────────────────────

// What: when N concurrent tasks all miss on the same cache key
// simultaneously, exactly one becomes the refresh leader (`Ok(None)`)
// and the remaining N-1 waiters are served the entry the leader
// installs (`Ok(Some(_))`).
//
// Why: this is the storm-suppression property the whole cache exists
// to provide, and none of the existing concurrent tests exercise it
// directly — each of them spawns a single blocked getter. This test
// closes that gap by running a real "storm" of concurrent callers.
//
// Mechanism:
//   - Each task calls `get_cache_entry` on an empty cache. The
//     classifier serializes on the state mutex, so exactly one task
//     wins the "cache miss, key not inflight, fan-out slot open"
//     branch and returns `Ok(None)`; the rest fall into the "inflight
//     within grace interval" branch and enter `wait_for_leader`.
//   - The elected leader sleeps briefly to simulate fetch latency,
//     then puts the entry. `put_cache_entry` writes to the inner
//     cache and clears the inflight bit, unblocking the waiters on
//     their next poll.
//   - `fan_out = 20` is chosen so the fan-out limit is not a
//     constraint here (the fan-out-saturated behavior is already
//     covered by `test_get_miss_blocks_when_fanout_saturated_...`);
//     this test isolates the per-key coalescing property.
//   - The leader's 100ms fetch delay is well within the 2s grace
//     interval, so subsequent tasks classify as "inflight, wait" and
//     do NOT independently become leaders.
#[tokio::test]
async fn test_concurrent_gets_on_same_key_coalesce_to_one_refresh() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    const N_TASKS: usize = 50;
    const LEADER_FETCH_DELAY_MS: u64 = 100;
    const STORM_FAN_OUT: usize = 20;

    let cmc = Arc::new(
        StormTrackingCmc::new(
            32,
            4,
            GRACE_PERIOD_SECS,
            GRACE_INTERVAL_SECS,
            STORM_FAN_OUT,
            INFLIGHT_TTL_SECS,
            SLEEP_MILLI,
            None,
        )
        .expect("constructs"),
    );

    let leader_count = Arc::new(AtomicUsize::new(0));
    let waiter_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(N_TASKS);
    for _ in 0..N_TASKS {
        let cmc = Arc::clone(&cmc);
        let leader_count = Arc::clone(&leader_count);
        let waiter_count = Arc::clone(&waiter_count);
        handles.push(tokio::spawn(async move {
            match cmc
                .get_cache_entry(b"target")
                .await
                .expect("get_cache_entry Ok")
            {
                None => {
                    // Elected leader: simulate the "go fetch" latency
                    // callers would incur in production, then publish
                    // the fresh entry.
                    leader_count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(LEADER_FETCH_DELAY_MS)).await;
                    let now = SystemTime::now();
                    let expiry = now + Duration::from_secs(3600);
                    cmc.put_cache_entry(b"target", make_entry_at(now, expiry))
                        .await
                        .expect("leader puts");
                }
                Some(_) => {
                    waiter_count.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    let joined = tokio::time::timeout(Duration::from_secs(10), async {
        for h in handles {
            h.await.expect("task joins");
        }
    })
    .await;
    joined.expect("all storm tasks complete within 10s");

    let leaders = leader_count.load(Ordering::SeqCst);
    let waiters = waiter_count.load(Ordering::SeqCst);
    assert_eq!(
        leaders, 1,
        "exactly one task must be elected refresh leader (got {leaders} leaders, \
         {waiters} waiters)"
    );
    assert_eq!(
        waiters,
        N_TASKS - 1,
        "every non-leader task must be served the entry the leader put \
         (got {leaders} leaders, {waiters} waiters, expected {} waiters)",
        N_TASKS - 1
    );
}
