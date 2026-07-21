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

    // Advance clock to t2 and get again — key is inflight but NOT within grace interval
    // (grace_interval = 2s, t2 - t1 = 1s < 2s → actually still within interval).
    // Use t1 + 3s to be outside the grace interval.
    let t3 = t1 + Duration::from_secs(3); // > grace_interval=2s
    let cmc2 = StormTrackingCmc::with_clock(
        32,
        4,
        GRACE_PERIOD_SECS,
        GRACE_INTERVAL_SECS,
        FAN_OUT,
        INFLIGHT_TTL_SECS,
        SLEEP_MILLI,
        None,
        move || t3,
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
        recorded, t3,
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
