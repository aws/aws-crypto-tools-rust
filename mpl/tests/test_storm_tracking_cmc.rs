// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `StormTrackingCmc`.
//!
//! Gated behind the `test-utils` feature, which compiles in what these tests rely on:
//! the `StormTrackingCmcBuilder::clock` setter and the `#[doc(hidden)]` inflight-map
//! hooks (`inner`, `peek_inflight`, `inflight_count`, `mark_inflight`).

#![cfg(feature = "test-utils")]

use aws_crypto_mpl::Error;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::error::{Cache, Resource, RetryKind};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_crypto_mpl::cmc::{LocalCmc, SharedCmc, StormTrackingCmc, StormTrackingCmcBuilder};
use aws_crypto_mpl::shared::IntoShared;
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId,
};
use aws_crypto_mpl::types::{CacheEntry, CachedMaterials, UsageMetadata};

/// Positional shorthand for the `Cmc` operations.
#[async_trait]
trait CmcExt {
    fn handle(&self) -> SharedCmc;

    async fn put_entry(&self, id: &[u8], entry: CacheEntry) -> Result<(), Error> {
        let put = self.handle().put_cache_entry().identifier(id).entry(entry);
        put.send().await.map(|_| ())
    }

    async fn get_entry(&self, id: &[u8]) -> Result<Option<Arc<CacheEntry>>, Error> {
        let get = self.handle().get_cache_entry().identifier(id);
        Ok(get.send().await?.into_entry())
    }

    async fn delete_entry(&self, id: &[u8]) -> Result<(), Error> {
        let delete = self.handle().delete_cache_entry().identifier(id);
        delete.send().await.map(|_| ())
    }
}

impl<T: IntoShared<SharedCmc> + Clone + Send + Sync> CmcExt for T {
    fn handle(&self) -> SharedCmc {
        self.clone().into_shared()
    }
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);

/// "Now" anchor for frozen-clock tests.
fn anchor_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// Grace period for most tests.
const GRACE_PERIOD: Duration = Duration::from_secs(10);
/// Grace interval (must be <= inflight_ttl).
const GRACE_INTERVAL: Duration = Duration::from_secs(2);
/// Inflight TTL (must be >= grace_interval).
const INFLIGHT_TTL: Duration = Duration::from_secs(5);
/// Fan-out limit.
const FAN_OUT: usize = 3;
/// Sleep between polls in tests (short so tests run fast).
const SLEEP: Duration = Duration::from_millis(5);

fn make_encryption_materials() -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .build()
        .expect("constructing empty encryption materials")
}

fn make_decryption_materials() -> DecryptionMaterials {
    DecryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .build()
        .expect("constructing empty decryption materials")
}

fn make_branch_key_materials() -> BranchKeyMaterials {
    BranchKeyMaterials::builder()
        .branch_key([0u8; 32])
        .branch_key_id("test-branch-key-id".to_string())
        .branch_key_version("00000000-0000-4000-8000-000000000000".to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .expect("constructing branch key materials")
}

fn make_beacon_key_materials() -> BeaconKeyMaterials {
    BeaconKeyMaterials::builder()
        .beacon_key_id("test-beacon-key-id".to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap()
}

fn make_entry_at(creation: SystemTime, expiry: SystemTime) -> CacheEntry {
    CacheEntry::builder()
        .materials(CachedMaterials::Encryption(make_encryption_materials()))
        .creation_time(creation)
        .expiry_time(expiry)
        .usage_metadata(
            UsageMetadata::builder()
                .messages_used(0)
                .bytes_used(0)
                .build()
                .expect("usage metadata builds"),
        )
        .build()
        .expect("cache entry builds")
}

/// A `StormTrackingCmc` builder with explicit settings.
fn storm_config(
    entry_capacity: usize,
    entry_pruning_tail_size: usize,
    grace_period: Duration,
    grace_interval: Duration,
    fan_out: usize,
    inflight_ttl: Duration,
    sleep: Duration,
) -> StormTrackingCmcBuilder {
    StormTrackingCmc::builder()
        .entry_capacity(entry_capacity)
        .entry_pruning_tail_size(entry_pruning_tail_size)
        .grace_period(grace_period)
        .grace_interval(grace_interval)
        .fan_out(fan_out)
        .inflight_ttl(inflight_ttl)
        .sleep(sleep)
}

/// Construct a `StormTrackingCmc` with a frozen clock at `now`.
fn make_storm_tracking(now: SystemTime) -> StormTrackingCmc {
    storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .clock(move || now)
    .build()
    .expect("StormTrackingCmc constructs")
}

// ── Group 1 — Initialization ──────────────────────────────────────────────────

#[tokio::test]
async fn test_initialization_accepts_local_cmc_parameters() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);

    let cmc = storm_config(
        8,
        2,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .clock(move || now)
    .build()
    .expect("construction with explicit LocalCmc parameters succeeds");

    // Round-trip proves the inner LocalCmc was configured with those parameters.
    cmc.put_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put succeeds");
    let got = cmc.get_entry(b"k").await.expect("get succeeds");
    assert!(got.is_some(), "entry survives a put-get round-trip");
}

#[tokio::test]
async fn test_initialization_requires_storm_tracking_parameters() {
    let now = anchor_now();

    let cmc = storm_config(
        8,
        2,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .clock(move || now)
    .build()
    .expect("construction succeeds");

    assert_eq!(cmc.grace_period(), Some(GRACE_PERIOD));
    assert_eq!(cmc.grace_interval(), GRACE_INTERVAL);
    assert_eq!(cmc.fan_out(), FAN_OUT);
    assert_eq!(cmc.inflight_ttl(), INFLIGHT_TTL);
    assert_eq!(cmc.sleep(), SLEEP);
}

#[tokio::test]
async fn test_initialization_instantiates_local_cmc() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);
    let cmc = make_storm_tracking(now);

    cmc.put_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put succeeds");

    let got = cmc
        .inner()
        .get_entry(b"k")
        .await
        .expect("inner get succeeds");
    assert!(
        got.is_some(),
        "entry written through the wrapper is visible in the inner LocalCmc, \
         proving a backing LocalCmc was instantiated"
    );
}

// ── Group 2 — Durations ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_grace_period_is_the_configured_duration() {
    // expiry = anchor + 11s; now = anchor + 1s.
    // A 10 s grace period starts at anchor + 1s, so the entry is within it.
    // A 10 ms grace period starts at anchor + 10.99s, so the entry is not.
    let anchor = anchor_now();
    let expiry = anchor + Duration::from_secs(11);
    let now = anchor + Duration::from_secs(1);

    for (grace_period, grace_interval, inflight_ttl, within) in [
        (
            Duration::from_secs(10),
            Duration::from_secs(2),
            Duration::from_secs(5),
            true,
        ),
        (
            Duration::from_millis(10),
            Duration::from_millis(2),
            Duration::from_millis(5),
            false,
        ),
    ] {
        let cmc = storm_config(
            8,
            2,
            grace_period,
            grace_interval,
            FAN_OUT,
            inflight_ttl,
            SLEEP,
        )
        .clock(move || now)
        .build()
        .expect("construction succeeds");
        cmc.put_entry(b"k", make_entry_at(anchor, expiry))
            .await
            .expect("put");
        // Within the grace period, the get returns NoSuchEntry and marks the key inflight.
        let got = cmc.get_entry(b"k").await.expect("get succeeds");
        assert_eq!(
            got.is_none(),
            within,
            "grace_period {grace_period:?}: entry within grace period = {within}"
        );
    }
}

#[tokio::test]
async fn test_sub_second_grace_period_is_honored() {
    // expiry = anchor + 11ms; a 10 ms grace period starts at anchor + 1ms = now.
    let anchor = anchor_now();
    let expiry = anchor + Duration::from_millis(11);
    let now = anchor + Duration::from_millis(1);

    let cmc = storm_config(
        8,
        2,
        Duration::from_millis(10),
        Duration::from_millis(2),
        FAN_OUT,
        Duration::from_millis(5),
        SLEEP,
    )
    .clock(move || now)
    .build()
    .expect("construction succeeds");
    cmc.put_entry(b"k", make_entry_at(anchor, expiry))
        .await
        .expect("put");
    let got = cmc.get_entry(b"k").await.expect("get succeeds");

    assert!(
        got.is_none(),
        "a 10 ms grace period starting now puts the entry within it"
    );
}

// ── Group 3 — Builder defaults and validation ─────────────────────────────────

fn assert_rejected(result: Result<StormTrackingCmc, Error>, what: &str) {
    let err = result.expect_err(what);
    assert!(err.is_validation(), "{what}: {err:?}");
}

#[test]
fn test_builder_defaults() {
    let config = StormTrackingCmc::builder()
        .build()
        .expect("the defaults are consistent");
    assert_eq!(config.entry_capacity(), 1000);
    assert_eq!(config.entry_pruning_tail_size(), 1);
    assert_eq!(config.grace_period(), Some(Duration::from_secs(10)));
    assert_eq!(config.grace_interval(), Duration::from_secs(1));
    assert_eq!(config.fan_out(), 20);
    assert_eq!(config.inflight_ttl(), Duration::from_secs(10));
    assert_eq!(config.sleep(), Duration::from_millis(20));
}

#[test]
fn test_builder_applies_each_default_when_its_setter_is_omitted() {
    let config = StormTrackingCmc::builder()
        .entry_capacity(5000)
        .grace_period(Duration::from_secs(30))
        .build()
        .expect("valid config");
    assert_eq!(config.entry_capacity(), 5000);
    assert_eq!(config.grace_period(), Some(Duration::from_secs(30)));
    assert_eq!(config.entry_pruning_tail_size(), 1);
    assert_eq!(config.grace_interval(), Duration::from_secs(1));
    assert_eq!(config.fan_out(), 20);
    assert_eq!(config.inflight_ttl(), Duration::from_secs(10));
    assert_eq!(config.sleep(), Duration::from_millis(20));
}

#[test]
fn test_builder_set_none_applies_the_default() {
    let config = StormTrackingCmc::builder()
        .grace_interval(Duration::from_secs(5))
        .set_grace_interval(None)
        .set_fan_out(Some(3))
        .build()
        .expect("valid config");
    assert_eq!(config.grace_interval(), Duration::from_secs(1));
    assert_eq!(config.fan_out(), 3);
}

#[test]
fn test_invalid_settings_are_rejected() {
    assert_rejected(
        StormTrackingCmc::builder().fan_out(0).build(),
        "fan_out = 0",
    );
    assert_rejected(
        StormTrackingCmc::builder()
            .grace_interval(Duration::ZERO)
            .inflight_ttl(Duration::ZERO)
            .build(),
        "inflight_ttl = 0",
    );
    assert_rejected(
        StormTrackingCmc::builder().sleep(Duration::ZERO).build(),
        "sleep = 0",
    );
    assert_rejected(
        StormTrackingCmc::builder()
            .grace_interval(Duration::from_secs(2))
            .inflight_ttl(Duration::from_secs(1))
            .build(),
        "grace_interval > inflight_ttl",
    );
}

#[test]
fn test_durations_are_stored_exactly() {
    let grace_period = Duration::ZERO;
    let grace_interval = Duration::from_nanos(1_500);
    let inflight_ttl = Duration::from_secs(30);
    let sleep = Duration::from_nanos(1);
    let config = StormTrackingCmc::builder()
        .grace_period(grace_period)
        .grace_interval(grace_interval)
        .inflight_ttl(inflight_ttl)
        .sleep(sleep)
        .build()
        .expect("valid durations are accepted");
    assert_eq!(config.grace_period(), Some(grace_period));
    assert_eq!(config.grace_interval(), grace_interval);
    assert_eq!(config.inflight_ttl(), inflight_ttl);
    assert_eq!(config.sleep(), sleep);
}

// ── Group 4 — Behaviors ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_cmc_trait_surface_matches_local_cmc() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);

    let storm = SharedCmc::new(make_storm_tracking(now));
    let local = SharedCmc::new(
        LocalCmc::builder()
            .entry_capacity(32)
            .entry_pruning_tail_size(4)
            .clock(move || now)
            .build()
            .expect("LocalCmc constructs"),
    );

    for cmc in [&storm, &local] {
        cmc.put_entry(b"k", make_entry_at(now, expiry))
            .await
            .expect("put");
        let got = cmc.get_entry(b"k").await.expect("get");
        assert!(got.is_some(), "put-then-get succeeds on both Cmc impls");
        cmc.delete_entry(b"k").await.expect("delete");
        let after = cmc.get_entry(b"k").await.expect("get after delete");
        assert!(
            after.is_none(),
            "entry absent after delete on both Cmc impls"
        );
    }
}

// ── Group 5 — In Flight ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_inflight_records_most_recent_nosuchentry_time() {
    // Two calls at different timestamps must record the SECOND timestamp.
    let t1 = anchor_now();

    let cmc = make_storm_tracking(t1);
    // Expiry within grace period at t1.
    let expiry = t1 + GRACE_PERIOD - Duration::from_secs(1);
    cmc.put_entry(b"k", make_entry_at(t1, expiry))
        .await
        .expect("put");

    // First get at t1 — key not inflight → NoSuchEntry, marked at t1.
    let _ = cmc.get_entry(b"k").await.expect("first get");

    // Advance clock to t2, past grace_interval, and get again.
    // grace_interval = 2s, so use t1 + 3s to be outside the grace interval.
    let t2 = t1 + Duration::from_secs(3); // > grace_interval=2s
    let cmc2 = storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .clock(move || t2)
    .build()
    .expect("constructs");
    cmc2.put_entry(b"k", make_entry_at(t1, expiry))
        .await
        .expect("put");
    // Pre-mark as inflight at t1 so the second get triggers the "update" path.
    cmc2.mark_inflight(b"k", t1);

    let _ = cmc2.get_entry(b"k").await.expect("second get");

    let recorded = cmc2.peek_inflight(b"k").expect("key must be inflight");
    assert_eq!(
        recorded, t2,
        "inflight time must be updated to the most recent NoSuchEntry time"
    );
}

// ── Group 6 — PutCacheEntry ───────────────────────────────────────────────────

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

    cmc.put_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put succeeds");
    assert!(
        cmc.peek_inflight(b"k").is_none(),
        "key must not be inflight after put_cache_entry"
    );
}

// ── Group 7 — Within Grace Period ────────────────────────────────────────────

#[tokio::test]
async fn test_within_grace_period_matches_spec_formula() {
    use aws_crypto_mpl::cmc::__test_internals::within_grace_period;

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

// ── Group 8 — Within Grace Interval ─────────────────────────────────────────

#[tokio::test]
async fn test_within_grace_interval_matches_spec_formula() {
    use aws_crypto_mpl::cmc::__test_internals::within_grace_interval;

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

// ── Group 9 — GetCacheEntry ──────────────────────────────────────────────────

#[tokio::test]
async fn test_get_consults_inner_local_cmc() {
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);
    let cmc = make_storm_tracking(now);

    cmc.put_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");

    // Read from the inner LocalCmc directly — proves the wrapper delegated to it.
    let got = cmc.inner().get_entry(b"k").await.expect("inner get");
    assert!(
        got.is_some(),
        "entry written via the wrapper is visible in the inner LocalCmc"
    );
}

#[tokio::test]
async fn test_get_hit_returns_entry_when_fanout_saturated() {
    let now = anchor_now();
    // Expiry inside grace period (expiry - gp <= now).
    let expiry = now + GRACE_PERIOD - Duration::from_secs(1);
    let cmc = make_storm_tracking(now);

    // Put the entry and saturate the inflight map.
    cmc.put_entry(b"target", make_entry_at(now, expiry))
        .await
        .expect("put");
    for i in 0..FAN_OUT {
        cmc.mark_inflight(&[i as u8], now);
    }
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    let got = cmc.get_entry(b"target").await.expect("get succeeds");
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
    cmc.put_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");

    let got = cmc.get_entry(b"k").await.expect("get succeeds");
    assert!(
        got.is_some(),
        "entry outside grace period MUST be returned directly"
    );
}

#[tokio::test]
async fn test_get_hit_within_grace_not_inflight_returns_none_and_marks() {
    let now = anchor_now();
    // Expiry inside grace period.
    let expiry = now + GRACE_PERIOD - Duration::from_secs(1);
    let cmc = make_storm_tracking(now);
    cmc.put_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");

    let got = cmc.get_entry(b"k").await.expect("get succeeds");
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
    let expiry = now + GRACE_PERIOD - Duration::from_secs(1);
    let cmc = make_storm_tracking(now);
    cmc.put_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");
    // Mark as inflight very recently — well within grace_interval.
    let inflight_t = now - Duration::from_millis(100);
    cmc.mark_inflight(b"k", inflight_t);

    let got = cmc.get_entry(b"k").await.expect("get succeeds");
    assert!(
        got.is_some(),
        "within grace period AND inflight within interval MUST return the cache entry"
    );
}

#[tokio::test]
async fn test_get_hit_within_grace_inflight_outside_interval_returns_none_and_updates() {
    let now = anchor_now();
    // Expiry inside grace period.
    let expiry = now + GRACE_PERIOD - Duration::from_secs(1);
    let cmc = make_storm_tracking(now);
    cmc.put_entry(b"k", make_entry_at(now, expiry))
        .await
        .expect("put");
    // Mark as inflight at a time OUTSIDE the grace interval but WITHIN inflight TTL.
    // grace_interval=2s, inflight_ttl=5s; set inflight_t 3s ago → outside interval, within TTL.
    let inflight_t = now - Duration::from_secs(3);
    cmc.mark_inflight(b"k", inflight_t);

    let got = cmc.get_entry(b"k").await.expect("get succeeds");
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
    let cmc = storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .build()
    .expect("constructs");

    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(3600);

    // Saturate inflight with FAN_OUT distinct keys (not "target").
    for i in 0..FAN_OUT {
        cmc.mark_inflight(&[i as u8], now);
    }

    let cmc_getter = cmc.clone();
    let getter = tokio::spawn(async move { cmc_getter.get_entry(b"target").await });

    // Give the getter a moment to block, then put the entry.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let put_now = SystemTime::now();
    cmc.put_entry(b"target", make_entry_at(put_now, expiry))
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

    let got = cmc.get_entry(b"k").await.expect("get succeeds");
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
    let stale_t = now - (INFLIGHT_TTL + Duration::from_secs(1));
    cmc.mark_inflight(b"k", stale_t);

    let result = cmc.get_entry(b"k").await;
    assert!(
        result.is_err(),
        "inflight TTL exceeded MUST return an error"
    );
    let err = result.expect_err("error");
    let Error::Throttling(e) = &err else {
        panic!("expected Throttling, got {err:?}");
    };
    assert_eq!(e.retry_kind(), Some(RetryKind::Throttling));
    assert_eq!(e.service(), None);
    assert_eq!(e.resource(), Some(&Resource::Cache(Cache::new())));
    assert!(err.is_retryable());
}

#[tokio::test]
async fn test_get_miss_inflight_within_interval_blocks_until_unblocked() {
    // Real concurrency test — pre-mark inflight just now (within grace interval),
    // saturate fan-out so the only unblock path is "key appears in cache".
    let cmc = storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .build()
    .expect("constructs");

    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(3600);
    // Mark "target" inflight at `now` — 0s elapsed, well within grace_interval=2s.
    cmc.mark_inflight(b"target", now);
    // Saturate remaining FAN_OUT-1 slots with other keys so slot_open is false.
    for i in 0..(FAN_OUT - 1) {
        cmc.mark_inflight(&[100 + i as u8], now);
    }
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    let cmc_getter = cmc.clone();
    let getter = tokio::spawn(async move { cmc_getter.get_entry(b"target").await });

    // Pause briefly, then put the entry (which also clears "target" from inflight).
    tokio::time::sleep(Duration::from_millis(50)).await;
    let put_now = SystemTime::now();
    cmc.put_entry(b"target", make_entry_at(put_now, expiry))
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

    let got = cmc.get_entry(b"k").await.expect("get succeeds");
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
// a retryable `Throttling` error about the cache.
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

    let cmc = storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .clock(move || *clock_reader.lock().expect("clock lock"))
    .build()
    .expect("constructs");

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
    // start + INFLIGHT_TTL = start + 5s }.
    let cmc_getter = cmc.clone();
    let getter = tokio::spawn(async move { cmc_getter.get_entry(b"target").await });

    // Let the getter reach the wait loop.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Advance the clock past the per-waiter deadline. The mark_inflight
    // times stay at `start`, so the map-level state is unchanged; only
    // wall-clock advanced. Next iteration: sleep, cache miss, now >=
    // deadline → return Err.
    *clock.lock().expect("clock lock") = start + INFLIGHT_TTL + Duration::from_secs(1);

    let result = tokio::time::timeout(Duration::from_millis(500), getter)
        .await
        .expect("getter must complete after per-waiter deadline elapses")
        .expect("task joins");
    let err = result.expect_err("must be an error once the deadline fires");
    let Error::Throttling(e) = &err else {
        panic!("expected Throttling, got {err:?}");
    };
    assert_eq!(e.retry_kind(), Some(RetryKind::Throttling));
    assert_eq!(e.service(), None);
    assert_eq!(e.resource(), Some(&Resource::Cache(Cache::new())));
    assert!(err.is_retryable());
}

// ── Group 10 — Material Variant Coverage ─────────────────────────────────────

#[tokio::test]
async fn test_all_material_variants_round_trip() {
    // The wrapper's storage path is variant-agnostic — this test asserts
    // every `CachedMaterials` variant survives a put/get round-trip, not
    // only the `Encryption` variant exercised by the rest of this file.
    let now = anchor_now();
    let expiry = now + Duration::from_secs(3600);
    let usage = UsageMetadata::builder()
        .messages_used(0)
        .bytes_used(0)
        .build()
        .expect("usage metadata builds");

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
        cmc.put_entry(
            b"id",
            CacheEntry::builder()
                .materials(materials)
                .creation_time(now)
                .expiry_time(expiry)
                .usage_metadata(usage)
                .build()
                .expect("cache entry builds"),
        )
        .await
        .expect("put succeeds");

        let got = cmc
            .get_entry(b"id")
            .await
            .expect("get succeeds")
            .unwrap_or_else(|| panic!("{label}: entry is present after put"));

        let got_variant = match &got.materials() {
            CachedMaterials::Encryption(_) => "Encryption",
            CachedMaterials::Decryption(_) => "Decryption",
            CachedMaterials::BranchKey(_) => "BranchKey",
            CachedMaterials::BeaconKey(_) => "BeaconKey",
            other => panic!("unexpected cached materials {other:?}"),
        };
        assert_eq!(
            got_variant, label,
            "materials variant must be preserved through put/get"
        );
        assert_eq!(
            got.creation_time(),
            now,
            "{label}: creation_time must round-trip"
        );
        assert_eq!(
            got.expiry_time(),
            expiry,
            "{label}: expiry_time must round-trip"
        );
        assert_eq!(
            got.usage_metadata(),
            usage,
            "{label}: usage_metadata must round-trip"
        );
    }
}

// ── Group 11 — Bug Reproduction Tests (Copilot PR #33 review) ────────────────

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

    let cmc = storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .clock(move || *clock_reader.lock().expect("clock lock"))
    .build()
    .expect("constructs");

    for i in 0..FAN_OUT {
        cmc.mark_inflight(&[i as u8], start);
    }
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    let cmc_getter = cmc.clone();
    let getter = tokio::spawn(async move { cmc_getter.get_entry(b"new-key").await });

    // Let the getter enter the block loop.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Every pre-marked entry is now stale relative to the advanced clock.
    *clock.lock().expect("clock lock") = start + INFLIGHT_TTL + Duration::from_secs(10);

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
        Some(start + INFLIGHT_TTL + Duration::from_secs(10)),
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
    const GRACE_INTERVAL: Duration = Duration::from_secs(10);
    const INFLIGHT_TTL: Duration = Duration::from_secs(20);
    const GRACE_PERIOD: Duration = Duration::from_secs(30);

    let start = anchor_now();
    let clock = Arc::new(StdMutex::new(start));
    let clock_reader = Arc::clone(&clock);

    let cmc = storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .clock(move || *clock_reader.lock().expect("clock lock"))
    .build()
    .expect("constructs");

    // Saturate fan-out: target + 2 other keys, all inflight at start.
    cmc.mark_inflight(b"target", start);
    cmc.mark_inflight(&[1], start);
    cmc.mark_inflight(&[2], start);
    assert_eq!(cmc.inflight_count(), FAN_OUT);

    let cmc_getter = cmc.clone();
    let getter = tokio::spawn(async move { cmc_getter.get_entry(b"target").await });

    // Let the getter enter the block loop.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Free two fan-out slots by putting the saturators. Under the fix,
    // put clears their inflight after writing cache — either way, once
    // both puts land the inflight map holds only `target`.
    let entry_expiry = start + Duration::from_secs(3600);
    cmc.put_entry(&[1], make_entry_at(start, entry_expiry))
        .await
        .expect("put saturator 1");
    cmc.put_entry(&[2], make_entry_at(start, entry_expiry))
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
    *clock.lock().expect("clock lock") = start + GRACE_INTERVAL + Duration::from_secs(1);

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
        inflight_time >= start + GRACE_INTERVAL,
        "target must be marked inflight after grace interval elapsed \
         (got {inflight_time:?}, expected >= start + {GRACE_INTERVAL:?}); \
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

    const GRACE_INTERVAL: Duration = Duration::from_secs(10);
    const INFLIGHT_TTL: Duration = Duration::from_secs(10);
    const GRACE_PERIOD: Duration = Duration::from_secs(30);

    let start = anchor_now();
    let clock = Arc::new(StdMutex::new(start));
    let clock_reader = Arc::clone(&clock);

    let cmc = storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .clock(move || *clock_reader.lock().expect("clock lock"))
    .build()
    .expect("constructs");

    // Mark target inflight at start; saturate fan-out with other keys.
    cmc.mark_inflight(b"target", start);
    cmc.mark_inflight(&[1], start);
    cmc.mark_inflight(&[2], start);

    // Advance clock 5s. Target has now been inflight (per map) for 5s
    // (still within TTL=10s, so decide passes and returns BlockMissInflight).
    *clock.lock().expect("clock lock") = start + Duration::from_secs(5);

    // Spawn getter. decide reads captured inflight_t = start, elapsed=5.
    // Getter's enter_time is start+5 → per-waiter deadline = start+15.
    let cmc_getter = cmc.clone();
    let getter = tokio::spawn(async move { cmc_getter.get_entry(b"target").await });

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
    cmc.put_entry(
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

// ── Group 12 — Storm Coalescing ──────────────────────────────────────────────

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

    let cmc = storm_config(
        32,
        4,
        GRACE_PERIOD,
        GRACE_INTERVAL,
        STORM_FAN_OUT,
        INFLIGHT_TTL,
        SLEEP,
    )
    .build()
    .expect("constructs");

    let leader_count = Arc::new(AtomicUsize::new(0));
    let waiter_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(N_TASKS);
    for _ in 0..N_TASKS {
        let cmc = cmc.clone();
        let leader_count = Arc::clone(&leader_count);
        let waiter_count = Arc::clone(&waiter_count);
        handles.push(tokio::spawn(async move {
            match cmc.get_entry(b"target").await.expect("get_cache_entry Ok") {
                None => {
                    // Elected leader: simulate the "go fetch" latency
                    // callers would incur in production, then publish
                    // the fresh entry.
                    leader_count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(LEADER_FETCH_DELAY_MS)).await;
                    let now = SystemTime::now();
                    let expiry = now + Duration::from_secs(3600);
                    cmc.put_entry(b"target", make_entry_at(now, expiry))
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

#[tokio::test]
async fn test_clone_shares_entries_with_original() {
    let now = anchor_now();
    let original = make_storm_tracking(now);
    let clone = original.clone();

    original
        .put_entry(b"id-1", make_entry_at(now, now + Duration::from_secs(3600)))
        .await
        .expect("put succeeds");

    assert!(
        clone
            .get_entry(b"id-1")
            .await
            .expect("get succeeds")
            .is_some(),
        "an entry put through the original MUST be visible through a clone"
    );
}
