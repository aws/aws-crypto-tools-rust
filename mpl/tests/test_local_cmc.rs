// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for [`aws_crypto_mpl::cmc::LocalCmc`].
//!
//! These tests exercise the local CMC's public `Cmc` trait surface and the
//! LocalCmc-specific behaviors defined in
//! `../spec/framework/local-cryptographic-materials-cache.md`. They also
//! discharge the abstract CMC-trait requirements that the concrete LocalCmc
//! now realizes (TTL enforcement, "must create a new cache entry", "must
//! include all usage metadata", and the "updating usage metadata SHOULD be
//! atomic" SHOULD).
//!
//! The cache's clock is injected via [`LocalCmc::with_clock`] so TTL and
//! pruning tests advance time deterministically without sleeping.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_crypto_mpl::cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, LocalCmc, MessageUsage, UsageMetadata,
};
use aws_crypto_mpl::structures::{AlgorithmSuiteId, EncryptionContext, EncryptionMaterials};

// Fixtures

const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;

/// TTL offset for entries that should be TTL-expired against `FROZEN_NOW_OFFSET`.
/// `creation + TTL_EXPIRED_OFFSET < creation + FROZEN_NOW_OFFSET` so any entry
/// stamped with this expiry is past expiry the moment the test reads time.
const TTL_EXPIRED_OFFSET: Duration = Duration::from_secs(60);

/// "Now" offset used by frozen-clock tests. Sits strictly between
/// `TTL_EXPIRED_OFFSET` (so expired entries ARE expired) and
/// `TTL_FRESH_OFFSET` (so fresh entries are NOT yet expired).
const FROZEN_NOW_OFFSET: Duration = Duration::from_secs(120);

/// TTL offset for entries that should remain fresh against `FROZEN_NOW_OFFSET`.
/// `creation + TTL_FRESH_OFFSET > creation + FROZEN_NOW_OFFSET`.
const TTL_FRESH_OFFSET: Duration = Duration::from_secs(7200);

/// Standard expiry offset used by tests that don't care about TTL behavior
/// (they want a comfortably-in-the-future expiry so the entry never expires
/// during the test body).
const STANDARD_TTL: Duration = Duration::from_secs(3600);

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

fn make_entry_at(creation: SystemTime, expiry: SystemTime) -> CacheEntry {
    CacheEntry::new(
        CachedMaterials::Encryption(make_encryption_materials()),
        creation,
        expiry,
        UsageMetadata::new(MessageUsage(0), BytesUsage(0)),
    )
}

fn make_entry_with_usage(
    creation: SystemTime,
    expiry: SystemTime,
    usage: UsageMetadata,
) -> CacheEntry {
    CacheEntry::new(
        CachedMaterials::Encryption(make_encryption_materials()),
        creation,
        expiry,
        usage,
    )
}

/// A reference instant used as the "now" anchor for tests that mix fresh
/// and TTL-expired entries.
fn anchor_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

// Initialization + entry capacity boundary

#[tokio::test]
async fn test_initialization_accepts_zero_and_max_capacity() {
    // Zero endpoint — caller may configure a no-store cache. The "MUST NOT
    // store more entries than this value" constraint reduces to "store
    // nothing": any put must leave `len() == 0` once the post-eviction
    // sweep has run.
    //= ../spec/framework/local-cryptographic-materials-cache.md#initialization
    //= type=test
    //# On initialization of the local CMC,
    //# the caller MUST provide the following:
    //
    //= ../spec/framework/local-cryptographic-materials-cache.md#entry-capacity
    //= type=test
    //# The local CMC MUST accept entry capacity values between zero
    //# and an implementation-defined maximum, inclusive.
    let zero_cap = LocalCmc::new(0, 1).expect("zero capacity is accepted");
    assert_eq!(zero_cap.entry_capacity(), 0);

    // Sanity: a put on a zero-capacity cache returns Ok and the
    // post-condition `len <= entry_capacity` holds (i.e., len == 0).
    let creation = anchor_now();
    let expiry = creation + STANDARD_TTL;
    zero_cap
        .put_cache_entry(b"id", make_entry_at(creation, expiry))
        .await
        .expect("put on zero-capacity cache succeeds");
    assert_eq!(
        zero_cap.len().expect("len succeeds"),
        0,
        "post-put len MUST be 0 for a zero-capacity cache"
    );

    // Maximum endpoint — implementation-defined max is `usize::MAX`.
    let max_cap = LocalCmc::new(usize::MAX, 1).expect("usize::MAX capacity is accepted");
    assert_eq!(max_cap.entry_capacity(), usize::MAX);
}

// Put + capacity invariants

#[tokio::test]
async fn test_put_within_capacity_does_not_evict() {
    let now = anchor_now();
    let cmc = LocalCmc::with_clock(4, 2, move || now).expect("LocalCmc constructs");
    let creation = now;
    let expiry = now + STANDARD_TTL;

    for i in 0..3u8 {
        cmc.put_cache_entry(&[i], make_entry_at(creation, expiry))
            .await
            .expect("put succeeds");
    }

    assert_eq!(cmc.len().expect("len succeeds"), 3);
    for i in 0..3u8 {
        let got = cmc
            .get_cache_entry(&[i])
            .await
            .expect("get succeeds")
            .expect("id {i} survives within-capacity puts");
        assert_eq!(
            got.expiry_time, expiry,
            "id {i} returns the expiry_time it was put with",
        );
        assert_eq!(
            got.creation_time, creation,
            "id {i} returns the creation_time it was put with",
        );
    }
}

#[tokio::test]
async fn test_put_over_capacity_evicts_lru() {
    let now = anchor_now();
    let cmc = LocalCmc::with_clock(2, 1, move || now).expect("LocalCmc constructs");
    let creation = now;
    let expiry = now + STANDARD_TTL;

    cmc.put_cache_entry(b"oldest", make_entry_at(creation, expiry))
        .await
        .expect("put oldest succeeds");
    cmc.put_cache_entry(b"middle", make_entry_at(creation, expiry))
        .await
        .expect("put middle succeeds");
    //= ../spec/framework/local-cryptographic-materials-cache.md#put-cache-entry
    //= type=test
    //# While performing a Put Cache Entry operation,
    //# the local CMC MAY store more entries than the entry capacity.
    cmc.put_cache_entry(b"newest", make_entry_at(creation, expiry))
        .await
        .expect("put newest succeeds even though cache was at capacity");

    //= ../spec/framework/local-cryptographic-materials-cache.md#put-cache-entry
    //= type=test
    //# However, before returning, the local CMC MUST evict least-recently used entries
    //# until the number of stored entries does not exceed the entry capacity.
    let evicted = cmc.get_cache_entry(b"oldest").await.expect("get succeeds");
    assert!(evicted.is_none(), "oldest LRU entry MUST have been evicted");
}

#[tokio::test]
async fn test_capacity_invariant_holds_after_put_returns() {
    let now = anchor_now();
    let capacity = 2_usize;
    let cmc = LocalCmc::with_clock(capacity, 1, move || now).expect("LocalCmc constructs");
    let creation = now;
    let expiry = now + STANDARD_TTL;

    for i in 0..5u8 {
        cmc.put_cache_entry(&[i], make_entry_at(creation, expiry))
            .await
            .expect("put succeeds");
        //= ../spec/framework/local-cryptographic-materials-cache.md#entry-capacity
        //= type=test
        //# The local CMC MUST NOT store more entries than this value,
        //# except temporarily while performing a Put Cache Entry operation.
        assert!(
            cmc.len().expect("len succeeds") <= capacity,
            "post-put size MUST stay at or below the configured capacity"
        );
    }
}

// TTL behavior

#[tokio::test]
async fn test_get_drops_ttl_expired_entry() {
    // Anchor "now" *after* the entry's expiry so the requested entry is
    // TTL-expired the moment we call get.
    let creation = anchor_now();
    let expiry = creation + TTL_EXPIRED_OFFSET;
    let frozen_now = expiry + Duration::from_secs(1);
    let cmc = LocalCmc::with_clock(8, 8, move || frozen_now).expect("LocalCmc constructs");

    cmc.put_cache_entry(b"expiring", make_entry_at(creation, expiry))
        .await
        .expect("put succeeds");

    //= ../spec/framework/local-cryptographic-materials-cache.md#get-cache-entry
    //= type=test
    //# The local CMC MUST NOT return any TTL-expired entry.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#time-to-live-ttl
    //= type=test
    //# After a cache entry's TTL has elapsed,
    //# we say that the entry is _TTL-expired_,
    //# and a CMC MUST NOT return the entry to any caller.
    //
    //= ../spec/framework/cryptographic-materials-cache.md#get-cache-entry
    //= type=test
    //# The CMC MUST validate that the cache entry
    //# has not exceeded it's stored [TTL](#time-to-live-ttl).
    let got = cmc
        .get_cache_entry(b"expiring")
        .await
        .expect("get succeeds");
    assert!(got.is_none(), "TTL-expired entry MUST NOT be returned");
}

#[tokio::test]
async fn test_get_at_exact_expiry_returns_none() {
    // Boundary: `frozen_now == entry.expiry_time` exactly. The
    // implementation uses `entry.expiry_time <= now` (inclusive on the
    // expired side) in BOTH the get-side TTL check and `prune_tail`, so an
    // entry whose expiry equals "now" is TTL-expired and MUST NOT be
    // returned. This test pins the `<=` boundary so a refactor to `<`
    // (which would silently leak one tick of stale entries) fails loudly.
    let creation = anchor_now();
    let expiry = creation + TTL_EXPIRED_OFFSET;
    let frozen_now = expiry; // exact boundary — no offset
    let cmc = LocalCmc::with_clock(8, 8, move || frozen_now).expect("LocalCmc constructs");

    cmc.put_cache_entry(b"at-expiry", make_entry_at(creation, expiry))
        .await
        .expect("put succeeds");

    // No new `//= type=test` block here — `test_get_drops_ttl_expired_entry`
    // already carries the `#get-cache-entry` "MUST NOT return TTL-expired"
    // citation. This test strengthens the SAME requirement at the
    // `<=` boundary so a future refactor to `<` fails loudly.
    let got = cmc
        .get_cache_entry(b"at-expiry")
        .await
        .expect("get succeeds");
    assert!(
        got.is_none(),
        "entry whose expiry_time == now MUST NOT be returned",
    );

    // The exact-at-expiry boundary applies in `prune_tail` too: the
    // 8-entry tail window covers our single entry, so the prune step
    // inside get evicts it. A subsequent len() must read zero.
    assert_eq!(
        cmc.len().expect("len succeeds"),
        0,
        "exact-at-expiry entry MUST be evicted by the prune step inside get",
    );
}

#[tokio::test]
async fn test_get_prunes_tail_window() {
    // Set up: cache with tail size 3. Insert 5 entries; the 3 LRU entries
    // are TTL-expired; the 2 MRU entries are fresh. A single get on a
    // fresh entry must trigger a prune that removes the 3 expired ones.
    let creation = anchor_now();
    let expired = creation + TTL_EXPIRED_OFFSET;
    let fresh = creation + TTL_FRESH_OFFSET;
    let frozen_now = creation + FROZEN_NOW_OFFSET; // past `expired`, before `fresh`
    let cmc = LocalCmc::with_clock(10, 3, move || frozen_now).expect("LocalCmc constructs");

    // Insert 3 expired (will be the LRU tail) followed by 2 fresh.
    for i in 0..3u8 {
        cmc.put_cache_entry(&[b'e', i], make_entry_at(creation, expired))
            .await
            .expect("put expired succeeds");
    }
    for i in 0..2u8 {
        cmc.put_cache_entry(&[b'f', i], make_entry_at(creation, fresh))
            .await
            .expect("put fresh succeeds");
    }
    assert_eq!(cmc.len().expect("len succeeds"), 5);

    // Trigger a get on a fresh entry — the prune-on-get pass should drop
    // every TTL-expired entry in the LRU tail before returning.
    //= ../spec/framework/local-cryptographic-materials-cache.md#get-cache-entry
    //= type=test
    //# When performing a Get Cache Entry operation,
    //# the local CMC MUST [prune TTL-expired cache entries](#pruning).
    let _ = cmc
        .get_cache_entry(&[b'f', 0])
        .await
        .expect("get on fresh entry succeeds");

    assert_eq!(
        cmc.len().expect("len succeeds"),
        2,
        "every TTL-expired entry in the LRU tail MUST be pruned by get"
    );
}

#[tokio::test]
async fn test_pruning_evicts_all_ttl_expired_in_tail() {
    // Tail size 4; 4 LRU entries are TTL-expired; one MRU entry is fresh.
    // After a single prune (driven by get), every expired tail entry must
    // be gone.
    let creation = anchor_now();
    let expired = creation + TTL_EXPIRED_OFFSET;
    let fresh = creation + TTL_FRESH_OFFSET;
    let frozen_now = creation + FROZEN_NOW_OFFSET;
    let cmc = LocalCmc::with_clock(10, 4, move || frozen_now).expect("LocalCmc constructs");

    for i in 0..4u8 {
        cmc.put_cache_entry(&[b'e', i], make_entry_at(creation, expired))
            .await
            .expect("put expired succeeds");
    }
    cmc.put_cache_entry(b"fresh", make_entry_at(creation, fresh))
        .await
        .expect("put fresh succeeds");

    // Drive prune via a get on the fresh entry.
    let _ = cmc.get_cache_entry(b"fresh").await.expect("get succeeds");

    //= ../spec/framework/local-cryptographic-materials-cache.md#pruning
    //= type=test
    //# To prune TTL-expired cache entries,
    //# the local CMC MUST evict all TTL-expired entries
    //# among the `N` least recently used entries,
    //# where `N` is the [Entry Pruning Tail Size](#entry-pruning-tail-size).
    for i in 0..4u8 {
        let got = cmc.get_cache_entry(&[b'e', i]).await.expect("get succeeds");
        assert!(
            got.is_none(),
            "TTL-expired entry e{i} MUST be evicted by pruning"
        );
    }
}

#[tokio::test]
async fn test_pruning_does_not_evict_outside_tail() {
    // Tail size 2; insert one TTL-expired entry FIRST (so it is the LRU
    // tail entry), then insert 4 fresh entries (so the expired one is at
    // position 0 of the LRU vec while positions 1..5 are fresh). The
    // configured tail size is 2, so a prune scans only positions 0 and 1.
    // Position 0 is expired → evicted. We then insert ANOTHER expired
    // entry but place it at LRU position 4 by getting it last — we want
    // to prove that an expired entry OUTSIDE the tail window survives.
    //
    // Easier construction: configure tail size 1 and put one fresh entry
    // first (LRU tail), then put a TTL-expired entry that becomes MRU,
    // then trigger prune via a get on a different id. The expired entry
    // is at the MRU end (outside the 1-entry tail window) and must
    // survive.
    let creation = anchor_now();
    let expired = creation + TTL_EXPIRED_OFFSET;
    let fresh = creation + TTL_FRESH_OFFSET;
    let frozen_now = creation + FROZEN_NOW_OFFSET;

    //= ../spec/framework/local-cryptographic-materials-cache.md#initialization
    //= type=test
    //# The local CMC MUST also define the following:
    let cmc = LocalCmc::with_clock(10, 1, move || frozen_now).expect("LocalCmc constructs");
    assert_eq!(cmc.entry_pruning_tail_size(), 1);

    // Put a fresh entry first — this becomes the LRU tail.
    cmc.put_cache_entry(b"fresh-tail", make_entry_at(creation, fresh))
        .await
        .expect("put fresh-tail succeeds");
    // Put a TTL-expired entry — this becomes the MRU end (outside the
    // 1-entry tail window).
    cmc.put_cache_entry(b"expired-mru", make_entry_at(creation, expired))
        .await
        .expect("put expired-mru succeeds");

    // Trigger a prune by getting an unrelated id (cache miss still
    // executes the prune step before lookup).
    let _ = cmc
        .get_cache_entry(b"unrelated")
        .await
        .expect("get unrelated succeeds");

    //= ../spec/framework/local-cryptographic-materials-cache.md#entry-pruning-tail-size
    //= type=test
    //# The _entry pruning tail size_
    //# is the number of least recently used entries that the local CMC
    //# MUST check during [pruning](#pruning)
    //# for TTL-expired entries to evict.
    assert_eq!(
        cmc.len().expect("len succeeds"),
        2,
        "an expired entry outside the tail window MUST NOT be evicted by pruning"
    );
}

// Abstract-trait MUSTs realized by LocalCmc

#[tokio::test]
async fn test_put_then_get_returns_inserted_entry() {
    let now = anchor_now();
    let cmc = LocalCmc::with_clock(4, 1, move || now).expect("LocalCmc constructs");
    let creation = now;
    let expiry = now + STANDARD_TTL;

    let entry = make_entry_at(creation, expiry);
    let expected_creation = entry.creation_time;
    let expected_expiry = entry.expiry_time;
    cmc.put_cache_entry(b"id-1", entry)
        .await
        .expect("put succeeds");

    //= ../spec/framework/cryptographic-materials-cache.md#put-cache-entry
    //= type=test
    //# The CMC MUST create a new cache entry for the specified cache ID.
    let got = cmc
        .get_cache_entry(b"id-1")
        .await
        .expect("get succeeds")
        .expect("entry is present");
    assert_eq!(got.creation_time, expected_creation);
    assert_eq!(got.expiry_time, expected_expiry);
}

#[tokio::test]
async fn test_usage_metadata_round_trips_through_put_get() {
    let now = anchor_now();
    let cmc = LocalCmc::with_clock(4, 1, move || now).expect("LocalCmc constructs");
    let creation = now;
    let expiry = now + STANDARD_TTL;
    let usage = UsageMetadata::new(MessageUsage(7), BytesUsage(2048));

    cmc.put_cache_entry(b"id-usage", make_entry_with_usage(creation, expiry, usage))
        .await
        .expect("put succeeds");

    let got = cmc
        .get_cache_entry(b"id-usage")
        .await
        .expect("get succeeds")
        .expect("entry is present");

    assert_eq!(got.usage_metadata, usage);
}

#[tokio::test]
async fn test_concurrent_put_atomic_visibility() {
    let now = anchor_now();
    let cmc = Arc::new(LocalCmc::with_clock(4, 1, move || now).expect("LocalCmc constructs"));
    let creation = now;
    let expiry = now + STANDARD_TTL;

    let usage_a = UsageMetadata::new(MessageUsage(11), BytesUsage(111));
    let usage_b = UsageMetadata::new(MessageUsage(22), BytesUsage(222));

    let cmc_a = Arc::clone(&cmc);
    let cmc_b = Arc::clone(&cmc);

    let task_a = tokio::spawn(async move {
        cmc_a
            .put_cache_entry(
                b"shared-id",
                make_entry_with_usage(creation, expiry, usage_a),
            )
            .await
    });
    let task_b = tokio::spawn(async move {
        cmc_b
            .put_cache_entry(
                b"shared-id",
                make_entry_with_usage(creation, expiry, usage_b),
            )
            .await
    });

    task_a
        .await
        .expect("task a joins")
        .expect("task a put succeeds");
    task_b
        .await
        .expect("task b joins")
        .expect("task b put succeeds");

    let got = cmc
        .get_cache_entry(b"shared-id")
        .await
        .expect("get succeeds")
        .expect("entry is present");

    // Whichever put won, the stored usage metadata must equal one of the
    // two supplied values verbatim (no torn read across the two fields).
    //= ../spec/framework/cryptographic-materials-cache.md#usage-metadata
    //= type=test
    //# Updating usage metadata SHOULD be atomic.
    assert!(
        got.usage_metadata == usage_a || got.usage_metadata == usage_b,
        "concurrent puts MUST yield one of the two supplied UsageMetadata values, observed {:?}",
        got.usage_metadata
    );
}

// Delete

#[tokio::test]
async fn test_delete_existing_entry_then_get_returns_none() {
    let now = anchor_now();
    let cmc = LocalCmc::with_clock(4, 1, move || now).expect("LocalCmc constructs");
    let creation = now;
    let expiry = now + STANDARD_TTL;

    cmc.put_cache_entry(b"id-to-delete", make_entry_at(creation, expiry))
        .await
        .expect("put succeeds");
    cmc.delete_cache_entry(b"id-to-delete")
        .await
        .expect("delete succeeds");

    let got = cmc
        .get_cache_entry(b"id-to-delete")
        .await
        .expect("get succeeds");
    assert!(got.is_none(), "deleted id returns None");
}

#[tokio::test]
async fn test_delete_missing_entry_returns_ok() {
    let cmc = LocalCmc::new(4, 1).expect("LocalCmc constructs");
    cmc.delete_cache_entry(b"never-inserted")
        .await
        .expect("delete on missing id MUST succeed");
}
