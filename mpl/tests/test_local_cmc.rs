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
//!
//! ## Deterministic clock pattern
//!
//! To test the cache eviction behavior without having to wait for the ttl
//! to expire, the cache asks a function "what time is it?";
//! the test controls that function.
//! Freezing the clock means the function always returns the same value.
//! The `move` keyword is Rust's way of making sure the frozen value
//! stays alive as long as the cache does.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_crypto_mpl::cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, LocalCmc, MessageUsage, UsageMetadata,
};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptionContext, EncryptionMaterials,
};

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
    //
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

    // Get on a zero-capacity cache returns Ok(None) — nothing was stored.
    let got = zero_cap
        .get_cache_entry(b"id")
        .await
        .expect("get on zero-capacity cache succeeds");
    assert!(
        got.is_none(),
        "zero-capacity cache MUST NOT return an entry"
    );

    // Delete on a zero-capacity cache is a no-op that returns Ok.
    zero_cap
        .delete_cache_entry(b"id")
        .await
        .expect("delete on zero-capacity cache succeeds");

    // Upper endpoint — a comfortably-large capacity is accepted. The
    // underlying `lru::LruCache` pre-allocates its hashmap with the
    // supplied capacity, so `usize::MAX` is not representable in practice;
    // this bound exercises the config layer's lack of an artificial cap
    // without asking the allocator for an impossible amount of memory.
    const LARGE_CAP: usize = 1_000_000;
    let large_cap = LocalCmc::new(LARGE_CAP, 1).expect("large capacity is accepted");
    assert_eq!(large_cap.entry_capacity(), LARGE_CAP);
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
            .unwrap_or_else(|| panic!("id {i} survives within-capacity puts"));
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
    cmc.put_cache_entry(b"newest", make_entry_at(creation, expiry))
        .await
        .expect("put newest succeeds even though cache was at capacity");

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
    // Tail size 1. Put a fresh entry first — it becomes the LRU tail.
    // Then put a TTL-expired entry — it becomes MRU, sitting OUTSIDE the
    // 1-entry pruning tail window. Trigger a prune via a get on an
    // unrelated id; the prune scans only the fresh LRU entry (kept), and
    // the expired MRU entry MUST survive.
    let creation = anchor_now();
    let expired = creation + TTL_EXPIRED_OFFSET;
    let fresh = creation + TTL_FRESH_OFFSET;
    let frozen_now = creation + FROZEN_NOW_OFFSET;

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
    let creation = now;
    let expiry = now + STANDARD_TTL;
    let usage = UsageMetadata::new(MessageUsage(7), BytesUsage(2048));

    // Exercise every `CachedMaterials` variant so this test discharges the
    // abstract-trait "must include all usage metadata" requirement across
    // the entire enum, not just the encryption variant.
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
        let cmc = LocalCmc::with_clock(4, 1, move || now).expect("LocalCmc constructs");
        let entry = CacheEntry::new(materials, creation, expiry, usage);
        cmc.put_cache_entry(b"id-usage", entry)
            .await
            .expect("put succeeds");

        let got = cmc
            .get_cache_entry(b"id-usage")
            .await
            .expect("get succeeds")
            .unwrap_or_else(|| panic!("{label}: entry is present"));

        assert_eq!(
            got.usage_metadata, usage,
            "{label}: usage metadata must round-trip through put/get"
        );
        assert_eq!(
            got.creation_time, creation,
            "{label}: creation_time must round-trip through put/get"
        );
        assert_eq!(
            got.expiry_time, expiry,
            "{label}: expiry_time must round-trip through put/get"
        );
    }
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

#[tokio::test]
async fn test_is_empty_reflects_stored_count() {
    let now = anchor_now();
    let cmc = LocalCmc::with_clock(4, 1, move || now).expect("LocalCmc constructs");

    // Fresh cache is empty.
    assert!(cmc.is_empty().expect("is_empty succeeds"));

    let creation = now;
    let expiry = now + STANDARD_TTL;
    cmc.put_cache_entry(b"id", make_entry_at(creation, expiry))
        .await
        .expect("put succeeds");
    assert!(
        !cmc.is_empty().expect("is_empty succeeds"),
        "cache with a live entry MUST NOT report empty"
    );

    cmc.delete_cache_entry(b"id")
        .await
        .expect("delete succeeds");
    assert!(
        cmc.is_empty().expect("is_empty succeeds"),
        "cache MUST report empty after deleting its only entry"
    );
}

#[tokio::test]
async fn test_get_evicts_expired_entry_outside_tail_window() {
    // A TTL-expired entry sitting OUTSIDE the pruning tail window still
    // MUST NOT be returned by a direct `get` on that id. The prune step
    // will skip it (it's not in the tail window), so the get path itself
    // is responsible for the eviction — this exercises the peek-then-pop
    // branch that fires when peek reports an expired entry.
    let creation = anchor_now();
    let expired = creation + TTL_EXPIRED_OFFSET;
    let fresh = creation + TTL_FRESH_OFFSET;
    let frozen_now = creation + FROZEN_NOW_OFFSET;

    let cmc = LocalCmc::with_clock(10, 1, move || frozen_now).expect("LocalCmc constructs");

    // Put a fresh entry first — this becomes the LRU tail entry.
    cmc.put_cache_entry(b"fresh-tail", make_entry_at(creation, fresh))
        .await
        .expect("put fresh-tail succeeds");
    // Put a TTL-expired entry — this becomes MRU and lies OUTSIDE the
    // 1-entry pruning tail window.
    cmc.put_cache_entry(b"expired-mru", make_entry_at(creation, expired))
        .await
        .expect("put expired-mru succeeds");

    // A direct get on the expired MRU entry MUST NOT return it, even
    // though the tail-window prune would not have touched it.
    let got = cmc
        .get_cache_entry(b"expired-mru")
        .await
        .expect("get succeeds");
    assert!(
        got.is_none(),
        "TTL-expired entry outside the tail window MUST NOT be returned by get"
    );

    // And it MUST have been evicted from the cache — a follow-up get
    // remains a miss.
    assert!(
        cmc.get_cache_entry(b"expired-mru")
            .await
            .expect("get succeeds")
            .is_none(),
        "expired entry MUST be evicted by the get that observed it"
    );
    assert_eq!(
        cmc.len().expect("len succeeds"),
        1,
        "only the fresh-tail entry remains"
    );
}
