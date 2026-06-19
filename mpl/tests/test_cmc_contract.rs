// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract tests for the abstract `Cmc` trait.
//!
//! These tests verify the abstract `Cmc` trait contract via the in-file
//! `MockCmc`. They are intentionally NOT duvet-annotated — the corresponding
//! requirements are annotated as `type=exception` in `src/cmc/mod.rs` (and
//! `type=implication` for the structural ones in `src/cmc/entry.rs`) and
//! will be re-annotated as `type=implementation,test` once concrete CMCs
//! (LocalCmc, SynchronizedLocalCmc, StormTrackerCmc) are added.
//!
//! The mock's `put_cache_entry` / `get_cache_entry` / `delete_cache_entry`
//! exercise every documented branch of the CMC interface (put-then-get,
//! miss on different ID, TTL-expired returns miss, replace-on-put, delete
//! existing/missing, and round-trip through every `CachedMaterials`
//! variant).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use aws_crypto_mpl::cmc::{
    BytesUsage, CacheEntry, CachedMaterials, Cmc, CmcError, MessageUsage, UsageMetadata,
};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptionContext, EncryptionMaterials,
};

// MockCmc

/// Configurable in-memory mock CMC used to exercise the `Cmc` trait
/// contract. Storage is a `BTreeMap<Vec<u8>, Arc<CacheEntry>>`; clock is
/// injected via a closure so tests can deterministically advance time past
/// an entry's TTL.
struct MockCmc {
    store: Mutex<BTreeMap<Vec<u8>, Arc<CacheEntry>>>,
    /// `now` returns the wall-clock instant the cache should compare
    /// against entry TTLs. Tests override it to fast-forward past a TTL.
    now: Box<dyn Fn() -> SystemTime + Send + Sync>,
}

impl MockCmc {
    fn new() -> Self {
        Self {
            store: Mutex::new(BTreeMap::new()),
            now: Box::new(SystemTime::now),
        }
    }

    fn with_clock<F>(now: F) -> Self
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        Self {
            store: Mutex::new(BTreeMap::new()),
            now: Box::new(now),
        }
    }
}

#[async_trait]
impl Cmc for MockCmc {
    async fn put_cache_entry(&self, cache_id: &[u8], entry: CacheEntry) -> Result<(), CmcError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| CmcError::storage_failed(format!("MockCmc lock poisoned: {e}")))?;
        // "If a cache entry for the given cache ID exists in the cache, it
        // must be removed." `BTreeMap::insert` does exactly that — replaces
        // any prior entry — and the spec also says the put MUST NOT return
        // the prior entry, which `Result<(), CmcError>` enforces.
        store.insert(cache_id.to_vec(), Arc::new(entry));
        Ok(())
    }

    async fn get_cache_entry(&self, cache_id: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| CmcError::storage_failed(format!("MockCmc lock poisoned: {e}")))?;
        let now = (self.now)();
        match store.get(cache_id).cloned() {
            Some(entry) => {
                if entry.expiry_time <= now {
                    // TTL elapsed — drop the stored entry and return a miss.
                    store.remove(cache_id);
                    Ok(None)
                } else {
                    Ok(Some(entry))
                }
            }
            None => Ok(None),
        }
    }

    async fn delete_cache_entry(&self, cache_id: &[u8]) -> Result<(), CmcError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| CmcError::storage_failed(format!("MockCmc lock poisoned: {e}")))?;
        // Spec: if no entry exists for the supplied cache ID, delete MUST
        // return successfully. `BTreeMap::remove` returns `None` in that
        // case and we ignore it.
        store.remove(cache_id);
        Ok(())
    }
}

// Fixtures

const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;

fn make_encryption_materials() -> EncryptionMaterials {
    EncryptionMaterials::new(
        SUITE,
        vec![],
        EncryptionContext::new(),
        std::collections::BTreeSet::new(),
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
        std::collections::BTreeSet::new(),
        None,
        None,
        None,
    )
    .expect("constructing empty decryption materials")
}

fn make_branch_key_materials() -> BranchKeyMaterials {
    // A valid UUIDv4 string — required by `BranchKeyMaterials::new`.
    BranchKeyMaterials::new(
        [0xAB; 32],
        "branch-key-id".to_string(),
        "11111111-2222-4333-8444-555555555555".to_string(),
        EncryptionContext::new(),
    )
    .expect("constructing branch key materials")
}

fn make_beacon_key_materials() -> BeaconKeyMaterials {
    BeaconKeyMaterials::new(
        "beacon-key-id".to_string(),
        EncryptionContext::new(),
        Some(vec![0xCC; 32]),
        None,
    )
}

fn make_entry(materials: CachedMaterials, ttl_seconds: u64) -> CacheEntry {
    let creation = SystemTime::now();
    let expiry = creation + Duration::from_secs(ttl_seconds);
    CacheEntry::new(
        materials,
        creation,
        expiry,
        UsageMetadata::new(MessageUsage(0), BytesUsage(0)),
    )
}

fn make_entry_at(
    materials: CachedMaterials,
    creation: SystemTime,
    expiry: SystemTime,
) -> CacheEntry {
    CacheEntry::new(
        materials,
        creation,
        expiry,
        UsageMetadata::new(MessageUsage(0), BytesUsage(0)),
    )
}

// put-then-get

#[tokio::test]
async fn test_put_then_get_returns_inserted_entry() {
    let cmc = MockCmc::new();
    let cache_id = b"id-1";
    let entry = make_entry(
        CachedMaterials::Encryption(make_encryption_materials()),
        3600,
    );
    let expected_creation = entry.creation_time;
    let expected_expiry = entry.expiry_time;

    cmc.put_cache_entry(cache_id, entry)
        .await
        .expect("put succeeds");

    let got = cmc
        .get_cache_entry(cache_id)
        .await
        .expect("get succeeds")
        .expect("entry is present");

    assert_eq!(got.creation_time, expected_creation);
    assert_eq!(got.expiry_time, expected_expiry);
    assert_eq!(got.usage_metadata.messages_used, MessageUsage(0));
    assert_eq!(got.usage_metadata.bytes_used, BytesUsage(0));
    assert!(matches!(got.materials, CachedMaterials::Encryption(_)));
}

#[tokio::test]
async fn test_get_on_unknown_id_returns_none() {
    let cmc = MockCmc::new();
    let entry = make_entry(
        CachedMaterials::Encryption(make_encryption_materials()),
        3600,
    );
    cmc.put_cache_entry(b"id-known", entry)
        .await
        .expect("put succeeds");

    let got = cmc
        .get_cache_entry(b"id-other")
        .await
        .expect("get on unknown id succeeds");

    assert!(got.is_none(), "unknown cache id returns None");
}

// TTL enforcement

#[tokio::test]
async fn test_get_after_ttl_returns_miss() {
    // Pin the cache's clock far in the future relative to a 1-second TTL
    // so the entry is TTL-expired the moment we call get.
    let frozen_now = SystemTime::now() + Duration::from_secs(3600);
    let cmc = MockCmc::with_clock(move || frozen_now);

    let creation = SystemTime::now();
    let expiry = creation + Duration::from_secs(1);
    let entry = make_entry_at(
        CachedMaterials::Encryption(make_encryption_materials()),
        creation,
        expiry,
    );
    cmc.put_cache_entry(b"id-expiring", entry)
        .await
        .expect("put succeeds");

    let got = cmc
        .get_cache_entry(b"id-expiring")
        .await
        .expect("get succeeds");

    assert!(
        got.is_none(),
        "TTL-expired entry must NOT be returned to the caller"
    );
}

#[tokio::test]
async fn test_get_before_ttl_returns_entry() {
    // Inverse of the TTL test: clock is BEFORE the TTL so the entry must be
    // returned, proving the TTL check uses the configured `now`.
    let creation = SystemTime::now();
    let expiry = creation + Duration::from_secs(3600);
    // Frozen clock 1 second after creation, well before expiry.
    let frozen_now = creation + Duration::from_secs(1);
    let cmc = MockCmc::with_clock(move || frozen_now);

    let entry = make_entry_at(
        CachedMaterials::Encryption(make_encryption_materials()),
        creation,
        expiry,
    );
    cmc.put_cache_entry(b"id-fresh", entry)
        .await
        .expect("put succeeds");

    let got = cmc
        .get_cache_entry(b"id-fresh")
        .await
        .expect("get succeeds")
        .expect("entry is fresh");
    assert_eq!(got.expiry_time, expiry);
}

// Replace-on-put

#[tokio::test]
async fn test_put_replaces_existing_entry() {
    let cmc = MockCmc::new();
    let cache_id = b"id-replaceable";

    let first = make_entry(
        CachedMaterials::Encryption(make_encryption_materials()),
        3600,
    );
    cmc.put_cache_entry(cache_id, first)
        .await
        .expect("first put succeeds");

    // Second put with a different materials variant — the cache must
    // overwrite the prior entry.
    let second_creation = SystemTime::now() + Duration::from_secs(10);
    let second_expiry = second_creation + Duration::from_secs(3600);
    let second = make_entry_at(
        CachedMaterials::BranchKey(make_branch_key_materials()),
        second_creation,
        second_expiry,
    );
    cmc.put_cache_entry(cache_id, second)
        .await
        .expect("second put succeeds");

    let got = cmc
        .get_cache_entry(cache_id)
        .await
        .expect("get succeeds")
        .expect("entry is present");

    assert!(
        matches!(got.materials, CachedMaterials::BranchKey(_)),
        "second put replaced the first; observed materials variant: {:?}",
        std::mem::discriminant(&got.materials)
    );
    assert_eq!(got.creation_time, second_creation);
    assert_eq!(got.expiry_time, second_expiry);
}

// Delete

#[tokio::test]
async fn test_delete_existing_entry_then_get_returns_none() {
    let cmc = MockCmc::new();
    let cache_id = b"id-to-delete";
    let entry = make_entry(
        CachedMaterials::Encryption(make_encryption_materials()),
        3600,
    );
    cmc.put_cache_entry(cache_id, entry)
        .await
        .expect("put succeeds");

    cmc.delete_cache_entry(cache_id)
        .await
        .expect("delete on existing id succeeds");

    let got = cmc
        .get_cache_entry(cache_id)
        .await
        .expect("get after delete succeeds");
    assert!(got.is_none(), "delete removes the entry");
}

#[tokio::test]
async fn test_delete_missing_entry_returns_ok() {
    let cmc = MockCmc::new();
    // Per the spec: "If no cache entry exists for the specified cache ID,
    // Delete Cache Entry must return successfully."
    cmc.delete_cache_entry(b"id-never-inserted")
        .await
        .expect("delete on missing id must succeed");
}

// Round-trip through every CachedMaterials variant

#[tokio::test]
async fn test_round_trip_encryption_materials() {
    let cmc = MockCmc::new();
    let entry = make_entry(
        CachedMaterials::Encryption(make_encryption_materials()),
        3600,
    );
    cmc.put_cache_entry(b"id-enc", entry).await.unwrap();
    let got = cmc.get_cache_entry(b"id-enc").await.unwrap().unwrap();
    assert!(matches!(got.materials, CachedMaterials::Encryption(_)));
}

#[tokio::test]
async fn test_round_trip_decryption_materials() {
    let cmc = MockCmc::new();
    let entry = make_entry(
        CachedMaterials::Decryption(make_decryption_materials()),
        3600,
    );
    cmc.put_cache_entry(b"id-dec", entry).await.unwrap();
    let got = cmc.get_cache_entry(b"id-dec").await.unwrap().unwrap();
    assert!(matches!(got.materials, CachedMaterials::Decryption(_)));
}

#[tokio::test]
async fn test_round_trip_branch_key_materials() {
    let cmc = MockCmc::new();
    let entry = make_entry(
        CachedMaterials::BranchKey(make_branch_key_materials()),
        3600,
    );
    cmc.put_cache_entry(b"id-bk", entry).await.unwrap();
    let got = cmc.get_cache_entry(b"id-bk").await.unwrap().unwrap();
    assert!(matches!(got.materials, CachedMaterials::BranchKey(_)));
}

#[tokio::test]
async fn test_round_trip_beacon_key_materials() {
    let cmc = MockCmc::new();
    let entry = make_entry(
        CachedMaterials::BeaconKey(make_beacon_key_materials()),
        3600,
    );
    cmc.put_cache_entry(b"id-beacon", entry).await.unwrap();
    let got = cmc.get_cache_entry(b"id-beacon").await.unwrap().unwrap();
    assert!(matches!(got.materials, CachedMaterials::BeaconKey(_)));
}

// Usage metadata sanity

#[tokio::test]
async fn test_usage_metadata_round_trips_through_put_get() {
    let cmc = MockCmc::new();
    let creation = SystemTime::now();
    let expiry = creation + Duration::from_secs(3600);
    let usage = UsageMetadata::new(MessageUsage(7), BytesUsage(2048));
    let entry = CacheEntry::new(
        CachedMaterials::Encryption(make_encryption_materials()),
        creation,
        expiry,
        usage,
    );

    cmc.put_cache_entry(b"id-usage", entry).await.unwrap();
    let got = cmc.get_cache_entry(b"id-usage").await.unwrap().unwrap();
    assert_eq!(got.usage_metadata, usage);
}
