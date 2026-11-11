# BUG-09: `cache_entry_within_limits` admits cache entries up to `ttl + 1 s` old (whole-second truncation)

Status: Fixed on main in `e9bde48` (#98). See "Status on main (620771c)" below.

Summary (as found at `a1e23d7`): the hierarchical keyring's per-keyring TTL check compared `elapsed.as_secs()`, which truncates, against `ttl_seconds`. An entry was therefore accepted until it was just under `ttl + 1` seconds old. This only shows when a `Shared` cache returns an entry whose own expiry is later than this keyring's TTL. The behavior matches the Dafny MPL's whole-second clock, so it's likely not a bug.

- Confidence: Confirmed by test, likely not a bug (it matches the Dafny MPL's whole-second granularity)
- Spec conflict: no. The spec formula doesn't define a time resolution, and the Dafny reference compares whole seconds (see Expected behavior). A reading with real-valued time would make this a conflict of under one second.
- Severity: Informational. The overshoot is bounded by 1 s and only occurs with a `Shared` cache whose entries expire later than this keyring's TTL.
- Related IDs: VR-2026-T14 (property (b)); TM-MPL-010

## Status on main (620771c)

- Status: Fixed on main. The original report rated this "likely not a bug", but `main` changed the behavior anyway.
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-09.
- Evidence: the reproducer was adapted for API changes only and still passes, but its output changed. With ttl = 1 s, entries aged 1500 ms and 1950 ms are now "treated as expired"; at `a1e23d7` they were "USED". In the shared-`LocalCmc` case at about 1.5 s, the keystore is now called again (calls = 2, was 1) (`.agents/tasks/bug-recheck/logs/recheck09.log`).
- Fixing commit: `e9bde48` "feat(esdk): retarget the ESDK and C++ shim onto the native Rust MPL (#98)". Its diff replaces `elapsed.as_secs() <= ttl_seconds` with `elapsed <= ttl`.
- Where the fix lives: `cache_entry_within_limits` (`mpl/src/aws_kms/hierarchical_keyring.rs:989-995`). It now compares full `Duration`s and is called at `:684` (OnEncrypt) and `:927` (OnDecrypt). Main also added a regression test, `on_encrypt_ttl_compares_the_full_duration` (`mpl/tests/test_aws_kms_hierarchical_keyring.rs:1547`).

The sections after Location are the original analysis at `a1e23d7`, kept as history. Their line numbers refer to `a1e23d7`.

## Location

Current code (`main` `620771c`), `mpl/src/aws_kms/hierarchical_keyring.rs:987-995`:

```rust
987 /// Whether a cache entry is still within its TTL:
988 /// `time.now() - cacheEntryCreationTime <= ttlSeconds`.
989 fn cache_entry_within_limits(entry: &CacheEntry, ttl: Duration) -> bool {
990     let now = SystemTime::now();
991     let elapsed = now
992         .duration_since(entry.creation_time())
993         .unwrap_or(Duration::ZERO);
994     elapsed <= ttl
995 }
```

Originally reported at `a1e23d7`: `mpl/src/aws_kms/hierarchical_keyring.rs:620-626`, called at `:322` (OnEncrypt) and `:566` (OnDecrypt). It compared `elapsed.as_secs() <= ttl_seconds`. For comparison, the keyring's own `LocalCmc` already expired entries at full `SystemTime` precision (`mpl/src/cmc/local.rs:179` at `a1e23d7`), so the truncation only mattered with a `Shared` cache.

## Original analysis at a1e23d7 (history)

The rest of this report describes the behavior at `a1e23d7`, before the fix.

### Expected behavior

`spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt` (the same text appears under `#ondecrypt`):

> There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
> `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
> valid for TTL of the Hierarchical Keyring getting the cache entry.
> If this is NOT true, then we MUST treat the cache entry as expired.

The spec doesn't say what unit `time.now()` uses. The Dafny MPL evaluates `now - creationTime <= ttlSeconds`, where both values come from `Time.GetCurrent()`, documented as "the number of seconds since some fixed-as-long-as-this-program-is-running moment" ([AwsKmsHierarchicalKeyring.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy), [Time.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/StandardLibrary/src/Time.dfy)). Dafny therefore also accepts entries somewhat older than `ttl`. Its window is between `ttl` and `ttl + 1` s depending on where the two timestamps fall within their seconds, while Rust's window is consistently just under `ttl + 1` s.

### Actual behavior

1. A keyring with `ttl_seconds = 1` reads an entry created 1.5 s ago, through a `Shared` cache that reports a one-hour expiry.
2. `elapsed` = 1.5 s, and `as_secs()` = 1, so `1 <= 1` and the entry is used without calling the keystore.
3. The entry is treated as expired only once `elapsed >= 2 s`. The test shows 1950 ms used and 2050 ms expired.
4. The same happens with two real keyrings sharing a `LocalCmc`. A keyring with a TTL of 100 s populates the cache, and a keyring with a TTL of 1 s reuses the entry at about 1.5 s and refreshes it at about 2.2 s.

### Impact

- Preconditions: a `CacheType::Shared` cache, plus an entry whose cache-level expiry is later than this keyring's TTL. That happens when another keyring with a longer TTL populated it, or with a custom `Cmc` that doesn't enforce expiry.
- Effect: a keyring can use branch key materials up to (just under) one second longer than its configured TTL. For example, a rotation or revocation is picked up up to 1 s later than configured. The materials are the ones the cache already holds for this identifier, so no other keyring's materials are involved.
- I'd call this not exploitable in any meaningful sense, and it's equivalent to the Dafny MPL to within the same one-second granularity.

### Reproduction / evidence

Reproducer: `mpl/tests/zz_bugrepro_09_ttl_truncation.rs` (a temporary untracked test, removed from the tree after the run; full source below, copy in `.agents/tasks/bug-reports/reproducers/`). Command: `cd mpl && cargo test --test zz_bugrepro_09_ttl_truncation -- --nocapture`.

```rust
// TEMPORARY reproducer for BUG-09 (T14). Delete after running.
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use aws_crypto_mpl::cmc::cache_config::CacheType;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext,
    EncryptionMaterials,
};
use aws_crypto_mpl::{
    CacheEntry, CachedMaterials, Cmc, CmcError, HierarchicalKeyring, Keyring, LocalCmc,
    UsageMetadata,
};
const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
fn bkm() -> BranchKeyMaterials {
    BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap()
}
struct CountingKeystore {
    active_calls: Mutex<u32>,
}
#[async_trait]
impl Keystore for CountingKeystore {
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
        Ok(KeyStoreInfo {
            keystore_id: "id".into(),
            keystore_name: "t".into(),
            logical_keystore_name: "L".into(),
            grant_tokens: vec![],
            kms_configuration: KmsConfiguration::Discovery,
        })
    }
    async fn create_key_store(&self) -> Result<String, KeystoreError> { unimplemented!() }
    async fn create_key(&self, _: Option<String>, _: Option<EncryptionContext>) -> Result<String, KeystoreError> { unimplemented!() }
    async fn version_key(&self, _: String) -> Result<(), KeystoreError> { unimplemented!() }
    async fn get_active_branch_key(&self, _: String) -> Result<BranchKeyMaterials, KeystoreError> {
        *self.active_calls.lock().unwrap() += 1;
        Ok(bkm())
    }
    async fn get_branch_key_version(&self, _: String, _: String) -> Result<BranchKeyMaterials, KeystoreError> { Ok(bkm()) }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}
/// A shared cache that always returns an entry created `age` ago, expiring in an hour.
struct BackdatedCmc {
    age: Duration,
}
#[async_trait]
impl Cmc for BackdatedCmc {
    async fn put_cache_entry(&self, _: &[u8], _: CacheEntry) -> Result<(), CmcError> { Ok(()) }
    async fn get_cache_entry(&self, _: &[u8]) -> Result<Option<Arc<CacheEntry>>, CmcError> {
        let now = SystemTime::now();
        Ok(Some(Arc::new(CacheEntry::new(
            CachedMaterials::BranchKey(bkm()),
            now - self.age,
            now + Duration::from_secs(3600),
            UsageMetadata::default(),
        ))))
    }
    async fn delete_cache_entry(&self, _: &[u8]) -> Result<(), CmcError> { Ok(()) }
}
fn em() -> EncryptionMaterials {
    EncryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, vec![], EncryptionContext::new(), Default::default(), None, None, None).unwrap()
}
#[tokio::test]
async fn backdated_entry_older_than_ttl_is_used() {
    for age_ms in [900u64, 1_500, 1_950, 2_050] {
        let ks = Arc::new(CountingKeystore { active_calls: Mutex::new(0) });
        let cache: Arc<dyn Cmc> = Arc::new(BackdatedCmc { age: Duration::from_millis(age_ms) });
        let kr = HierarchicalKeyring::new(ks.clone(), 1, Some(BKID.into()), None, Some(CacheType::Shared(cache)), Some("p".into())).unwrap();
        kr.on_encrypt(em()).await.unwrap();
        let calls = *ks.active_calls.lock().unwrap();
        println!(
            "REPRO BUG-09 ttl_seconds=1, entry age={age_ms} ms -> {} (keystore calls={calls})",
            if calls == 0 { "cache entry USED" } else { "treated as expired" }
        );
    }
}
#[tokio::test]
async fn shared_local_cmc_two_keyrings_different_ttls() {
    let shared: Arc<dyn Cmc> = Arc::new(LocalCmc::new(1000, 1).unwrap());
    let ks = Arc::new(CountingKeystore { active_calls: Mutex::new(0) });
    let kr_long = HierarchicalKeyring::new(ks.clone(), 100, Some(BKID.into()), None, Some(CacheType::Shared(shared.clone())), Some("p".into())).unwrap();
    let kr_short = HierarchicalKeyring::new(ks.clone(), 1, Some(BKID.into()), None, Some(CacheType::Shared(shared.clone())), Some("p".into())).unwrap();
    kr_long.on_encrypt(em()).await.unwrap();
    println!("REPRO BUG-09 after ttl=100 keyring populates shared LocalCmc: keystore calls = {}", *ks.active_calls.lock().unwrap());
    std::thread::sleep(Duration::from_millis(1_500));
    kr_short.on_encrypt(em()).await.unwrap();
    println!("REPRO BUG-09 ttl=1 keyring at ~1.5 s: keystore calls = {} (1 = cache entry used)", *ks.active_calls.lock().unwrap());
    std::thread::sleep(Duration::from_millis(700));
    kr_short.on_encrypt(em()).await.unwrap();
    println!("REPRO BUG-09 ttl=1 keyring at ~2.2 s: keystore calls = {} (2 = treated as expired)", *ks.active_calls.lock().unwrap());
}
```

Observed output (`.agents/tasks/bug-reports/logs/bugrepro09.log`):

```text
running 2 tests
REPRO BUG-09 after ttl=100 keyring populates shared LocalCmc: keystore calls = 1
REPRO BUG-09 ttl_seconds=1, entry age=900 ms -> cache entry USED (keystore calls=0)
REPRO BUG-09 ttl_seconds=1, entry age=1500 ms -> cache entry USED (keystore calls=0)
REPRO BUG-09 ttl_seconds=1, entry age=1950 ms -> cache entry USED (keystore calls=0)
REPRO BUG-09 ttl_seconds=1, entry age=2050 ms -> treated as expired (keystore calls=1)
test backdated_entry_older_than_ttl_is_used ... ok
REPRO BUG-09 ttl=1 keyring at ~1.5 s: keystore calls = 1 (1 = cache entry used)
REPRO BUG-09 ttl=1 keyring at ~2.2 s: keystore calls = 2 (2 = treated as expired)
test shared_local_cmc_two_keyrings_different_ttls ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.23s
```

### Re-check on main (620771c)

The reproducer was adapted for API changes only. The custom `BackdatedCmc` implements the new `Cmc` trait (`*Input` / `*Output`, plus the new `update_usage_metadata`). `CacheEntry::new(..)` became `CacheEntry::builder()`, with the same creation and expiry times. The TTL is `Duration::from_secs(..)`, and `CacheType::Shared(cmc)` became `.cache(SharedCmc)`. The TTLs (1 s and 100 s), the entry ages (900, 1500, 1950 and 2050 ms) and the sleeps are the same. Adapted reproducer: [`zz_bugrepro_09_ttl_truncation.rs`](../../.agents/tasks/bug-recheck/reproducers/zz_bugrepro_09_ttl_truncation.rs). Same command as above.

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck09.log`):

```text
running 2 tests
REPRO BUG-09 after ttl=100 keyring populates shared LocalCmc: keystore calls = 1
REPRO BUG-09 ttl_seconds=1, entry age=900 ms -> cache entry USED (keystore calls=0)
REPRO BUG-09 ttl_seconds=1, entry age=1500 ms -> treated as expired (keystore calls=1)
REPRO BUG-09 ttl_seconds=1, entry age=1950 ms -> treated as expired (keystore calls=1)
REPRO BUG-09 ttl_seconds=1, entry age=2050 ms -> treated as expired (keystore calls=1)
test backdated_entry_older_than_ttl_is_used ... ok
REPRO BUG-09 ttl=1 keyring at ~1.5 s: keystore calls = 2 (1 = cache entry used)
REPRO BUG-09 ttl=1 keyring at ~2.2 s: keystore calls = 2 (2 = treated as expired)
test shared_local_cmc_two_keyrings_different_ttls ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.23s
```

The test prints instead of asserting, so it passes either way. The changed rows (1500 ms, 1950 ms, and `calls = 2` at about 1.5 s) are the evidence of the fix. The `(1 = cache entry used)` label is the original test's printed text.

## Resolved

Fixed on `main` in `e9bde48` (#98), as described in the Status section. This is fix option 1 from the original report: compare at full precision. The original fix options are no longer needed and were removed from this report. They remain in the git history of this file.

Questions that may still be relevant:

1. Rust now refreshes slightly earlier than the Dafny MPL, which compares whole-second timestamps. Should the spec state the time resolution, so that all runtimes agree near the TTL boundary?
2. Would that small difference from Dafny matter for any cross-runtime conformance test that measures cache hits around the TTL boundary?
