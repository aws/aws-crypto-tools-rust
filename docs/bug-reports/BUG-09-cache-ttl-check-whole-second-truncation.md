# BUG-09: `cache_entry_within_limits` admits cache entries up to `ttl + 1 s` old (whole-second truncation)

Summary: the hierarchical keyring's per-keyring TTL check compares `elapsed.as_secs()`, which truncates, against `ttl_seconds`. An entry is therefore accepted until it's just under `ttl + 1` seconds old. This only shows when a `Shared` cache returns an entry whose own expiry is later than this keyring's TTL. The behavior matches the Dafny MPL's whole-second clock, so it's likely not a bug.

- Confidence: Confirmed by test, likely not a bug (it matches the Dafny MPL's whole-second granularity)
- Spec conflict: no. The spec formula doesn't define a time resolution, and the Dafny reference compares whole seconds (see Expected behavior). A reading with real-valued time would make this a conflict of under one second.
- Severity: Informational. The overshoot is bounded by 1 s and only occurs with a `Shared` cache whose entries expire later than this keyring's TTL.
- Related IDs: VR-2026-T14 (property (b)); TM-MPL-010

## Location

Verified against `HEAD a1e23d7`. `mpl/src/aws_kms/hierarchical_keyring.rs:620-626`, called at `:322` (OnEncrypt) and `:566` (OnDecrypt):

```rust
618 /// Whether a cache entry is still within its TTL:
619 /// `time.now() - cacheEntryCreationTime <= ttlSeconds`.
620 fn cache_entry_within_limits(entry: &CacheEntry, ttl_seconds: u64) -> bool {
621     let now = SystemTime::now();
622     let elapsed = now
623         .duration_since(entry.creation_time)
624         .unwrap_or(Duration::ZERO);
625     elapsed.as_secs() <= ttl_seconds
626 }
```

For comparison, the keyring's own `LocalCmc` expires entries at full `SystemTime` precision (`mpl/src/cmc/local.rs:179`, `entry.expiry_time > now`). With a non-shared cache, entries are already gone at exactly `ttl`, so the truncation never matters there.

## Expected behavior

`spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt` (the same text appears under `#ondecrypt`):

> There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
> `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
> valid for TTL of the Hierarchical Keyring getting the cache entry.
> If this is NOT true, then we MUST treat the cache entry as expired.

The spec doesn't say what unit `time.now()` uses. The Dafny MPL evaluates `now - creationTime <= ttlSeconds`, where both values come from `Time.GetCurrent()`, documented as "the number of seconds since some fixed-as-long-as-this-program-is-running moment" ([AwsKmsHierarchicalKeyring.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy), [Time.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/StandardLibrary/src/Time.dfy)). Dafny therefore also accepts entries somewhat older than `ttl`. Its window is between `ttl` and `ttl + 1` s depending on where the two timestamps fall within their seconds, while Rust's window is consistently just under `ttl + 1` s.

## Actual behavior

1. A keyring with `ttl_seconds = 1` reads an entry created 1.5 s ago, through a `Shared` cache that reports a one-hour expiry.
2. `elapsed` = 1.5 s, and `as_secs()` = 1, so `1 <= 1` and the entry is used without calling the keystore.
3. The entry is treated as expired only once `elapsed >= 2 s`. The test shows 1950 ms used and 2050 ms expired.
4. The same happens with two real keyrings sharing a `LocalCmc`. A keyring with a TTL of 100 s populates the cache, and a keyring with a TTL of 1 s reuses the entry at about 1.5 s and refreshes it at about 2.2 s.

## Impact

- Preconditions: a `CacheType::Shared` cache, plus an entry whose cache-level expiry is later than this keyring's TTL. That happens when another keyring with a longer TTL populated it, or with a custom `Cmc` that doesn't enforce expiry.
- Effect: a keyring can use branch key materials up to (just under) one second longer than its configured TTL. For example, a rotation or revocation is picked up up to 1 s later than configured. The materials are the ones the cache already holds for this identifier, so no other keyring's materials are involved.
- I'd call this not exploitable in any meaningful sense, and it's equivalent to the Dafny MPL to within the same one-second granularity.

## Reproduction / evidence

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

## Fix options

1. Compare at full precision: `elapsed <= Duration::from_secs(ttl_seconds)`.
   - Pros: exact under a real-valued reading of the spec, and simple to prove (T14 (b)). Cost is unchanged.
   - Cons: a small behavior difference from Dafny, which can accept entries up to about 1 s past `ttl`, so Rust would refresh slightly earlier. With `ttl_seconds` near `u64::MAX`, `Duration::from_secs` is fine, but see BUG-01 for the related overflow in `now + ttl`.
2. Keep the current behavior and document it: "TTL is checked at whole-second granularity; entries may be used for up to `ttl + 1 s` when served by a shared cache."
   - Pros: no behavior change, and it stays close to Dafny.
   - Cons: the doc comment's formula and the code differ slightly unless the comment is updated.
3. Mirror Dafny exactly: compare whole-second timestamps (`now_secs - created_secs <= ttl`).
   - Pros: the closest cross-runtime match.
   - Cons: the window depends on phase (sometimes under `ttl`, sometimes over), which is harder to explain and to specify.

Recommendation: option 2, unless the team wants the T14 proof to state the exact `<= ttl` bound, in which case option 1. I don't see a security reason to prefer either.

## Questions for the engineers

1. Is whole-second TTL granularity intended across runtimes? Should the spec say so explicitly?
2. Would refreshing slightly earlier than Dafny with option 1 matter for anyone, for example in cross-runtime conformance tests that measure cache hits around the TTL boundary?
3. Are there `Cmc` implementations in use that don't enforce `expiry_time`, which would make this keyring-side check the only TTL enforcement?
