# BUG-01: Large accepted TTL / grace / inflight values overflow `SystemTime + Duration` and panic

Summary: `HierarchicalKeyring` and `StormTrackingCmc` accept arbitrarily large time values at construction, then add them to `SystemTime::now()` with the panicking `+` operator, so a valid-looking configuration such as `ttl_seconds = u64::MAX` panics on first use instead of returning an error.

- Confidence: Confirmed by test
- Spec conflict: no
- Severity: Low. The trigger is configuration only (trusted application code), and the threshold on Unix is roughly 9.2 × 10^18 s. Still, a "never expire" sentinel such as `u64::MAX` is a plausible thing for an application to pass, and the result is a panic, not an error.
- Related IDs: VR-2026-T06; TM-MPL-018, TM-MPL-022, TM-MPL-023

## Location

Verified against `HEAD a1e23d7` (branch `aws-crypto-rust/esdk-native-mpl`).

`mpl/src/aws_kms/hierarchical_keyring.rs:342` (OnEncrypt cache put) and `:585` (OnDecrypt cache put), same code at both sites:

```rust
338                let now = SystemTime::now();
339                let entry = CacheEntry::new(
340                    CachedMaterials::BranchKey(bkm.clone()),
341                    now,
342                    now + Duration::from_secs(self.ttl_seconds),
343                    UsageMetadata::default(),
344                );
```

`HierarchicalKeyring::new` (`hierarchical_keyring.rs:150`) only rejects `ttl_seconds == 0`.

`mpl/src/cmc/storm_tracking.rs:446` (per-waiter deadline) and `:536` (`within_grace_interval`):

```rust
445                            Ok(GetDecision::Wait {
446                                deadline: Some(now + self.inflight_ttl),
447                            })
...
531 pub fn within_grace_interval(
532     inflight: SystemTime,
533     now: SystemTime,
534     grace_interval: Duration,
535 ) -> bool {
536     now < inflight + grace_interval
537 }
```

`ValidatedConfig::from_raw` (`storm_tracking.rs:108-143`) checks only the lower bounds (each value ≥ 1) and the ordering `grace_interval <= inflight_ttl <= grace_period`. There is no upper bound.

## Expected behavior

There's no spec requirement here; this is a robustness / defense-in-depth issue. The spec sets a lower bound and no upper bound:

- `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl`: "This value MUST be greater than zero."
- `spec/framework/storm-tracking-cryptographic-materials-cache.md#consistency` constrains only the relative order of grace interval, inflight TTL and grace period.

For reference, the Dafny MPL guards the same addition and returns an error instead of overflowing (`AwsKmsHierarchicalKeyring.dfy`, both put paths): `:- Need((now as int + ttlSeconds as int) < UInt.INT64_MAX_LIMIT, ... "INT64 Overflow when putting cache entry.")` ([source](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy), main branch, read while writing this report). I did not check the Dafny storm-tracking cache.

## Actual behavior

Hierarchical keyring:

1. `HierarchicalKeyring::new(.., ttl_seconds = u64::MAX, ..)` returns `Ok`.
2. The first `on_encrypt` (or `on_decrypt`) misses the cache, fetches the branch key, then evaluates `now + Duration::from_secs(u64::MAX)` at line 342 (or 585).
3. `impl Add<Duration> for SystemTime` panics with `overflow when adding duration to instant`.

Storm-tracking cache, `grace_interval` large (BUG-01b):

1. `StormTrackingCmc::new(.., grace_period = u64::MAX, grace_interval = u64::MAX, .., inflight_ttl = u64::MAX, ..)` passes every check and returns `Ok`.
2. The first `get_cache_entry(k)` misses and marks `k` inflight.
3. The second `get_cache_entry(k)` misses, finds `k` inflight, and calls `within_grace_interval`, which panics at line 536.

Storm-tracking cache, `inflight_ttl` large (BUG-01c):

1. Same as above, but with `grace_interval = 1`.
2. The second `get_cache_entry(k)` is within the grace interval, so it computes the waiter deadline `now + self.inflight_ttl` at line 446 and panics.

The same constructor path is reachable through `HierarchicalKeyring::new(.., cache_type = CacheType::StormTracking(..))`. The keyring only checks `grace_period < ttl_seconds`, so a large TTL lets an equally large grace period through.

## Impact

- Precondition: the application configures a TTL, grace interval or inflight TTL larger than about `i64::MAX − now` seconds on Unix-like targets. The log shows that `now + 1e15 s` succeeds and `now + i64::MAX s` fails.
- Effect: a panic on an encrypt/decrypt path. Under Tokio this kills the task, and the caller gets a `JoinError`. With `panic = "abort"`, or across an FFI boundary such as the C++ shim, it takes down the process. No `catch_unwind` exists in `mpl/src`, `esdk/src` or `esdk/shims` (searched).
- Remote exploitability: none. Message data can't influence these values.
- Platform note (expected from Rust's `SystemTime` representation on Windows, but not tested): the Windows limit is much lower, around 1.8 × 10^12 s from 1601. A value like `1e13` that works on Linux would panic there.

## Reproduction / evidence

Reproducer: `mpl/tests/zz_bugrepro_01_ttl_overflow.rs` (a temporary untracked test, removed from the tree after the run; full source below, copy in `.agents/tasks/bug-reports/reproducers/`). Command: `cd mpl && cargo test --test zz_bugrepro_01_ttl_overflow -- --nocapture`. The tests pass when the panic is observed.

```rust
// TEMPORARY reproducer for BUG-01 (T06). Delete after running.
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext,
    EncryptionMaterials,
};
use aws_crypto_mpl::{Cmc, HierarchicalKeyring, Keyring, StormTrackingCmc};
const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
struct FakeKeystore;
#[async_trait]
impl Keystore for FakeKeystore {
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
        Ok(BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap())
    }
    async fn get_branch_key_version(&self, _: String, _: String) -> Result<BranchKeyMaterials, KeystoreError> {
        Ok(BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap())
    }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}
fn panic_msg(e: tokio::task::JoinError) -> String {
    let p = e.into_panic();
    p.downcast_ref::<&str>().map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic>".into())
}
#[test]
fn std_systemtime_add_limits() {
    let now = SystemTime::now();
    println!("REPRO BUG-01 now+u64::MAX s checked_add = {:?}", now.checked_add(Duration::from_secs(u64::MAX)));
    println!("REPRO BUG-01 now+i64::MAX s checked_add = {:?}", now.checked_add(Duration::from_secs(i64::MAX as u64)));
    println!("REPRO BUG-01 now+1e15 s checked_add is_some = {}", now.checked_add(Duration::from_secs(1_000_000_000_000_000)).is_some());
}
#[tokio::test]
async fn hierarchical_ttl_u64_max_accepted_then_on_encrypt_panics() {
    let kr = HierarchicalKeyring::new(Arc::new(FakeKeystore), u64::MAX, Some(BKID.into()), None, None, Some("p".into()));
    println!("REPRO BUG-01a HierarchicalKeyring::new(ttl_seconds = u64::MAX) is_ok = {}", kr.is_ok());
    let kr = Arc::new(kr.unwrap());
    let em = EncryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, vec![], EncryptionContext::new(), Default::default(), None, None, None).unwrap();
    let h = tokio::spawn(async move { kr.on_encrypt(em).await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01a on_encrypt PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; on_encrypt returned is_ok={ok}"),
    }
}
#[tokio::test]
async fn hierarchical_ttl_u64_max_on_decrypt_panics() {
    use aws_crypto_mpl::aws_kms::__test_internals::wrap;
    use aws_crypto_mpl::structures::{DecryptionMaterials, EncryptedDataKey};
    let bkm = BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap();
    let ct = wrap(&bkm, &EncryptionContext::new(), &[1u8; 32]).unwrap();
    let edk = EncryptedDataKey::new("aws-kms-hierarchy".into(), BKID.as_bytes().to_vec(), ct);
    let kr = Arc::new(HierarchicalKeyring::new(Arc::new(FakeKeystore), u64::MAX, Some(BKID.into()), None, None, Some("p".into())).unwrap());
    let dm = DecryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, EncryptionContext::new(), Default::default(), None, None, None).unwrap();
    let h = tokio::spawn(async move { kr.on_decrypt(dm, &[edk]).await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01d on_decrypt PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; on_decrypt returned is_ok={ok}"),
    }
}
#[tokio::test]
async fn storm_tracking_huge_grace_interval_accepted_then_second_get_panics() {
    // grace_period, grace_interval, inflight_ttl all u64::MAX seconds: satisfies every check in from_raw.
    let cmc = StormTrackingCmc::new(1000, 1, u64::MAX, u64::MAX, 1, u64::MAX, 1, None);
    println!("REPRO BUG-01b StormTrackingCmc::new(grace_interval = u64::MAX s) is_ok = {}", cmc.is_ok());
    let cmc = Arc::new(cmc.unwrap());
    let first = cmc.get_cache_entry(b"k").await;
    println!("REPRO BUG-01b first get (miss, marks inflight) = {:?}", first.as_ref().map(|o| o.is_some()));
    let c2 = Arc::clone(&cmc);
    let h = tokio::spawn(async move { c2.get_cache_entry(b"k").await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01b second get PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; get returned is_ok={ok}"),
    }
}
#[tokio::test]
async fn storm_tracking_huge_inflight_ttl_accepted_then_waiter_deadline_panics() {
    // grace_interval = 1 s keeps within_grace_interval safe; inflight_ttl = u64::MAX s.
    let cmc = StormTrackingCmc::new(1000, 1, u64::MAX, 1, 1, u64::MAX, 1, None);
    println!("REPRO BUG-01c StormTrackingCmc::new(inflight_ttl = u64::MAX s) is_ok = {}", cmc.is_ok());
    let cmc = Arc::new(cmc.unwrap());
    let _ = cmc.get_cache_entry(b"k").await;
    let c2 = Arc::clone(&cmc);
    let h = tokio::spawn(async move { c2.get_cache_entry(b"k").await.is_ok() });
    match h.await {
        Err(e) if e.is_panic() => println!("REPRO BUG-01c second get PANICKED: {}", panic_msg(e)),
        Err(_) => panic!("join error that is not a panic"),
        Ok(ok) => panic!("expected panic; get returned is_ok={ok}"),
    }
}
```

Observed output (`.agents/tasks/bug-reports/logs/bugrepro01.log`, macOS; interleaved thread lines kept as logged):

```text
running 5 tests
REPRO BUG-01 now+u64::MAX s checked_add = None
REPRO BUG-01 now+i64::MAX s checked_add = None
REPRO BUG-01 now+1e15 s checked_add is_some = true
test std_systemtime_add_limits ... ok
REPRO BUG-01b StormTrackingCmc::new(grace_interval = u64::MAX s) is_ok = true
REPRO BUG-01b first get (miss, marks inflight) = Ok(false)
REPRO BUG-01c StormTrackingCmc::new(inflight_ttl = u64::MAX s) is_ok = true
REPRO BUG-01a HierarchicalKeyring::new(ttl_seconds = u64::MAX) is_ok = true
thread 'storm_tracking_huge_inflight_ttl_accepted_then_waiter_deadline_panics' (5934199) panicked at /rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/time.rs:746:31:
overflow when adding duration to instant
...
REPRO BUG-01c second get PANICKED: overflow when adding duration to instant
REPRO BUG-01b second get PANICKED: overflow when adding duration to instant
...
REPRO BUG-01a on_encrypt PANICKED: overflow when adding duration to instant
REPRO BUG-01d on_decrypt PANICKED: overflow when adding duration to instant
...
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

## Fix options

1. Checked addition at each use site, returning an error.
   - Hierarchical keyring: `now.checked_add(..).ok_or_else(|| MaterialsError::keyring_failed("... TTL overflow ..."))`. This matches the Dafny MPL's "INT64 Overflow when putting cache entry" failure.
   - Storm tracking: `CmcError`.
   - Trade-off: these configs change from "panics" to "returns an error on every call". That's still unusable, but it no longer crashes. Cost is negligible.
2. Reject at construction. Add an upper bound in `HierarchicalKeyring::new` and `ValidatedConfig::from_raw`, for example a fixed maximum such as 100 years or `i64::MAX` seconds minus a margin.
   - Trade-off: the failure moves to construction time, which is the best UX. But it adds a limit the spec doesn't state. Picking a constant means coordinating with the other runtimes. The Dafny check is time-relative (`now + ttl < INT64_MAX`), not a fixed cap. A fixed cap also doesn't fully remove the per-call addition unless it's chosen below the platform limit (see the Windows note).
3. Saturate: treat overflow as "never expires".
   - `checked_add(..)` with a far-future fallback. `within_grace_interval` returns `true` on overflow. The waiter deadline becomes `None` on overflow.
   - Trade-off: no error at all, and it arguably matches what a user passing `u64::MAX` means. But it silently changes semantics, diverges from Dafny's fail-closed behavior, and `deadline: None` disables the per-waiter InFlightTTL check.

Recommendation: option 1 at all four sites, because it matches the Dafny reference and keeps behavior fail-closed. Option 2 can be added later if the team wants a construction-time error.

## Questions for the engineers

1. Should the native Rust library match the Dafny error ("INT64 Overflow when putting cache entry") per call, or fail early in the constructors?
2. If a constructor bound is preferred, what maximum TTL / grace values should be agreed across runtimes, and should the limit account for Windows `SystemTime` range?
3. For storm tracking, should overflow in `within_grace_interval` mean "within the interval" (saturate) or be an error?
4. Is the C++ shim built with `panic = "abort"` or otherwise relying on no panics crossing the FFI boundary? That determines how urgent this is.
