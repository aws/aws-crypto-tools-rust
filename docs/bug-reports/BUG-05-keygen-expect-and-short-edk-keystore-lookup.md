# BUG-05: (a) Default CMM panics if ECDSA key generation fails; (b) a 44–59-byte hierarchical EDK reaches the keystore before rejection

Summary: (a) `DefaultCmm::get_encryption_materials` calls `.expect` on the `Result` from `ecdsa_generate_keypair`, so a key-generation failure panics instead of returning `MaterialsError`. (b) `HierarchicalKeyring` fetches the branch key (from the keystore on a cache miss) for an EDK of 44–59 bytes before rejecting it as too short.

- Confidence: (a) Confirmed by code reading; (b) Confirmed by test for the behavior. Part (b) is likely not a bug: it matches the Dafny MPL and adds no amplification beyond what any EDK of 60 bytes or more already causes.
- Spec conflict: no
- Severity: Low.
  - (a) is a latent panic on a path that should be unreachable unless AWS-LC fails (RNG or self-test failure, allocation failure).
  - (b) costs one keystore round trip per malformed EDK, then fails closed.
- Related IDs: VR-2026-T16; TM-MPL-023

## Location

Verified against `HEAD a1e23d7`.

(a) `mpl/src/cmm/default_cmm.rs:114-115`:

```rust
114            let keys = ecdsa_generate_keypair(alg)
115                .expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms");
```

`prim/src/ecdsa.rs:370-400` (`ecdsa_generate_keypair`) returns `Result<SignatureKeyPair, Error>` and has four `Err` paths: keygen (line 372), public-key compression (377), DER encoding (383), and the verification-key length check (388-393). The enclosing function already returns `Result<EncryptionMaterials, MaterialsError>`.

(b) `mpl/src/aws_kms/hierarchical_keyring.rs:536-542` checks only for ≥ 44 bytes (salt 16 + IV 12 + version 16) before the cache/keystore lookup at `:570-572`. The full 60-byte minimum is enforced afterwards, in `branch_key_wrap::unwrap` (`branch_key_wrap.rs:231-236`), called at line 601:

```rust
536        if ciphertext.len() < CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN {
537            return Err(MaterialsError::keyring_failed(format!(
538                "HierarchicalKeyring::on_decrypt: EDK ciphertext too short to contain branch-key version: {} bytes (need at least {})",
...
570                let bkm = self
571                    .keystore
572                    .get_branch_key_version(branch_key_id.to_string(), branch_key_version.clone())
```

## Expected behavior

There's no spec requirement for either part; this is robustness / defense-in-depth.

(a) `spec/framework/default-cmm.md#get-encryption-materials` says "the default CMM MUST Generate a [signing key](structures.md#signing-key)" but says nothing about how a generation failure is reported. The Dafny Default CMM propagates it as an error: `var pair :- maybeECDSAPair.MapFailure(e => Types.AwsCryptographyPrimitives(e));` ([DefaultCMM.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/CMMs/DefaultCMM.dfy), `main`, read while writing this report).

(b) `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt` orders the steps as: find branch key materials from the cache, using the version from the EDK, and fall back to the keystore; then unwrap. It doesn't require a full-length check first. The Dafny keyring does the same as Rust: `Need(|providerWrappedMaterial| >= EDK_CIPHERTEXT_VERSION_INDEX, ...)` (44 bytes), then `GetHierarchicalMaterialsVersion` (cache/keystore), then the exact-length check `== EXPECTED_EDK_CIPHERTEXT_OVERHEAD + KeyLength` in `KmsHierarchyUnwrapKeyMaterial.Invoke` ([AwsKmsHierarchicalKeyring.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy)).

## Actual behavior

(a), by code reading:

1. A signing suite is selected (for example the default committing suite with ECDSA P-384).
2. `ecdsa_generate_keypair` returns `Err`.
3. `.expect` panics, and the caller sees a panic, not `MaterialsError`.

(b), by test:

1. An EDK with provider id `aws-kms-hierarchy`, a matching branch key id, and a 44–59-byte ciphertext is passed to `on_decrypt`.
2. The version is parsed from bytes 28..44, the cache misses, and `get_branch_key_version` is called once.
3. `unwrap` then rejects it: "ciphertext too short: N < 60".
4. At 43 bytes, it's rejected before the keystore (0 calls).

## Impact

(a):

- Precondition: AWS-LC key generation, compression or encoding fails. In practice that means an entropy source failure, a FIPS self-test failure, or allocation failure. It can't be triggered by message data.
- Effect: a panic instead of an error on the encrypt path. Under Tokio that kills the task. With `panic = "abort"`, or across FFI, it ends the process.
- The `expect` message's claim ("cannot fail") isn't something the type system or the callee guarantees. The verification-targets analysis records this as an unprovable obligation, not a proven-unreachable one.

(b):

- Precondition: an attacker can get a crafted EDK into a message that a victim decrypts with a hierarchical keyring, and knows or matches the branch key id.
- Effect: one cache lookup, and on a miss one keystore call (DynamoDB `GetItem` + KMS `Decrypt` with a real `BranchKeyStore`), before failing.
- The same attacker can get exactly the same effect with a garbage EDK of 60 bytes or more, which passes both length checks and fails only at AES-GCM authentication (the 60-byte row in the log shows this). Rejecting 44–59 earlier therefore removes no attack capability; it only saves a round trip on one class of malformed input.
- On a cache hit (the version was already cached), there's no keystore call at all.

## Reproduction / evidence

(a) wasn't reproduced. It needs a forced AWS-LC failure, which can't be injected without changing `prim/src`. This part is code reading only.

(b) Reproducer: `mpl/tests/zz_bugrepro_05_short_edk_lookup.rs` (a temporary untracked test, removed from the tree after the run; full source below, copy in `.agents/tasks/bug-reports/reproducers/`). Command: `cd mpl && cargo test --test zz_bugrepro_05_short_edk_lookup -- --nocapture`.

```rust
// TEMPORARY reproducer for BUG-05 part (b) (T16). Delete after running.
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptedDataKey, EncryptionContext,
};
use aws_crypto_mpl::{HierarchicalKeyring, Keyring};
const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
const VERSION_BYTES: [u8; 16] = [0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];
struct CountingKeystore {
    version_calls: Mutex<u32>,
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
    async fn get_active_branch_key(&self, _: String) -> Result<BranchKeyMaterials, KeystoreError> { unimplemented!() }
    async fn get_branch_key_version(&self, _: String, v: String) -> Result<BranchKeyMaterials, KeystoreError> {
        *self.version_calls.lock().unwrap() += 1;
        Ok(BranchKeyMaterials::new([7u8; 32], BKID.into(), v, EncryptionContext::new()).unwrap())
    }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}
#[tokio::test]
async fn short_edk_reaches_keystore_before_rejection() {
    for len in [43usize, 44, 50, 59, 60] {
        let ks = Arc::new(CountingKeystore { version_calls: Mutex::new(0) });
        let kr = HierarchicalKeyring::new(ks.clone(), 3600, Some(BKID.into()), None, None, Some("p".into())).unwrap();
        let mut ct = vec![0u8; len];
        if len >= 44 {
            ct[28..44].copy_from_slice(&VERSION_BYTES);
        }
        let edk = EncryptedDataKey::new("aws-kms-hierarchy".into(), BKID.as_bytes().to_vec(), ct);
        let dm = DecryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, EncryptionContext::new(), Default::default(), None, None, None).unwrap();
        let r = kr.on_decrypt(dm, &[edk]).await;
        let inner = r.as_ref().err().and_then(|e| e.collected_errors().first().map(|x| x.message.clone()));
        println!(
            "REPRO BUG-05b ciphertext_len={len}: on_decrypt is_err={} keystore get_branch_key_version calls={} inner_error={:?}",
            r.is_err(),
            *ks.version_calls.lock().unwrap(),
            inner
        );
    }
    let _ = VERSION;
}
```

Observed output (`.agents/tasks/bug-reports/logs/bugrepro05.log`):

```text
running 1 test
REPRO BUG-05b ciphertext_len=43: on_decrypt is_err=true keystore get_branch_key_version calls=0 inner_error=Some("HierarchicalKeyring::on_decrypt: EDK ciphertext too short to contain branch-key version: 43 bytes (need at least 44)")
REPRO BUG-05b ciphertext_len=44: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Branch key unwrap: ciphertext too short: 44 < 60")
REPRO BUG-05b ciphertext_len=50: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Branch key unwrap: ciphertext too short: 50 < 60")
REPRO BUG-05b ciphertext_len=59: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Branch key unwrap: ciphertext too short: 59 < 60")
REPRO BUG-05b ciphertext_len=60: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Branch key unwrap: AES-256-GCM decrypt failed")
test short_edk_reaches_keystore_before_rejection ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Fix options

(a) keygen `.expect`:

1. Propagate the error, for example `.map_err(|e| MaterialsError::new_with_cause("DefaultCmm: ECDSA signing key generation failed", e))?`.
   - Pros: matches the Dafny Default CMM and needs no API change, since the function already returns `Result`.
   - Cons: none significant. Negligible cost.
2. Keep the `.expect`, but document and prove the invariant: treat a keygen failure as fatal, by design, like an RNG failure.
   - Pros: no code change.
   - Cons: diverges from Dafny, and leaves a panic on a library path that a C++ caller can reach.

Recommendation for (a): option 1.

(b) short EDK:

1. Check the exact length before the lookup. In `try_decrypt_edk`, require `ciphertext.len() == 60 + suite.encryption_key_length()` before the cache/keystore step.
   - Pros: rejects all wrong-length EDKs with no I/O, and also fixes BUG-02 C04-F1 on the hierarchical path.
   - Cons: diverges in ordering from Dafny, though not in outcome (both reject). Error text changes for 44–59-byte inputs.
2. Raise the pre-lookup minimum from 44 to 60 (`FIXED_OVERHEAD_LEN`).
   - Pros: the smallest change.
   - Cons: only addresses 44–59; wrong lengths of 60 or more still reach the keystore.
3. No change. Document that the ordering matches Dafny and that a full-length garbage EDK has the same cost.

Recommendation for (b): fold it into the BUG-02 fix (option 1 here). Otherwise option 3 is acceptable; this part on its own isn't worth a dedicated change.

## Questions for the engineers

1. Is a panic acceptable anywhere on the `DefaultCmm` encrypt path (for example by a policy treating entropy failure as fatal), or should all primitive failures surface as `MaterialsError` as in Dafny?
2. Are there other `.expect` calls on primitive `Result`s that the team considers "cannot fail"? The verification analysis lists `default_cmm.rs:100` (provably unreachable) and `cache_entry_identifier.rs:64`.
3. For (b), is matching Dafny's step order a goal, or is rejecting before I/O preferred when the outcome is the same?
4. If the BUG-02 exact-length check is adopted, should it run before the cache/keystore lookup (which would resolve this item) or inside `unwrap`?
