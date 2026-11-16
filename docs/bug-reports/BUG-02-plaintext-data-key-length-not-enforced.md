# BUG-02: Plaintext data key length is not enforced (hierarchical OnDecrypt and materials constructors)

Status: Fixed on main in `e9bde48` (#98). See "Status on main (620771c)" below.

Summary (as found at `a1e23d7`): `HierarchicalKeyring::on_decrypt` returned whatever length the AES-GCM unwrap produced (0, 5, 64 bytes, and so on). Separately, `EncryptionMaterials::new` and `DecryptionMaterials::new` accepted a plaintext data key (PDK) of any length. The spec requires the PDK length to equal the algorithm suite's key length.

- Confidence: Confirmed by test
- Spec conflict: yes
- Severity: Medium. This is a spec MUST deviation and a divergence from the Dafny MPL, which checks length in both places. Producing a wrong-length EDK needs the branch key, or a custom CMM/keyring supplying the PDK. Downstream ESDK checks catch it for identity-KDF and V2 (committing) suites, but by code reading not for V1 HKDF suites in release builds.
- Related IDs: VR-2026-C04 (C04-F1 = keyring OnDecrypt, C04-F2 = materials constructors); cap:cat1 (1a); TM-MPL-006 (Medium), TM-MPL-023 (Low). Ratings are from `docs/threat-model.md` (HEAD 9955ecd), where the fix is recorded as a mitigation for both threats and no rating changed; targets are from `docs/verification-targets.md`.
- Completeness audit mapping (`docs/completeness-audit.md` section 3b): BUG-02 (Fixed) -> TM-MPL-006, 023 -> C04.
- Last cross-checked: HEAD 9955ecd (code == main 620771c for mpl/ and prim/)

## Status on main (620771c)

- Status: Fixed on main (both C04-F1 and C04-F2).
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-02.
- Evidence: with the reproducer adapted for API changes only, F1 now prints `on_decrypt Err: InvalidMaterials: plaintext data key is N bytes, expected 32 for the algorithm suite` for N = 5, 0 and 64. In F2, both materials builders return that `Err`, so the test fails at its own `em.unwrap()` (`.agents/tasks/bug-recheck/logs/recheck02.log`).
- Fixing commit: `e9bde48` "feat(esdk): retarget the ESDK and C++ shim onto the native Rust MPL (#98)". It introduced `check_data_key_length` and moved the hierarchical OnDecrypt onto `add_data_key`. A later commit, `9646828` (#167, "check keyring and CMM materials by default"), adds further transition checks.
- Where the fix lives: `mpl/src/structures/algorithm_suite.rs:547` (`check_data_key_length`). It is called from the builders (`encryption_materials.rs:365`, `decryption_materials.rs:303`) and from `add_data_key` (`encryption_materials.rs:60`, `decryption_materials.rs:56`). The hierarchical keyring's OnDecrypt now calls `materials.add_data_key(..)` (`mpl/src/aws_kms/hierarchical_keyring.rs:767`).

The sections after Location are the original analysis at `a1e23d7`, kept as history. Their line numbers refer to `a1e23d7`.

## Location

Current code (`main` `620771c`), where the length is now enforced:

```rust
547 pub(crate) fn check_data_key_length(
548     suite: &AlgorithmSuite,
549     key: &PlaintextDataKey,
550 ) -> Result<(), Error> {
551     let expected_len = suite.encryption_key_length();
552     if key.len() != expected_len {
553         return Err(Error::new(
554             Kind::InvalidMaterials,
```

(`mpl/src/structures/algorithm_suite.rs:547-562`)

```rust
764             match self.try_decrypt_edk(&materials, edk, &branch_key_id).await {
765                 Ok(plaintext_dk_bytes) => {
766                     let materials =
767                         materials.add_data_key(PlaintextDataKey::new(plaintext_dk_bytes))?;
```

(`mpl/src/aws_kms/hierarchical_keyring.rs:764-767`)

Originally reported at `a1e23d7`:

- C04-F1: `hierarchical_keyring.rs:414-423`. OnDecrypt built `DecryptionMaterials::new(.., Some(PlaintextDataKey::new(plaintext_dk_bytes)), ..)` with no length check. `branch_key_wrap::unwrap` (`branch_key_wrap.rs:225-236`) only required `ciphertext.len() >= 60`.
- C04-F2: `EncryptionMaterials::new` (`encryption_materials.rs:30-89`) and `DecryptionMaterials::new` (`decryption_materials.rs:28-81`) did not check the PDK length.
- Control: `RawAesKeyring::on_decrypt` enforced the length (`raw_aes_keyring.rs:282, 326-330`).

## Original analysis at a1e23d7 (history)

The rest of this report describes the behavior at `a1e23d7`, before the fix.

### Expected behavior

- `spec/framework/structures.md#plaintext-data-key` (encryption materials): "The plaintext data key MUST: - Fit the specification for the [key derivation algorithm](algorithm-suites.md#key-derivation-algorithm) included in this decryption material's [algorithm suite]".
- `spec/framework/structures.md#plaintext-data-key-1` (decryption materials): "The plaintext data key MUST: - Fit the specification for the [encryption algorithm](algorithm-suites.md#encryption-algorithm) included in this decryption material's [algorithm suite]".
- `spec/framework/cmm-interface.md#get-encryption-materials`: "The plaintext data key length MUST be equal to the [key derivation input length](algorithm-suites.md#key-derivation-input-length)."
- `spec/framework/keyring-interface.md#generate-data-key`: "The length of the output plaintext data key MUST be equal to the KDF input length of the [algorithm suite]". This covers generation only; the hierarchical keyring's own generation path (`generate_random_data_key`, line 608) complies.

The Dafny MPL enforces this in three places (read on GitHub `main` while writing this report):

- `Materials.dfy`: `ValidEncryptionMaterials` / `ValidDecryptionMaterials` require `GetEncryptKeyLength(suite) == |plaintextDataKey|`. `EncryptionMaterialAddDataKey` / `DecryptionMaterialsAddDataKey` fail with "plaintextDataKey does not match Algorithm Suite specification." ([source](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Materials.dfy))
- `AwsKmsHierarchicalKeyring.dfy` `KmsHierarchyUnwrapKeyMaterial.Invoke`: requires `|wrappedMaterial| == EXPECTED_EDK_CIPHERTEXT_OVERHEAD + KeyLength`, otherwise "Received EDK Ciphertext of incorrect length2." ([source](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy))

### Actual behavior

C04-F1:

1. A party holding the branch key calls the crate's own `wrap()` with a 5-, 0- or 64-byte PDK. This gives EDK ciphertexts of 65, 60 and 124 bytes.
2. `on_decrypt` filters the EDK by provider id and branch key id, parses the version, and fetches the branch key.
3. `unwrap` accepts any length ≥ 60, AES-GCM authenticates, and the plaintext is returned.
4. `DecryptionMaterials::new` accepts it. `on_decrypt` returns `Ok` with a PDK of 5, 0 or 64 bytes for a suite that needs 32.

C04-F2:

1. `EncryptionMaterials::new(.., Some(5-byte PDK), ..)` and `DecryptionMaterials::new(.., Some(5-byte PDK), ..)` both return `Ok`.
2. `HierarchicalKeyring::on_encrypt` wraps the 5-byte PDK (65-byte EDK) and returns `Ok`. So does `RawAesKeyring::on_encrypt`.
3. `RawAesKeyring::on_decrypt` then rejects it, which shows the two keyrings behave inconsistently.

### Impact

How a wrong-length PDK can arise:

- (a) On decrypt, from a message whose hierarchical EDK was produced by someone who holds the branch key. Such a party can already decrypt anything under that branch key, so this isn't a confidentiality break. It does let them create messages that some runtimes accept and others reject.
- (b) On encrypt, from a custom CMM, or a custom generator keyring inside a multi-keyring, that supplies a wrong-length PDK.

Downstream handling in the ESDK (`esdk/src/key_derivation.rs`, code reading, not tested end to end):

- Identity-KDF suites reject a wrong length at lines 83-93.
- V2 (committing) suites reject it at lines 190-195.
- V1 HKDF suites (lines 105-132) pass the PDK to HKDF as IKM with no length check. The only guard is `debug_assert_eq!` at line 286, which panics in debug builds and is compiled out in release.

So in a release build, a V1 HKDF message can be encrypted or decrypted with a short (for example 0-byte) data key. On encrypt that's a weak key. On decrypt it's an interoperability difference with Dafny-based runtimes, which reject such an EDK.

Realistic exploitability is low: it needs either branch-key possession or a buggy or malicious custom component in the caller's own configuration.

### Reproduction / evidence

Reproducer: `mpl/tests/zz_bugrepro_02_pdk_length.rs` (a temporary untracked test, removed from the tree after the run; full source below, copy in `.agents/tasks/bug-reports/reproducers/`). Command: `cd mpl && cargo test --test zz_bugrepro_02_pdk_length -- --nocapture`.

```rust
// TEMPORARY reproducer for BUG-02 (C04-F1 / C04-F2). Delete after running.
use std::sync::Arc;
use async_trait::async_trait;
use aws_crypto_mpl::aws_kms::__test_internals::wrap;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, DecryptionMaterials,
    EncryptedDataKey, EncryptionContext, EncryptionMaterials, PlaintextDataKey,
};
use aws_crypto_mpl::{AesGcm, HierarchicalKeyring, Keyring, RawAesKeyring};
const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf;
fn bkm() -> BranchKeyMaterials {
    BranchKeyMaterials::new([7u8; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap()
}
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
    async fn get_active_branch_key(&self, _: String) -> Result<BranchKeyMaterials, KeystoreError> { Ok(bkm()) }
    async fn get_branch_key_version(&self, _: String, _: String) -> Result<BranchKeyMaterials, KeystoreError> { Ok(bkm()) }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}
fn keyring() -> HierarchicalKeyring {
    HierarchicalKeyring::new(Arc::new(FakeKeystore), 3600, Some(BKID.into()), None, None, Some("p".into())).unwrap()
}
fn empty_dm() -> DecryptionMaterials {
    DecryptionMaterials::new(SUITE, EncryptionContext::new(), Default::default(), None, None, None).unwrap()
}
#[tokio::test]
async fn f1_hierarchical_on_decrypt_returns_wrong_length_pdk() {
    println!("REPRO BUG-02 F1 suite {SUITE:?} encryption_key_length = {}", SUITE.specification().encryption_key_length());
    for pdk_len in [5usize, 0, 64] {
        // An EDK produced by the real wrap() over a PDK of the wrong length,
        // i.e. what any party holding the branch key could produce.
        let ct = wrap(&bkm(), &EncryptionContext::new(), &vec![0xAA; pdk_len]).unwrap();
        let edk = EncryptedDataKey::new("aws-kms-hierarchy".into(), BKID.as_bytes().to_vec(), ct.clone());
        let out = keyring().on_decrypt(empty_dm(), &[edk]).await;
        match out {
            Ok(m) => println!(
                "REPRO BUG-02 F1 edk_ciphertext_len={} -> on_decrypt Ok, plaintext_data_key len = {}",
                ct.len(),
                m.plaintext_data_key().unwrap().len()
            ),
            Err(e) => println!("REPRO BUG-02 F1 edk_ciphertext_len={} -> on_decrypt Err: {}", ct.len(), e.message),
        }
    }
}
#[tokio::test]
async fn f2_constructors_accept_wrong_length_pdk_and_keyrings_pass_it_through() {
    let em = EncryptionMaterials::new(SUITE, vec![], EncryptionContext::new(), Default::default(), Some(PlaintextDataKey::new(vec![0xBB; 5])), None, None);
    println!("REPRO BUG-02 F2 EncryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = {}", em.is_ok());
    let dm = DecryptionMaterials::new(SUITE, EncryptionContext::new(), Default::default(), Some(PlaintextDataKey::new(vec![0xBB; 5])), None, None);
    println!("REPRO BUG-02 F2 DecryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = {}", dm.is_ok());
    let out = keyring().on_encrypt(em.unwrap()).await.unwrap();
    println!(
        "REPRO BUG-02 F2 HierarchicalKeyring::on_encrypt Ok: pdk len = {}, edk ciphertext len = {}",
        out.plaintext_data_key().unwrap().len(),
        out.encrypted_data_keys()[0].ciphertext.len()
    );
    // Same pass-through on the raw AES keyring's on_encrypt; its on_decrypt
    // (unlike the hierarchical one) then rejects the wrong length.
    let raw = RawAesKeyring::new("ns", "name", vec![9u8; 32], AesGcm::Aes256Gcm).unwrap();
    let em2 = EncryptionMaterials::new(SUITE, vec![], EncryptionContext::new(), Default::default(), Some(PlaintextDataKey::new(vec![0xBB; 5])), None, None).unwrap();
    let enc = raw.on_encrypt(em2).await;
    println!("REPRO BUG-02 F2 RawAesKeyring::on_encrypt(5-byte PDK) is_ok = {}", enc.is_ok());
    let edks = enc.unwrap().encrypted_data_keys().to_vec();
    match raw.on_decrypt(empty_dm(), &edks).await {
        Ok(m) => println!("REPRO BUG-02 RawAesKeyring::on_decrypt Ok len {}", m.plaintext_data_key().unwrap().len()),
        Err(e) => println!(
            "REPRO BUG-02 RawAesKeyring::on_decrypt Err: {} | first nested: {:?}",
            e.message,
            e.collected_errors().first().map(|x| x.message.clone())
        ),
    }
}
```

Observed output (`.agents/tasks/bug-reports/logs/bugrepro02.log`):

```text
running 2 tests
REPRO BUG-02 F1 suite AlgAes256GcmIv12Tag16NoKdf encryption_key_length = 32
REPRO BUG-02 F2 EncryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = true
REPRO BUG-02 F2 DecryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = true
REPRO BUG-02 F2 HierarchicalKeyring::on_encrypt Ok: pdk len = 5, edk ciphertext len = 65
REPRO BUG-02 F1 edk_ciphertext_len=65 -> on_decrypt Ok, plaintext_data_key len = 5
REPRO BUG-02 F2 RawAesKeyring::on_encrypt(5-byte PDK) is_ok = true
REPRO BUG-02 RawAesKeyring::on_decrypt Err: RawAesKeyring::on_decrypt: unable to decrypt any encrypted data key | first nested: Some("EncryptedDataKey 0: decrypted data key is 5 bytes, expected 32 for the algorithm suite")
REPRO BUG-02 F1 edk_ciphertext_len=60 -> on_decrypt Ok, plaintext_data_key len = 0
REPRO BUG-02 F1 edk_ciphertext_len=124 -> on_decrypt Ok, plaintext_data_key len = 64
test f2_constructors_accept_wrong_length_pdk_and_keyrings_pass_it_through ... ok
test f1_hierarchical_on_decrypt_returns_wrong_length_pdk ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

The V1 HKDF release-build path in the ESDK (Impact section) was not exercised by any test; that part is code reading only.

### Re-check on main (620771c)

The reproducer was adapted for API changes only. The suite is now `AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf)` and the raw AES wrapping algorithm is `AesWrappingAlg::AlgAes256GcmIv12Tag16`. The test uses builders instead of positional constructors, and prints the constructor `Err` text before the original `unwrap()`. The inputs are the same 5-, 0- and 64-byte keys under a 32-byte suite. Adapted reproducer: [`zz_bugrepro_02_pdk_length.rs`](../../.agents/tasks/bug-recheck/reproducers/zz_bugrepro_02_pdk_length.rs). Same command as above.

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck02.log`, trimmed):

```text
REPRO BUG-02 F1 suite Esdk(AlgAes256GcmIv12Tag16NoKdf) encryption_key_length = 32
REPRO BUG-02 F2 EncryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = false
REPRO BUG-02 F2 EncryptionMaterials::new Err = InvalidMaterials: plaintext data key is 5 bytes, expected 32 for the algorithm suite
REPRO BUG-02 F2 DecryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = false
REPRO BUG-02 F2 DecryptionMaterials::new Err = InvalidMaterials: plaintext data key is 5 bytes, expected 32 for the algorithm suite
...
REPRO BUG-02 F1 edk_ciphertext_len=65 -> on_decrypt Err: InvalidMaterials: plaintext data key is 5 bytes, expected 32 for the algorithm suite
REPRO BUG-02 F1 edk_ciphertext_len=60 -> on_decrypt Err: InvalidMaterials: plaintext data key is 0 bytes, expected 32 for the algorithm suite
REPRO BUG-02 F1 edk_ciphertext_len=124 -> on_decrypt Err: InvalidMaterials: plaintext data key is 64 bytes, expected 32 for the algorithm suite
...
test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

F1 "passes" only because it prints instead of asserting. Its output is the fixed behavior. F2 fails at the original test's own `em.unwrap()`, because the builder now rejects the 5-byte key. The rest of F2 (hierarchical and raw AES `on_encrypt` pass-through) cannot be reached that way any more.

## Resolved

Fixed on `main` in `e9bde48` (#98), as described in the Status section. Both sub-findings are covered. Materials can no longer be built with a wrong-length PDK, and `add_data_key` rejects one, so a keyring has no path left to hand back a wrong-length key. This matches fix option 3 from the original report in effect, with the check on the materials. The original fix options are no longer needed and were removed from this report. They remain in the git history of this file.

Questions that may still be relevant:

1. The ESDK V1 HKDF path in `esdk/src/key_derivation.rs` was guarded only by a `debug_assert_eq!` at `a1e23d7`. That ESDK path was not re-checked on `main`. With the MPL now rejecting wrong-length keys, is a separate ESDK check still wanted as defense-in-depth?
2. The hierarchical keyring now rejects a wrong-length key after the AES-GCM open (at `add_data_key`). The Dafny MPL rejects a wrong-length EDK before the open. Should the exact-length EDK check also be added before the open? This affects error messages and ordering only.
3. Are there cross-runtime test vectors with wrong-length hierarchical EDKs, so all runtimes agree on rejection?
