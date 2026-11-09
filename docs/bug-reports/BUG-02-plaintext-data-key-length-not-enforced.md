# BUG-02: Plaintext data key length is not enforced (hierarchical OnDecrypt and materials constructors)

Summary: `HierarchicalKeyring::on_decrypt` returns whatever length the AES-GCM unwrap produces (0, 5, 64 bytes, and so on). Separately, `EncryptionMaterials::new` and `DecryptionMaterials::new` accept a plaintext data key (PDK) of any length. The spec requires the PDK length to equal the algorithm suite's key length.

- Confidence: Confirmed by test
- Spec conflict: yes
- Severity: Medium. This is a spec MUST deviation and a divergence from the Dafny MPL, which checks length in both places. Producing a wrong-length EDK needs the branch key, or a custom CMM/keyring supplying the PDK. Downstream ESDK checks catch it for identity-KDF and V2 (committing) suites, but by code reading not for V1 HKDF suites in release builds.
- Related IDs: VR-2026-C04 (C04-F1 = keyring OnDecrypt, C04-F2 = materials constructors); cap:cat1 (1a)

## Location

Verified against `HEAD a1e23d7`.

C04-F1, `mpl/src/aws_kms/hierarchical_keyring.rs:414-423`. The unwrapped bytes go straight into the materials:

```rust
414            match self.try_decrypt_edk(&materials, edk, &branch_key_id).await {
415                Ok(plaintext_dk_bytes) => {
416                    return DecryptionMaterials::new(
417                        materials.algorithm_suite_id(),
418                        materials.encryption_context().clone(),
419                        materials.required_encryption_context_keys().clone(),
420                        Some(PlaintextDataKey::new(plaintext_dk_bytes)),
```

`try_decrypt_edk` ends with `branch_key_wrap::unwrap(..)` (line 601). `unwrap` (`mpl/src/aws_kms/branch_key_wrap.rs:225-236`) only requires `ciphertext.len() >= 60` (`FIXED_OVERHEAD_LEN`), and the encrypted-key slice is whatever lies between offset 44 and the tag.

C04-F2: neither constructor checks the PDK length.

- `mpl/src/structures/encryption_materials.rs:30-89`: its checks cover required-EC keys, EDKs present only with a PDK, signing-key presence, and symmetric-signing-key presence.
- `mpl/src/structures/decryption_materials.rs:28-81`: its checks cover required-EC keys, verification-key presence and length, and symmetric-signing-key presence.

As a result, `HierarchicalKeyring::on_encrypt` and `RawAesKeyring::on_encrypt` wrap a caller-supplied PDK of any length.

Control: `RawAesKeyring::on_decrypt` does enforce the length (`mpl/src/keyring/raw_aes_keyring.rs:282, 326-330`):

```rust
326            if plaintext_dk.len() != expected_dk_len {
327                collected_errors.push(MaterialsError::keyring_failed(format!(
328                    "EncryptedDataKey {index}: decrypted data key is {} bytes, expected {expected_dk_len} for the algorithm suite",
```

## Expected behavior

- `spec/framework/structures.md#plaintext-data-key` (encryption materials): "The plaintext data key MUST: - Fit the specification for the [key derivation algorithm](algorithm-suites.md#key-derivation-algorithm) included in this decryption material's [algorithm suite]".
- `spec/framework/structures.md#plaintext-data-key-1` (decryption materials): "The plaintext data key MUST: - Fit the specification for the [encryption algorithm](algorithm-suites.md#encryption-algorithm) included in this decryption material's [algorithm suite]".
- `spec/framework/cmm-interface.md#get-encryption-materials`: "The plaintext data key length MUST be equal to the [key derivation input length](algorithm-suites.md#key-derivation-input-length)."
- `spec/framework/keyring-interface.md#generate-data-key`: "The length of the output plaintext data key MUST be equal to the KDF input length of the [algorithm suite]". This covers generation only; the hierarchical keyring's own generation path (`generate_random_data_key`, line 608) complies.

The Dafny MPL enforces this in three places (read on GitHub `main` while writing this report):

- `Materials.dfy`: `ValidEncryptionMaterials` / `ValidDecryptionMaterials` require `GetEncryptKeyLength(suite) == |plaintextDataKey|`. `EncryptionMaterialAddDataKey` / `DecryptionMaterialsAddDataKey` fail with "plaintextDataKey does not match Algorithm Suite specification." ([source](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Materials.dfy))
- `AwsKmsHierarchicalKeyring.dfy` `KmsHierarchyUnwrapKeyMaterial.Invoke`: requires `|wrappedMaterial| == EXPECTED_EDK_CIPHERTEXT_OVERHEAD + KeyLength`, otherwise "Received EDK Ciphertext of incorrect length2." ([source](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy))

## Actual behavior

C04-F1:

1. A party holding the branch key calls the crate's own `wrap()` with a 5-, 0- or 64-byte PDK. This gives EDK ciphertexts of 65, 60 and 124 bytes.
2. `on_decrypt` filters the EDK by provider id and branch key id, parses the version, and fetches the branch key.
3. `unwrap` accepts any length ≥ 60, AES-GCM authenticates, and the plaintext is returned.
4. `DecryptionMaterials::new` accepts it. `on_decrypt` returns `Ok` with a PDK of 5, 0 or 64 bytes for a suite that needs 32.

C04-F2:

1. `EncryptionMaterials::new(.., Some(5-byte PDK), ..)` and `DecryptionMaterials::new(.., Some(5-byte PDK), ..)` both return `Ok`.
2. `HierarchicalKeyring::on_encrypt` wraps the 5-byte PDK (65-byte EDK) and returns `Ok`. So does `RawAesKeyring::on_encrypt`.
3. `RawAesKeyring::on_decrypt` then rejects it, which shows the two keyrings behave inconsistently.

## Impact

How a wrong-length PDK can arise:

- (a) On decrypt, from a message whose hierarchical EDK was produced by someone who holds the branch key. Such a party can already decrypt anything under that branch key, so this isn't a confidentiality break. It does let them create messages that some runtimes accept and others reject.
- (b) On encrypt, from a custom CMM, or a custom generator keyring inside a multi-keyring, that supplies a wrong-length PDK.

Downstream handling in the ESDK (`esdk/src/key_derivation.rs`, code reading, not tested end to end):

- Identity-KDF suites reject a wrong length at lines 83-93.
- V2 (committing) suites reject it at lines 190-195.
- V1 HKDF suites (lines 105-132) pass the PDK to HKDF as IKM with no length check. The only guard is `debug_assert_eq!` at line 286, which panics in debug builds and is compiled out in release.

So in a release build, a V1 HKDF message can be encrypted or decrypted with a short (for example 0-byte) data key. On encrypt that's a weak key. On decrypt it's an interoperability difference with Dafny-based runtimes, which reject such an EDK.

Realistic exploitability is low: it needs either branch-key possession or a buggy or malicious custom component in the caller's own configuration.

## Reproduction / evidence

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

## Fix options

1. Enforce in the materials constructors. In `EncryptionMaterials::new` and `DecryptionMaterials::new`, return `Err` when `pdk.len() != suite.encryption_key_length()`.
   - Pros: matches Dafny `ValidEncryptionMaterials` / `ValidDecryptionMaterials`, and every keyring, CMM and custom component benefits automatically.
   - Cons: a behavior change for any external code that currently builds materials with a non-standard PDK length (possibly test code). The `Err` surfaces from a constructor rather than from a keyring, so error kinds and messages change.
2. Enforce at the keyring boundary.
   - In `try_decrypt_edk` / `unwrap`, require `ciphertext.len() == 60 + suite.encryption_key_length()` before decrypting. This is the Dafny check and also avoids an AES-GCM call on a wrong-length EDK.
   - In `on_encrypt` of both keyrings, reject a supplied PDK of the wrong length.
   - Pros: a localized change, and the error reported per EDK matches what the raw AES keyring already does.
   - Cons: leaves the materials types able to hold invalid state for other producers, such as custom keyrings.
3. Do both. Constructors are the invariant; the keyring pre-check gives a clearer per-EDK error and rejects before the AES call.
   - Cons: two checks for one rule, which is minor.

Recommendation: option 3, or at minimum option 1 plus the exact-length EDK check from option 2. Also consider replacing the `debug_assert_eq!` in `esdk/src/key_derivation.rs:286` with a real check, so V1 HKDF suites don't depend on debug builds.

## Questions for the engineers

1. Is there any intended use of `EncryptionMaterials` / `DecryptionMaterials` with a PDK whose length differs from `encryption_key_length()` (for example a test helper or a migration path) that a constructor check would break?
2. Should the hierarchical keyring reject wrong-length EDKs before the AES-GCM open (the Dafny behavior), or after (the raw AES keyring behavior)? This affects error messages only.
3. Is the `debug_assert_eq!` in `derive_keys` meant as the sole guard for V1 HKDF suites, or was a real check intended there?
4. Are there cross-runtime test vectors with wrong-length hierarchical EDKs that should be added, so all runtimes agree on rejection?
