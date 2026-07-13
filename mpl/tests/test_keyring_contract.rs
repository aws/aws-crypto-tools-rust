// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract tests for the abstract `Keyring` trait.
//!
//! These tests verify the abstract `Keyring` trait contract via the in-file
//! `MockKeyring`. They are intentionally NOT duvet-annotated — the
//! corresponding requirements are annotated as `type=exception` in
//! `src/keyring/mod.rs` and will be re-annotated as `type=implementation,test`
//! once concrete keyrings (Raw AES, AWS KMS) are added.
//!
//! The mock's `on_encrypt` / `on_decrypt` exercise every documented branch of
//! the keyring interface (generate-only, encrypt-only, generate+encrypt,
//! no-behavior, decrypt success, plaintext-data-key-already-present, no-matching-EDK,
//! no-decrypt-behavior).

use std::collections::BTreeSet;

use async_trait::async_trait;

use aws_crypto_mpl::Keyring;
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, MaterialsError, MaterialsErrorKind, PlaintextDataKey,
};

// MockKeyring

/// Switches that select which OnEncrypt / OnDecrypt sub-behaviors the mock
/// will attempt. Default = none — exercises the "did not attempt any
/// behavior" branch on both sides.
#[derive(Debug, Clone, Copy, Default)]
struct MockBehaviors {
    /// Attempt the generate-data-key behavior on `on_encrypt`.
    generate: bool,
    /// Attempt the encrypt-data-key behavior on `on_encrypt`.
    encrypt: bool,
    /// Attempt the decrypt-data-key behavior on `on_decrypt`.
    decrypt: bool,
}

/// A test keyring that exposes every contractual branch of the trait.
///
/// `on_encrypt` consumes its input and returns reconstructed materials with
/// a freshly-generated PDK and/or appended EDK depending on `behaviors`.
/// `on_decrypt` walks the input EDK list and, on a (provider_id, provider_info)
/// match, reconstructs the materials with the EDK's ciphertext as the new PDK.
struct MockKeyring {
    behaviors: MockBehaviors,
    provider_id: String,
    provider_info: Vec<u8>,
}

impl MockKeyring {
    fn new(behaviors: MockBehaviors) -> Self {
        Self {
            behaviors,
            provider_id: "mock-keyring".to_string(),
            provider_info: b"mock-info".to_vec(),
        }
    }

    fn with_provider(behaviors: MockBehaviors, id: &str, info: &[u8]) -> Self {
        Self {
            behaviors,
            provider_id: id.to_string(),
            provider_info: info.to_vec(),
        }
    }
}

/// Reconstruct an `EncryptionMaterials` after mock mutation. The struct's
/// fields are private; we round-trip through `EncryptionMaterials::new` to
/// preserve all spec invariants on the way out.
fn rebuild_encryption_materials(
    materials: &EncryptionMaterials,
    edks: Vec<EncryptedDataKey>,
    pdk: Option<PlaintextDataKey>,
) -> Result<EncryptionMaterials, MaterialsError> {
    EncryptionMaterials::new(
        materials.algorithm_suite_id(),
        edks,
        materials.encryption_context().clone(),
        materials.required_encryption_context_keys().clone(),
        pdk,
        materials.signing_key().cloned(),
        materials.symmetric_signing_keys().map(<[_]>::to_vec),
    )
}

/// Reconstruct a `DecryptionMaterials` after mock mutation.
fn rebuild_decryption_materials(
    materials: &DecryptionMaterials,
    pdk: Option<PlaintextDataKey>,
) -> Result<DecryptionMaterials, MaterialsError> {
    DecryptionMaterials::new(
        materials.algorithm_suite_id(),
        materials.encryption_context().clone(),
        materials.required_encryption_context_keys().clone(),
        pdk,
        materials.verification_key().cloned(),
        materials.symmetric_signing_key().cloned(),
    )
}

#[async_trait]
impl Keyring for MockKeyring {
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        let suite = materials.algorithm_suite();
        let mut attempted = false;

        // Generate path: only when configured AND no PDK is already set.
        let new_pdk = if self.behaviors.generate && materials.plaintext_data_key().is_none() {
            attempted = true;
            // Deterministic suite-length filler so the length assertion is precise
            // and tests stay reproducible. Concrete keyrings will source from a
            // CSPRNG (annotated `type=exception` on the trait module).
            Some(PlaintextDataKey::new(vec![
                0xAA;
                suite.encryption_key_length()
            ]))
        } else {
            materials.plaintext_data_key().cloned()
        };

        // Encrypt path: only when configured AND a PDK is present in the
        // (post-generate) state. The mock stores the PDK bytes verbatim as the
        // EDK ciphertext, which lets the symmetric decrypt path recover them.
        let mut new_edks = materials.encrypted_data_keys().to_vec();
        if let Some(ref pdk) = new_pdk
            && self.behaviors.encrypt
        {
            attempted = true;
            new_edks.push(EncryptedDataKey::new(
                self.provider_id.clone(),
                self.provider_info.clone(),
                pdk.as_bytes().to_vec(),
            ));
        }

        if !attempted {
            return Err(MaterialsError::no_behavior_attempted(
                "on_encrypt: no generate-data-key or encrypt-data-key behavior was attempted",
            ));
        }

        rebuild_encryption_materials(&materials, new_edks, new_pdk)
    }

    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError> {
        if materials.plaintext_data_key().is_some() {
            return Err(MaterialsError::plaintext_data_key_already_present(
                "on_decrypt: decryption materials already contain a plaintext data key",
            ));
        }
        if !self.behaviors.decrypt {
            return Err(MaterialsError::no_behavior_attempted(
                "on_decrypt: decrypt-data-key behavior was not attempted",
            ));
        }
        for edk in encrypted_data_keys {
            if edk.key_provider_id == self.provider_id
                && edk.key_provider_info == self.provider_info
            {
                let recovered = PlaintextDataKey::new(edk.ciphertext.clone());
                return rebuild_decryption_materials(&materials, Some(recovered));
            }
        }
        Err(MaterialsError::no_matching_data_key(
            "on_decrypt: no encrypted data key matched this keyring's (provider_id, provider_info)",
        ))
    }
}

// Fixtures

/// 256-bit-key non-signing committing suite. KDF input length = 32 bytes.
const COMMITTING_SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;

fn empty_encryption_materials(suite: AlgorithmSuiteId) -> EncryptionMaterials {
    EncryptionMaterials::new(
        suite,
        vec![],
        EncryptionContext::new(),
        BTreeSet::new(),
        None,
        None,
        None,
    )
    .expect("constructing empty encryption materials")
}

fn encryption_materials_with_pdk(
    suite: AlgorithmSuiteId,
    pdk_bytes: Vec<u8>,
) -> EncryptionMaterials {
    EncryptionMaterials::new(
        suite,
        vec![],
        EncryptionContext::new(),
        BTreeSet::new(),
        Some(PlaintextDataKey::new(pdk_bytes)),
        None,
        None,
    )
    .expect("constructing encryption materials with pdk")
}

fn empty_decryption_materials(suite: AlgorithmSuiteId) -> DecryptionMaterials {
    DecryptionMaterials::new(
        suite,
        EncryptionContext::new(),
        BTreeSet::new(),
        None,
        None,
        None,
    )
    .expect("constructing empty decryption materials")
}

fn decryption_materials_with_pdk(
    suite: AlgorithmSuiteId,
    pdk_bytes: Vec<u8>,
) -> DecryptionMaterials {
    DecryptionMaterials::new(
        suite,
        EncryptionContext::new(),
        BTreeSet::new(),
        Some(PlaintextDataKey::new(pdk_bytes)),
        None,
        None,
    )
    .expect("constructing decryption materials with pdk")
}

// OnEncrypt — generate + encrypt

#[tokio::test]
async fn test_on_encrypt_generate_then_encrypt_modifies_materials() {
    let keyring = MockKeyring::new(MockBehaviors {
        generate: true,
        encrypt: true,
        decrypt: false,
    });
    let suite = COMMITTING_SUITE;
    let expected_pdk_len = suite.specification().encryption_key_length();
    let input = empty_encryption_materials(suite);

    let output = keyring
        .on_encrypt(input)
        .await
        .expect("on_encrypt with generate+encrypt should succeed");

    assert!(
        output.plaintext_data_key().is_some(),
        "generate behavior must set the plaintext data key"
    );
    let pdk_after = output
        .plaintext_data_key()
        .expect("PDK must be set after generate")
        .as_bytes()
        .to_vec();
    assert_eq!(
        pdk_after.len(),
        expected_pdk_len,
        "generated PDK length must equal the suite's encryption_key_length ({expected_pdk_len})"
    );

    assert_eq!(
        output.encrypted_data_keys().len(),
        1,
        "generate+encrypt must produce exactly one EDK"
    );

    let edk = &output.encrypted_data_keys()[0];
    assert_eq!(edk.ciphertext, pdk_after, "EDK ciphertext encodes the PDK");
}

#[tokio::test]
async fn test_on_encrypt_generate_only_with_no_pdk_sets_pdk() {
    let keyring = MockKeyring::new(MockBehaviors {
        generate: true,
        encrypt: false,
        decrypt: false,
    });
    let suite = COMMITTING_SUITE;
    let expected_pdk_len = suite.specification().encryption_key_length();
    let input = empty_encryption_materials(suite);

    let output = keyring.on_encrypt(input).await.expect("generate succeeds");

    assert!(
        output.plaintext_data_key().is_some(),
        "generate must set the plaintext data key when none is present"
    );
    assert_eq!(
        output.plaintext_data_key().expect("PDK must be set").len(),
        expected_pdk_len,
        "generated PDK length must equal the suite's encryption_key_length ({expected_pdk_len})"
    );

    assert!(
        output.encrypted_data_keys().is_empty(),
        "generate-only path must not append EDKs"
    );
}

#[tokio::test]
async fn test_on_encrypt_generate_skipped_when_pdk_already_present() {
    let keyring = MockKeyring::new(MockBehaviors {
        generate: true,
        encrypt: false,
        decrypt: false,
    });
    let original_pdk_bytes = vec![0x11; 32];
    let input = encryption_materials_with_pdk(COMMITTING_SUITE, original_pdk_bytes.clone());

    let result = keyring.on_encrypt(input).await;

    let err = result.expect_err("generate-only path must not attempt generate when PDK is present");
    assert_eq!(
        err.kind,
        MaterialsErrorKind::NoBehaviorAttempted,
        "generate-skipped + no other behavior attempted yields NoBehaviorAttempted; got {err:?}"
    );
}

#[tokio::test]
async fn test_on_encrypt_generated_pdk_length_matches_suite_kdf_input_length() {
    let keyring = MockKeyring::new(MockBehaviors {
        generate: true,
        encrypt: false,
        decrypt: false,
    });
    let suite = COMMITTING_SUITE;
    let expected_len = suite.specification().encryption_key_length();
    let input = empty_encryption_materials(suite);

    let output = keyring.on_encrypt(input).await.expect("generate succeeds");

    assert_eq!(
        output.plaintext_data_key().expect("PDK must be set").len(),
        expected_len,
        "generated PDK length must equal the suite's encryption_key_length ({expected_len})"
    );
}

// OnEncrypt — encrypt only

#[tokio::test]
async fn test_on_encrypt_encrypt_only_with_pdk_appends_edk() {
    let keyring = MockKeyring::new(MockBehaviors {
        generate: false,
        encrypt: true,
        decrypt: false,
    });
    let pdk_bytes = vec![0x55; 32];
    let input = encryption_materials_with_pdk(COMMITTING_SUITE, pdk_bytes.clone());

    let output = keyring.on_encrypt(input).await.expect("encrypt succeeds");

    assert_eq!(
        output.encrypted_data_keys().len(),
        1,
        "encrypt path with PDK present must append exactly one EDK"
    );
    assert_eq!(
        output.encrypted_data_keys()[0].ciphertext,
        pdk_bytes,
        "mock EDK ciphertext encodes the PDK bytes verbatim"
    );
}

#[tokio::test]
async fn test_on_encrypt_encrypt_skipped_when_no_pdk() {
    let keyring = MockKeyring::new(MockBehaviors {
        generate: false,
        encrypt: true,
        decrypt: false,
    });
    let input = empty_encryption_materials(COMMITTING_SUITE);

    let result = keyring.on_encrypt(input).await;

    let err = result.expect_err("encrypt-only path must not attempt encrypt when PDK is absent");
    assert_eq!(
        err.kind,
        MaterialsErrorKind::NoBehaviorAttempted,
        "encrypt-skipped + no other behavior attempted yields NoBehaviorAttempted; got {err:?}"
    );
}

// OnEncrypt — neither behavior attempted

#[tokio::test]
async fn test_on_encrypt_no_behaviors_fails_without_mutation() {
    let keyring = MockKeyring::new(MockBehaviors::default());
    let original_pdk_bytes = vec![0x77; 32];
    let input = encryption_materials_with_pdk(COMMITTING_SUITE, original_pdk_bytes.clone());

    // Capture the inputs we care about BEFORE the call, since the materials are
    // moved into the call and we need the originals to assert non-mutation.
    let original_edk_count = input.encrypted_data_keys().len();
    let result = keyring.on_encrypt(input).await;

    let err = result.expect_err("no-behaviors path must fail");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::NoBehaviorAttempted,
        "no-behaviors path must yield NoBehaviorAttempted; got {err:?}"
    );

    // Reconstructing the original input proves non-mutation: we still see the
    // original PDK bytes and EDK count when we rebuild from the same arguments.
    let untouched = encryption_materials_with_pdk(COMMITTING_SUITE, original_pdk_bytes.clone());
    assert_eq!(
        untouched
            .plaintext_data_key()
            .expect("original PDK still recoverable")
            .as_bytes(),
        &original_pdk_bytes,
        "original materials are not mutated by failed on_encrypt"
    );
    assert_eq!(
        untouched.encrypted_data_keys().len(),
        original_edk_count,
        "EDK list of original materials is unchanged"
    );
}

// OnEncrypt → OnDecrypt round-trip

#[tokio::test]
async fn test_on_encrypt_then_on_decrypt_round_trip_recovers_pdk() {
    let encrypt_keyring = MockKeyring::new(MockBehaviors {
        generate: true,
        encrypt: true,
        decrypt: false,
    });
    let decrypt_keyring = MockKeyring::new(MockBehaviors {
        generate: false,
        encrypt: false,
        decrypt: true,
    });

    let enc_input = empty_encryption_materials(COMMITTING_SUITE);
    let enc_output = encrypt_keyring
        .on_encrypt(enc_input)
        .await
        .expect("encrypt succeeds");

    let original_pdk_bytes = enc_output
        .plaintext_data_key()
        .expect("encrypt output has PDK")
        .as_bytes()
        .to_vec();
    let edks = enc_output.encrypted_data_keys().to_vec();

    let dec_input = empty_decryption_materials(COMMITTING_SUITE);
    let dec_output = decrypt_keyring
        .on_decrypt(dec_input, &edks)
        .await
        .expect("decrypt succeeds");

    assert_eq!(
        dec_output
            .plaintext_data_key()
            .expect("decrypt output has PDK")
            .as_bytes(),
        &original_pdk_bytes,
        "round-trip recovers the original plaintext data key"
    );
}

// OnDecrypt — success

#[tokio::test]
async fn test_on_decrypt_success_sets_pdk() {
    let keyring = MockKeyring::new(MockBehaviors {
        generate: false,
        encrypt: false,
        decrypt: true,
    });
    let pdk_bytes = vec![0x33; 32];
    let edks = vec![EncryptedDataKey::new(
        "mock-keyring".to_string(),
        b"mock-info".to_vec(),
        pdk_bytes.clone(),
    )];
    let input = empty_decryption_materials(COMMITTING_SUITE);

    let output = keyring
        .on_decrypt(input, &edks)
        .await
        .expect("decrypt succeeds when EDK matches");

    assert!(
        output.plaintext_data_key().is_some(),
        "decrypt success must set the plaintext data key"
    );
    assert_eq!(
        output
            .plaintext_data_key()
            .expect("PDK must be set")
            .as_bytes(),
        &pdk_bytes,
        "PDK on output materials matches the EDK's ciphertext"
    );
    assert_eq!(
        output.plaintext_data_key().expect("PDK present").len(),
        pdk_bytes.len(),
        "decrypt path produced the expected PDK length"
    );
}

// OnDecrypt — plaintext already present

#[tokio::test]
async fn test_on_decrypt_with_existing_pdk_fails_without_mutation() {
    let keyring = MockKeyring::new(MockBehaviors {
        generate: false,
        encrypt: false,
        decrypt: true,
    });
    let original_pdk_bytes = vec![0x99; 32];
    let edks = vec![EncryptedDataKey::new(
        "mock-keyring".to_string(),
        b"mock-info".to_vec(),
        vec![0xCC; 32],
    )];
    let input = decryption_materials_with_pdk(COMMITTING_SUITE, original_pdk_bytes.clone());

    let result = keyring.on_decrypt(input, &edks).await;

    let err = result.expect_err("plaintext-data-key-already-present path must fail");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::PlaintextDataKeyAlreadyPresent,
        "plaintext-data-key-already-present path must yield PlaintextDataKeyAlreadyPresent; got {err:?}"
    );

    let untouched = decryption_materials_with_pdk(COMMITTING_SUITE, original_pdk_bytes.clone());
    assert_eq!(
        untouched
            .plaintext_data_key()
            .expect("original PDK still recoverable")
            .as_bytes(),
        &original_pdk_bytes,
        "original materials are not mutated by failed on_decrypt"
    );
}

// OnDecrypt — no matching EDK

#[tokio::test]
async fn test_on_decrypt_no_matching_edk_fails_without_mutation() {
    let keyring = MockKeyring::with_provider(
        MockBehaviors {
            generate: false,
            encrypt: false,
            decrypt: true,
        },
        "mock-keyring",
        b"mock-info",
    );
    // EDK from a DIFFERENT provider — no match.
    let edks = vec![EncryptedDataKey::new(
        "other-keyring".to_string(),
        b"other-info".to_vec(),
        vec![0xDD; 32],
    )];
    let input = empty_decryption_materials(COMMITTING_SUITE);

    let result = keyring.on_decrypt(input, &edks).await;

    let err = result.expect_err("no-matching-EDK path must fail");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::NoMatchingDataKey,
        "no-matching-EDK path must yield NoMatchingDataKey; got {err:?}"
    );

    let untouched = empty_decryption_materials(COMMITTING_SUITE);
    assert!(
        untouched.plaintext_data_key().is_none(),
        "original materials still have no PDK after failed on_decrypt"
    );
}

// OnDecrypt — no behavior attempted

#[tokio::test]
async fn test_on_decrypt_no_behavior_fails_without_mutation() {
    let keyring = MockKeyring::new(MockBehaviors::default());
    let edks = vec![EncryptedDataKey::new(
        "mock-keyring".to_string(),
        b"mock-info".to_vec(),
        vec![0xEE; 32],
    )];
    let input = empty_decryption_materials(COMMITTING_SUITE);

    let result = keyring.on_decrypt(input, &edks).await;

    let err = result.expect_err("no-behavior path must fail");

    assert_eq!(
        err.kind,
        MaterialsErrorKind::NoBehaviorAttempted,
        "no-decrypt-behavior path must yield NoBehaviorAttempted; got {err:?}"
    );

    let untouched = empty_decryption_materials(COMMITTING_SUITE);
    assert!(
        untouched.plaintext_data_key().is_none(),
        "original materials still have no PDK after failed on_decrypt"
    );
}
