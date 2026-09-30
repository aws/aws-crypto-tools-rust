// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::ErrorKind;
use std::collections::BTreeSet;

use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptionContext, EsdkAlgorithmSuiteId,
    PlaintextDataKey, SymmetricSigningKey, VerificationKey,
};

const NO_SIGN_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
const P256_SIGN_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256);
const SIGN_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384);

fn make_ec_with_keys(keys: &[&str]) -> EncryptionContext {
    keys.iter().map(|&k| (k, "val")).collect()
}

// SEC1 compressed P-256 verification key: 1 byte tag (0x02) + 32 bytes X = 33 bytes.
fn p256_verification_key() -> VerificationKey {
    let mut bytes = vec![0u8; 33];
    bytes[0] = 0x02;
    VerificationKey::new(bytes)
}

// SEC1 compressed P-384 verification key: 1 byte tag (0x02) + 48 bytes X = 49 bytes.
fn p384_verification_key() -> VerificationKey {
    let mut bytes = vec![0u8; 49];
    bytes[0] = 0x02;
    VerificationKey::new(bytes)
}

#[test]
fn test_valid_construction_minimal() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .build();
    assert!(result.is_ok());
}

#[test]
fn test_valid_construction_with_all_optional_fields() {
    let ec = make_ec_with_keys(&["k1", "aws-crypto-public-key"]);
    let reck = BTreeSet::from(["k1".to_string()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = p384_verification_key();

    // ESDK signing suite: asymmetric only (no symmetric_signing_key).
    let result = DecryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .plaintext_data_key(pdk)
        .verification_key(vk)
        .build();
    assert!(result.is_ok());
}

#[test]
fn test_required_ec_keys_must_be_subset() {
    let ec = make_ec_with_keys(&["existing"]);
    let reck = BTreeSet::from(["missing".to_string()]);

    let result = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .build();
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().kind(),
        ErrorKind::EncryptionContextMismatch
    );
}

#[test]
fn test_symmetric_key_rejected_without_symmetric_signing() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let ssk = SymmetricSigningKey::new(b"sym".to_vec());

    let result = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .symmetric_signing_key(ssk)
        .build();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidMaterials);
}

#[test]
fn test_verification_key_length_must_match_algorithm_suite() {
    // Reject both too-short and too-long verification keys on both P-256
    // (33-byte SEC1-compressed) and P-384 (49-byte SEC1-compressed) signing
    // suites. The four (suite, actual_len) combinations catch one-sided
    // length-check bugs (`>=`, `<=`) that would otherwise slip through.
    let cases: [(AlgorithmSuiteId, usize); 4] = [
        (P256_SIGN_SUITE, 32), // too short for P-256 (expects 33)
        (P256_SIGN_SUITE, 49), // too long for P-256 (49 is P-384's length)
        (SIGN_SUITE, 32),      // too short for P-384 (expects 49)
        (SIGN_SUITE, 200),     // too long for P-384
    ];
    for (suite_id, bad_len) in cases {
        let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
        let reck = BTreeSet::new();
        let bad_vk = VerificationKey::new(vec![0x04; bad_len]);

        let result = DecryptionMaterials::builder()
            .algorithm_suite_id(suite_id)
            .encryption_context(ec)
            .required_encryption_context_keys(reck)
            .verification_key(bad_vk)
            .build();
        let err = result.expect_err(&format!(
            "{suite_id:?} with {bad_len}-byte verification key must fail"
        ));
        assert_eq!(err.kind(), ErrorKind::InvalidMaterials);
    }
}

#[test]
fn test_verification_key_correct_length_succeeds() {
    // Positive companion: cover BOTH signing families so a spec-table row
    // swap between P-256 (65) and P-384 (97) surfaces as a failure.
    let cases: [(AlgorithmSuiteId, VerificationKey); 2] = [
        (P256_SIGN_SUITE, p256_verification_key()),
        (SIGN_SUITE, p384_verification_key()),
    ];
    for (suite_id, vk) in cases {
        let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
        let reck = BTreeSet::new();

        let result = DecryptionMaterials::builder()
            .algorithm_suite_id(suite_id)
            .encryption_context(ec)
            .required_encryption_context_keys(reck)
            .verification_key(vk)
            .build();
        assert!(
            result.is_ok(),
            "{suite_id:?} with correctly-sized verification key must succeed: {:?}",
            result.err()
        );
    }
}

#[test]
fn test_verification_key_rejected_without_asymmetric_signing() {
    // On a non-signing suite the verification key is rejected by the
    // "must not be present" check; the suite has no expected length, so
    // the actual byte count doesn't matter. Use a minimally-sized VK so
    // the fixture doesn't imply any length-check interaction.
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let vk = VerificationKey::new(vec![0x04; 4]);

    let result = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .verification_key(vk)
        .build();
    let err = result.expect_err("expected rejection of verification key on non-signing suite");
    assert_eq!(err.kind(), ErrorKind::InvalidMaterials);
}

#[test]
fn test_validate_aws_crypto_public_key_happy_path() {
    let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let vk = p384_verification_key();

    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .verification_key(vk)
        .build()
        .unwrap();
    assert!(mat.validate_aws_crypto_public_key().is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_should_not_include_without_verification() {
    let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
    let reck = BTreeSet::new();

    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .build()
        .unwrap();
    assert_eq!(
        mat.validate_aws_crypto_public_key().unwrap_err().kind(),
        ErrorKind::InvalidMaterials
    );
}

#[test]
fn test_plaintext_data_key_immutability_decryption() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"secret".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    // No symmetric_signing_key under ESDK suites.
    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .plaintext_data_key(pdk)
        .build()
        .unwrap();
    let pdk_ref = mat.plaintext_data_key().unwrap();
    assert_eq!(pdk_ref.as_bytes(), b"secret");
}

#[test]
fn test_plaintext_data_key_zeroize_decryption() {
    let mut pdk = PlaintextDataKey::new(b"secret-dec".to_vec());
    pdk.zeroize();
    assert!(pdk.as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn test_symmetric_signing_key_debug_redacted_dec() {
    let ssk = SymmetricSigningKey::new(b"sym-secret-key".to_vec());
    let debug_output = format!("{:?}", ssk);
    assert!(!debug_output.contains("sym-secret-key"));
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_field_getters_return_constructed_values() {
    let ec = make_ec_with_keys(&["k1", "aws-crypto-public-key"]);
    let reck = BTreeSet::from(["k1".to_string()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = p384_verification_key();

    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .encryption_context(ec.clone())
        .required_encryption_context_keys(reck.clone())
        .plaintext_data_key(pdk)
        .verification_key(vk)
        .build()
        .unwrap();

    assert_eq!(mat.algorithm_suite_id(), SIGN_SUITE);
    assert_eq!(*mat.encryption_context(), ec);
    assert_eq!(*mat.required_encryption_context_keys(), reck);

    assert_eq!(mat.verification_key().unwrap().len(), 49);
    assert!(mat.symmetric_signing_key().is_none());
}

#[test]
fn test_field_getters_return_none_for_omitted_optional_fields() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .build()
        .unwrap();

    assert!(mat.plaintext_data_key().is_none());
    assert!(mat.verification_key().is_none());
    assert!(mat.symmetric_signing_key().is_none());
}

#[test]
fn test_debug_format_includes_all_fields() {
    let ec = make_ec_with_keys(&["k1", "aws-crypto-public-key"]);
    let reck = BTreeSet::from(["k1".to_string()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = p384_verification_key();

    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .plaintext_data_key(pdk)
        .verification_key(vk)
        .build()
        .unwrap();
    let debug = format!("{:?}", mat);

    assert!(debug.contains("DecryptionMaterials"));
    assert!(debug.contains("algorithm_suite_id"));
    assert!(debug.contains("encryption_context"));
    assert!(debug.contains("required_encryption_context_keys"));
    assert!(debug.contains("plaintext_data_key"));
    assert!(debug.contains("verification_key"));
    assert!(debug.contains("symmetric_signing_key"));
}

#[test]
fn test_validate_aws_crypto_public_key_should_include_with_verification() {
    // EC does NOT contain aws-crypto-public-key, but verification key IS present
    let ec = make_ec_with_keys(&["other-key"]);
    let reck = BTreeSet::new();
    let vk = p384_verification_key();

    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .encryption_context(ec)
        .required_encryption_context_keys(reck)
        .verification_key(vk)
        .build()
        .unwrap();
    let err = mat.validate_aws_crypto_public_key().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidMaterials);
}

#[test]
fn test_algorithm_suite_accessor_returns_matching_specification() {
    // The accessor returns the FULL specification struct (11 fields), not
    // just the ID. Compare the whole struct against `id.specification()` for
    // both a non-signing and a signing suite so drift on any field (kdf,
    // signature alg, commit_kdf, message_format_version, suite_data_length,
    // …) surfaces as a test failure.
    for suite_id in [NO_SIGN_SUITE, SIGN_SUITE] {
        let ec = EncryptionContext::new();
        let reck = BTreeSet::new();
        let vk = if suite_id == SIGN_SUITE {
            Some(p384_verification_key())
        } else {
            None
        };
        let mat = DecryptionMaterials::builder()
            .algorithm_suite_id(suite_id)
            .encryption_context(ec)
            .required_encryption_context_keys(reck)
            .set_verification_key(vk)
            .build()
            .unwrap();
        assert_eq!(
            mat.algorithm_suite(),
            suite_id.specification(),
            "{:?}: algorithm_suite() must equal id.specification()",
            suite_id
        );
    }
}

#[test]
fn test_builder_requires_algorithm_suite() {
    let err = DecryptionMaterials::builder().build().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Validation);
}

#[test]
fn test_add_data_key_sets_key() {
    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .build()
        .unwrap()
        .add_data_key(PlaintextDataKey::new(vec![7; 32]))
        .unwrap();
    assert_eq!(mat.plaintext_data_key().unwrap().as_bytes(), [7; 32]);
}

#[test]
fn test_add_data_key_rejects_existing_key() {
    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .plaintext_data_key(PlaintextDataKey::new(vec![7; 32]))
        .build()
        .unwrap();
    let err = mat
        .add_data_key(PlaintextDataKey::new(vec![8; 32]))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidMaterials);
}

#[test]
fn test_add_data_key_rejects_wrong_length() {
    let mat = DecryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .build()
        .unwrap();
    let err = mat
        .add_data_key(PlaintextDataKey::new(vec![7; 16]))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidMaterials);
}
