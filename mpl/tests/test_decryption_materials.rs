// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptionContext, PlaintextDataKey,
    SymmetricSigningKey, VerificationKey,
};

const NO_SIGN_SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf;
const SIGN_SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384;

fn make_ec_with_keys(keys: &[&[u8]]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for k in keys {
        ec.insert(k.to_vec(), b"val".to_vec());
    }
    ec
}

// SEC1 uncompressed P-384 verification key: 1 byte tag (0x04) + 96 bytes (X||Y) = 97 bytes.
fn p384_verification_key() -> VerificationKey {
    let mut bytes = vec![0u8; 97];
    bytes[0] = 0x04;
    VerificationKey::new(bytes)
}

#[test]
fn test_valid_construction_minimal() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = DecryptionMaterials::new(NO_SIGN_SUITE, ec, reck, None, None, None);
    assert!(result.is_ok());
}

#[test]
fn test_valid_construction_with_all_optional_fields() {
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = p384_verification_key();

    // ESDK signing suite: asymmetric only (no symmetric_signing_key).
    let result = DecryptionMaterials::new(SIGN_SUITE, ec, reck, Some(pdk), Some(vk), None);
    assert!(result.is_ok());
}

#[test]
fn test_required_ec_keys_must_be_subset() {
    let ec = make_ec_with_keys(&[b"existing"]);
    let reck = BTreeSet::from([b"missing".to_vec()]);

    let result = DecryptionMaterials::new(NO_SIGN_SUITE, ec, reck, None, None, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("not found in encryption context")
    );
}

#[test]
fn test_symmetric_key_rejected_without_symmetric_signing() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let ssk = SymmetricSigningKey::new(b"sym".to_vec());

    let result = DecryptionMaterials::new(NO_SIGN_SUITE, ec, reck, None, None, Some(ssk));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Symmetric signing key must not be present")
    );
}

#[test]
fn test_verification_key_length_must_match_algorithm_suite() {
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    // 32 bytes is wrong for P-384 (which expects 97 bytes).
    let bad_vk = VerificationKey::new(vec![0x04; 32]);

    let result = DecryptionMaterials::new(SIGN_SUITE, ec, reck, None, Some(bad_vk), None);
    let err = result.expect_err("expected verification-key length mismatch error");
    assert!(
        err.message.contains("Verification key length"),
        "unexpected error message: {}",
        err.message
    );
}

#[test]
fn test_verification_key_correct_length_succeeds() {
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let vk = p384_verification_key(); // 97 bytes — correct for P-384

    let result = DecryptionMaterials::new(SIGN_SUITE, ec, reck, None, Some(vk), None);
    assert!(result.is_ok());
}

#[test]
fn test_verification_key_rejected_without_asymmetric_signing() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let vk = VerificationKey::new(vec![0x04; 97]);

    let result = DecryptionMaterials::new(NO_SIGN_SUITE, ec, reck, None, Some(vk), None);
    let err = result.expect_err("expected rejection of verification key on non-signing suite");
    assert!(err.message.contains("Verification key must not be present"));
}

#[test]
fn test_validate_aws_crypto_public_key_happy_path() {
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let vk = p384_verification_key();

    let mat = DecryptionMaterials::new(SIGN_SUITE, ec, reck, None, Some(vk), None).unwrap();
    assert!(mat.validate_aws_crypto_public_key().is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_should_not_include_without_verification() {
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();

    let mat = DecryptionMaterials::new(NO_SIGN_SUITE, ec, reck, None, None, None).unwrap();
    assert!(
        mat.validate_aws_crypto_public_key()
            .unwrap_err()
            .to_string()
            .contains("MUST NOT include")
    );
}

#[test]
fn test_plaintext_data_key_immutability_decryption() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"secret".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    // No symmetric_signing_key under ESDK suites.
    let mat = DecryptionMaterials::new(NO_SIGN_SUITE, ec, reck, Some(pdk), None, None).unwrap();
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
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = p384_verification_key();

    let mat = DecryptionMaterials::new(
        SIGN_SUITE,
        ec.clone(),
        reck.clone(),
        Some(pdk),
        Some(vk),
        None,
    )
    .unwrap();

    assert_eq!(mat.algorithm_suite_id(), SIGN_SUITE);
    assert_eq!(*mat.encryption_context(), ec);
    assert_eq!(*mat.required_encryption_context_keys(), reck);

    assert_eq!(mat.verification_key().unwrap().len(), 97);
    assert!(mat.symmetric_signing_key().is_none());
}

#[test]
fn test_field_getters_return_none_for_omitted_optional_fields() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    let mat = DecryptionMaterials::new(NO_SIGN_SUITE, ec, reck, None, None, None).unwrap();

    assert!(mat.plaintext_data_key().is_none());
    assert!(mat.verification_key().is_none());
    assert!(mat.symmetric_signing_key().is_none());
}

#[test]
fn test_debug_format_includes_all_fields() {
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = p384_verification_key();

    let mat = DecryptionMaterials::new(SIGN_SUITE, ec, reck, Some(pdk), Some(vk), None).unwrap();
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
    let ec = make_ec_with_keys(&[b"other-key"]);
    let reck = BTreeSet::new();
    let vk = p384_verification_key();

    let mat = DecryptionMaterials::new(SIGN_SUITE, ec, reck, None, Some(vk), None).unwrap();
    let err = mat.validate_aws_crypto_public_key().unwrap_err();
    assert!(err.to_string().contains("MUST include"));
}

#[test]
fn test_algorithm_suite_accessor_returns_matching_specification() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    let mat = DecryptionMaterials::new(NO_SIGN_SUITE, ec, reck, None, None, None).unwrap();
    let suite = mat.algorithm_suite();
    assert_eq!(suite.id(), NO_SIGN_SUITE.id_bytes());
}
