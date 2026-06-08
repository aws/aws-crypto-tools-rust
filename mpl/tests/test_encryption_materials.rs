// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, EncryptedDataKey, EncryptionContext, EncryptionMaterials, PlaintextDataKey,
    SigningKey, SymmetricSigningKey,
};

// Standard ESDK suite IDs used throughout the migrated tests:
// - NO_KDF non-signing (00 78): for `(false, false)` legacy cases.
// - HKDF-SHA384 + ECDSA-P384 (03 78): for `(true, false)` legacy cases.
const NO_SIGN_SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf;
const SIGN_SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384;

fn make_ec_with_keys(keys: &[&[u8]]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for k in keys {
        ec.insert(k.to_vec(), b"val".to_vec());
    }
    ec
}

fn make_edk() -> EncryptedDataKey {
    EncryptedDataKey::new("p".to_string(), b"i".to_vec(), b"c".to_vec())
}

// A correctly-sized P-384 signing key (private scalar): 48 bytes.
fn p384_signing_key() -> SigningKey {
    SigningKey::new(vec![0x42; 48])
}

#[test]
fn test_valid_construction_minimal() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = EncryptionMaterials::new(NO_SIGN_SUITE, vec![], ec, reck, None, None, None);
    assert!(result.is_ok());
}

#[test]
fn test_valid_construction_with_all_optional_fields() {
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    // ESDK signing suite: asymmetric signing only (no symmetric_signing_keys).
    let result =
        EncryptionMaterials::new(SIGN_SUITE, vec![edk], ec, reck, Some(pdk), Some(sk), None);
    assert!(result.is_ok());
}

#[test]
fn test_required_ec_keys_must_be_subset() {
    let ec = make_ec_with_keys(&[b"existing"]);
    let reck = BTreeSet::from([b"missing".to_vec()]);

    //= ../spec/framework/structures.md#required-encryption-context-keys
    //= type=test
    //# Every key in Required Encryption Context Keys
    //# MUST be a key in the [encryption context](#encryption-context-1).
    let result = EncryptionMaterials::new(NO_SIGN_SUITE, vec![], ec, reck, None, None, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("not found in encryption context")
    );
}

#[test]
fn test_edks_must_be_empty_without_pdk() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let edk = make_edk();

    //= ../spec/framework/structures.md#encrypted-data-keys
    //= type=test
    //# If the plaintext data key is not included in this set of encryption materials, this list MUST be empty.
    let result = EncryptionMaterials::new(NO_SIGN_SUITE, vec![edk], ec, reck, None, None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("must be empty"));
}

#[test]
fn test_signing_key_rejected_without_asymmetric_signing() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let sk = SigningKey::new(b"sign".to_vec());

    //= ../spec/framework/structures.md#signing-key
    //= type=test
    //# If the algorithm suite does not contain an asymmetric signing algorithm, the signing key MUST NOT be present.
    //
    //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
    //= type=test
    //# - Asymmetric signatures MUST NOT be generated.
    let result = EncryptionMaterials::new(NO_SIGN_SUITE, vec![], ec, reck, None, Some(sk), None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Signing key must not be present")
    );
}

#[test]
fn test_signing_key_length_must_match_algorithm_suite() {
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    // 16 bytes is wrong for P-384 (which expects 48 bytes).
    let bad_sk = SigningKey::new(vec![0u8; 16]);
    let edk = make_edk();

    //= ../spec/framework/structures.md#signing-key
    //= type=test
    //# The signing key MUST fit the specification described by the [asymmetric signature algorithm](algorithm-suites.md#asymmetric-signature-algorithm)
    //# included in this encryption material's [algorithm suite](#algorithm-suite).
    let result = EncryptionMaterials::new(
        SIGN_SUITE,
        vec![edk],
        ec,
        reck,
        Some(pdk),
        Some(bad_sk),
        None,
    );
    let err = result.expect_err("expected signing-key length mismatch error");
    assert!(
        err.message.contains("Signing key length"),
        "unexpected error message: {}",
        err.message
    );
}

#[test]
fn test_signing_key_correct_length_succeeds() {
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = p384_signing_key(); // 48 bytes — correct for P-384
    let edk = make_edk();

    let result =
        EncryptionMaterials::new(SIGN_SUITE, vec![edk], ec, reck, Some(pdk), Some(sk), None);
    assert!(result.is_ok());
}

#[test]
fn test_symmetric_keys_rejected_without_symmetric_signing() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let ssk = vec![SymmetricSigningKey::new(b"sym".to_vec())];
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let edk = make_edk();

    //= ../spec/framework/structures.md#symmetric-signing-keys
    //= type=test
    //# If the algorithm suite does not contain a symmetric signing algorithm, this list MUST NOT be included in the materials.
    //
    //= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
    //= type=test
    //# - Symmetric signatures MUST NOT be generated.
    let result = EncryptionMaterials::new(
        NO_SIGN_SUITE,
        vec![edk],
        ec,
        reck,
        Some(pdk),
        None,
        Some(ssk),
    );
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Symmetric signing keys must not be present")
    );
}

#[test]
fn test_validate_aws_crypto_public_key_happy_path() {
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    //= ../spec/framework/structures.md#encryption-context-1
    //= type=test
    //# If an [encryption material](#encryption-materials) contains a [signing key](#signing-key),
    //# the [encryption context](#encryption-context) SHOULD include the reserved key `aws-crypto-public-key`.
    let mat = EncryptionMaterials::new(SIGN_SUITE, vec![edk], ec, reck, Some(pdk), Some(sk), None)
        .unwrap();
    assert!(mat.validate_aws_crypto_public_key().is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_should_not_include_without_signing() {
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();

    //= ../spec/framework/structures.md#encryption-context-1
    //= type=test
    //# If an [encryption material](#encryption-materials) does not contains a [signing key](#signing-key),
    //# the [encryption context](#encryption-context) SHOULD NOT include the reserved key `aws-crypto-public-key`.
    let mat = EncryptionMaterials::new(NO_SIGN_SUITE, vec![], ec, reck, None, None, None).unwrap();
    assert!(
        mat.validate_aws_crypto_public_key()
            .unwrap_err()
            .to_string()
            .contains("SHOULD NOT include")
    );
}

#[test]
fn test_plaintext_data_key_immutability() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"secret".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat =
        EncryptionMaterials::new(NO_SIGN_SUITE, vec![], ec, reck, Some(pdk), None, None).unwrap();
    let pdk_ref = mat.plaintext_data_key().unwrap();
    assert_eq!(pdk_ref.as_bytes(), b"secret");
}

#[test]
fn test_plaintext_data_key_zeroize() {
    //= ../spec/framework/structures.md#plaintext-data-key
    //= type=test
    //# The plaintext data key SHOULD offer an interface to zero the plaintext data key.
    let mut pdk = PlaintextDataKey::new(b"secret".to_vec());
    pdk.zeroize();
    assert!(pdk.as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn test_signing_key_debug_redacted() {
    //= ../spec/framework/structures.md#signing-key
    //= type=test
    //# The value of this key MUST be kept secret.
    let sk = SigningKey::new(b"my-secret-key".to_vec());
    let debug_output = format!("{:?}", sk);
    assert!(!debug_output.contains("my-secret-key"));
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_symmetric_signing_key_debug_redacted() {
    //= ../spec/framework/structures.md#symmetric-signing-keys
    //= type=test
    //# The value of keys in this list MUST be kept secret.
    let ssk = SymmetricSigningKey::new(b"symmetric-secret".to_vec());
    let debug_output = format!("{:?}", ssk);
    assert!(!debug_output.contains("symmetric-secret"));
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_field_getters_return_constructed_values() {
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::new(
        SIGN_SUITE,
        vec![edk],
        ec.clone(),
        reck.clone(),
        Some(pdk),
        Some(sk),
        None,
    )
    .unwrap();

    assert_eq!(mat.algorithm_suite_id(), SIGN_SUITE);
    assert_eq!(mat.encrypted_data_keys().len(), 1);
    assert_eq!(*mat.encryption_context(), ec);
    assert_eq!(*mat.required_encryption_context_keys(), reck);
    assert_eq!(mat.signing_key().unwrap().len(), 48);
    assert!(mat.symmetric_signing_keys().is_none());
}

#[test]
fn test_field_getters_return_none_for_omitted_optional_fields() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    let mat = EncryptionMaterials::new(NO_SIGN_SUITE, vec![], ec, reck, None, None, None).unwrap();

    assert!(mat.plaintext_data_key().is_none());
    assert!(mat.signing_key().is_none());
    assert!(mat.symmetric_signing_keys().is_none());
}

#[test]
fn test_debug_format_includes_all_fields() {
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::new(SIGN_SUITE, vec![edk], ec, reck, Some(pdk), Some(sk), None)
        .unwrap();

    let s = format!("{:?}", mat);
    assert!(s.contains("EncryptionMaterials"));
    assert!(s.contains("algorithm_suite_id"));
    assert!(s.contains("encrypted_data_keys"));
    assert!(s.contains("encryption_context"));
    assert!(s.contains("required_encryption_context_keys"));
    assert!(s.contains("plaintext_data_key"));
    assert!(s.contains("signing_key"));
    assert!(s.contains("symmetric_signing_keys"));
}

#[test]
fn test_validate_aws_crypto_public_key_should_include_with_signing() {
    let ec = make_ec_with_keys(&[b"other-key"]);
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::new(SIGN_SUITE, vec![edk], ec, reck, Some(pdk), Some(sk), None)
        .unwrap();
    let err = mat.validate_aws_crypto_public_key().unwrap_err();
    assert!(err.to_string().contains("SHOULD include"));
}

#[test]
fn test_algorithm_suite_accessor_returns_matching_specification() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    let mat = EncryptionMaterials::new(NO_SIGN_SUITE, vec![], ec, reck, None, None, None).unwrap();
    let suite = mat.algorithm_suite();
    assert_eq!(suite.id(), NO_SIGN_SUITE.id_bytes());
}
