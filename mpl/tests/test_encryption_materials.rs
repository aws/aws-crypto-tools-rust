// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, EncryptedDataKey, EncryptionContext, EncryptionMaterials,
    EsdkAlgorithmSuiteId, PlaintextDataKey, SigningKey, SymmetricSigningKey,
};

// Standard ESDK suite IDs used throughout these tests:
// - NO_KDF non-signing (00 78): non-signing baseline.
// - HKDF-SHA256 + ECDSA-P256 (02 14): 32-byte signing key, 33-byte verify key.
// - HKDF-SHA384 + ECDSA-P384 (03 78): 48-byte signing key, 49-byte verify key.
const NO_SIGN_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
const P256_SIGN_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256);
const SIGN_SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384);

fn make_ec_with_keys(keys: &[&str]) -> EncryptionContext {
    keys.iter().map(|&k| (k, "val")).collect()
}

fn make_edk() -> EncryptedDataKey {
    edk_with_ciphertext(b"c")
}

fn edk_with_ciphertext(ciphertext: &[u8]) -> EncryptedDataKey {
    EncryptedDataKey::builder()
        .key_provider_id("p")
        .key_provider_info(b"i")
        .ciphertext(ciphertext)
        .build()
        .unwrap()
}

// A plaintext data key of the length NO_SIGN_SUITE and SIGN_SUITE require.
fn pdk_32() -> PlaintextDataKey {
    PlaintextDataKey::new(vec![0x5a; 32])
}

// A correctly-sized P-256 signing key (private scalar): 32 bytes.
fn p256_signing_key() -> SigningKey {
    SigningKey::new(vec![0x42; 32])
}

// A correctly-sized P-384 signing key (private scalar): 48 bytes.
fn p384_signing_key() -> SigningKey {
    SigningKey::new(vec![0x42; 48])
}

#[test]
fn test_valid_construction_minimal() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::<String>::new();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .build();
    assert!(result.is_ok());
}

#[test]
fn test_valid_construction_with_all_optional_fields() {
    let ec = make_ec_with_keys(&["k1", "aws-crypto-public-key"]);
    let reck = BTreeSet::from(["k1".to_string()]);
    let pdk = pdk_32();
    let sk = p384_signing_key();
    let edk = make_edk();

    // ESDK signing suite: asymmetric signing only (no symmetric_signing_keys).
    let result = EncryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .set_encrypted_data_keys(Some(vec![edk]))
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .plaintext_data_key(pdk)
        .signing_key(sk)
        .build();
    assert!(result.is_ok());
}

#[test]
fn test_required_ec_keys_must_be_subset() {
    let ec = make_ec_with_keys(&["existing"]);
    let reck = BTreeSet::from(["missing".to_string()]);

    let result = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .build();
    assert!(result.is_err());
    assert!(result.unwrap_err().is_encryption_context_mismatch());
}

#[test]
fn test_edks_must_be_empty_without_pdk() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::<String>::new();
    let edk = make_edk();

    let result = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .set_encrypted_data_keys(Some(vec![edk]))
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .build();
    assert!(result.is_err());
    assert!(result.unwrap_err().is_invalid_materials());
}

#[test]
fn test_signing_key_rejected_without_asymmetric_signing() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::<String>::new();
    let sk = SigningKey::new(b"sign".to_vec());

    let result = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .signing_key(sk)
        .build();
    assert!(result.is_err());
    assert!(result.unwrap_err().is_invalid_materials());
}

#[test]
fn test_signing_key_accepted_regardless_of_length() {
    // The spec constrains the signing key's presence and the algorithm it must
    // suit, not its byte length (`structures.md#signing-key`), and the Dafny
    // MPL likewise checks presence only. So a signing suite accepts a signing
    // key of any length: the raw-scalar sizes below, and the DER lengths that
    // `aws-mpl-primitives` actually emits (121 bytes for P-256, 167 for P-384)
    // and that `ecdsa_sign_digest` requires.
    let cases: [(AlgorithmSuiteId, SigningKey); 4] = [
        (P256_SIGN_SUITE, p256_signing_key()),
        (SIGN_SUITE, p384_signing_key()),
        (P256_SIGN_SUITE, SigningKey::new(vec![0u8; 121])),
        (SIGN_SUITE, SigningKey::new(vec![0u8; 167])),
    ];
    for (suite_id, sk) in cases {
        let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
        let reck = BTreeSet::<String>::new();
        let pdk =
            PlaintextDataKey::new(vec![0x5a; suite_id.specification().encryption_key_length()]);
        let edk = make_edk();

        let result = EncryptionMaterials::builder()
            .algorithm_suite_id(suite_id)
            .set_encrypted_data_keys(Some(vec![edk]))
            .set_encryption_context(Some(ec))
            .set_required_encryption_context_keys(Some(reck))
            .plaintext_data_key(pdk)
            .signing_key(sk)
            .build();
        assert!(
            result.is_ok(),
            "{suite_id:?} signing key must be accepted: {:?}",
            result.err()
        );
    }
}

#[test]
fn test_symmetric_keys_rejected_without_symmetric_signing() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::<String>::new();
    let ssk = vec![SymmetricSigningKey::new(b"sym".to_vec())];
    let pdk = pdk_32();
    let edk = make_edk();

    let result = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .set_encrypted_data_keys(Some(vec![edk]))
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .plaintext_data_key(pdk)
        .set_symmetric_signing_keys(Some(ssk))
        .build();
    assert!(result.is_err());
    assert!(result.unwrap_err().is_invalid_materials());
}

#[test]
fn test_validate_aws_crypto_public_key_happy_path() {
    let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
    let reck = BTreeSet::<String>::new();
    let pdk = pdk_32();
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .set_encrypted_data_keys(Some(vec![edk]))
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .plaintext_data_key(pdk)
        .signing_key(sk)
        .build()
        .unwrap();
    assert!(mat.validate_aws_crypto_public_key().is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_should_not_include_without_signing() {
    let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
    let reck = BTreeSet::<String>::new();

    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .build()
        .unwrap();
    assert!(
        mat.validate_aws_crypto_public_key()
            .unwrap_err()
            .is_invalid_materials()
    );
}

#[test]
fn test_plaintext_data_key_immutability() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::<String>::new();
    let pdk = pdk_32();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .plaintext_data_key(pdk)
        .build()
        .unwrap();
    let pdk_ref = mat.plaintext_data_key().unwrap();
    assert_eq!(pdk_ref.as_bytes(), [0x5a; 32]);
}

#[test]
fn test_plaintext_data_key_zeroize() {
    use zeroize::Zeroize;
    let mut pdk = PlaintextDataKey::new(b"secret".to_vec());
    pdk.zeroize();
    assert!(pdk.is_empty());
}

#[test]
fn test_signing_key_debug_redacted() {
    let sk = SigningKey::new(b"my-secret-key".to_vec());
    let debug_output = format!("{:?}", sk);
    assert!(!debug_output.contains("my-secret-key"));
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_symmetric_signing_key_debug_redacted() {
    let ssk = SymmetricSigningKey::new(b"symmetric-secret".to_vec());
    let debug_output = format!("{:?}", ssk);
    assert!(!debug_output.contains("symmetric-secret"));
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_field_getters_return_constructed_values() {
    let ec = make_ec_with_keys(&["k1", "aws-crypto-public-key"]);
    let reck = BTreeSet::from(["k1".to_string()]);
    let pdk = pdk_32();
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .set_encrypted_data_keys(Some(vec![edk]))
        .set_encryption_context(Some(ec.clone()))
        .set_required_encryption_context_keys(Some(reck.clone()))
        .plaintext_data_key(pdk)
        .signing_key(sk)
        .build()
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
    let reck = BTreeSet::<String>::new();

    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .build()
        .unwrap();

    assert!(mat.plaintext_data_key().is_none());
    assert!(mat.signing_key().is_none());
    assert!(mat.symmetric_signing_keys().is_none());
}

#[test]
fn test_debug_format_includes_all_fields() {
    let ec = make_ec_with_keys(&["k1", "aws-crypto-public-key"]);
    let reck = BTreeSet::from(["k1".to_string()]);
    let pdk = pdk_32();
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .set_encrypted_data_keys(Some(vec![edk]))
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .plaintext_data_key(pdk)
        .signing_key(sk)
        .build()
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
    let ec = make_ec_with_keys(&["other-key"]);
    let reck = BTreeSet::<String>::new();
    let pdk = pdk_32();
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(SIGN_SUITE)
        .set_encrypted_data_keys(Some(vec![edk]))
        .set_encryption_context(Some(ec))
        .set_required_encryption_context_keys(Some(reck))
        .plaintext_data_key(pdk)
        .signing_key(sk)
        .build()
        .unwrap();
    let err = mat.validate_aws_crypto_public_key().unwrap_err();
    assert!(err.is_invalid_materials(), "{:?}", err);
}

#[test]
fn test_algorithm_suite_accessor_returns_matching_specification() {
    // The accessor returns the FULL specification struct (11 fields), not
    // just the ID. Compare the whole struct against `id.specification()` for
    // both a non-signing and a signing suite so drift on any field (kdf,
    // signature alg, commit_kdf, message_format_version, suite_data_length,
    // …) surfaces as a test failure. Comparing only `.id()` would let e.g.
    // a wrong `commit_kdf` pass silently.
    for suite_id in [NO_SIGN_SUITE, SIGN_SUITE] {
        let ec = EncryptionContext::new();
        let reck = BTreeSet::<String>::new();
        let (sk, edks) = if suite_id == SIGN_SUITE {
            (Some(p384_signing_key()), vec![])
        } else {
            (None, vec![])
        };
        let mat = EncryptionMaterials::builder()
            .algorithm_suite_id(suite_id)
            .set_encrypted_data_keys(Some(edks))
            .set_encryption_context(Some(ec))
            .set_required_encryption_context_keys(Some(reck))
            .set_signing_key(sk)
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
    let err = EncryptionMaterials::builder().build().unwrap_err();
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn test_add_data_key_sets_key_and_appends_edk() {
    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .build()
        .unwrap()
        .add_data_key(PlaintextDataKey::new(vec![7; 32]), make_edk())
        .unwrap();
    assert_eq!(mat.plaintext_data_key().unwrap().as_bytes(), [7; 32]);
    assert_eq!(mat.encrypted_data_keys(), [make_edk()]);
}

#[test]
fn test_add_data_key_rejects_existing_key() {
    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .plaintext_data_key(PlaintextDataKey::new(vec![7; 32]))
        .build()
        .unwrap();
    let err = mat
        .add_data_key(PlaintextDataKey::new(vec![8; 32]), make_edk())
        .unwrap_err();
    assert!(err.is_invalid_materials(), "{:?}", err);
}

#[test]
fn test_add_data_key_rejects_wrong_length() {
    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .build()
        .unwrap();
    let err = mat
        .add_data_key(PlaintextDataKey::new(vec![7; 16]), make_edk())
        .unwrap_err();
    assert!(err.is_invalid_materials(), "{:?}", err);
}

#[test]
fn test_add_encrypted_data_key_appends() {
    let first = edk_with_ciphertext(b"first");
    let second = edk_with_ciphertext(b"second");
    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .build()
        .unwrap()
        .add_data_key(PlaintextDataKey::new(vec![7; 32]), first.clone())
        .unwrap()
        .add_encrypted_data_key(second.clone())
        .unwrap();
    assert_eq!(mat.encrypted_data_keys(), [first, second]);
}

#[test]
fn test_build_rejects_wrong_length_plaintext_data_key() {
    let err = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .plaintext_data_key(PlaintextDataKey::new(vec![7; 16]))
        .build()
        .unwrap_err();
    assert!(err.is_invalid_materials(), "{:?}", err);
}

#[test]
fn test_add_encrypted_data_key_requires_plaintext_data_key() {
    let mat = EncryptionMaterials::builder()
        .algorithm_suite_id(NO_SIGN_SUITE)
        .build()
        .unwrap();
    let err = mat.add_encrypted_data_key(make_edk()).unwrap_err();
    assert!(err.is_invalid_materials(), "{:?}", err);
}
