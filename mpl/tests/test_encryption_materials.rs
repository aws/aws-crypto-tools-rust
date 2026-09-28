// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use aws_crypto_mpl::structures::{
    EncryptedDataKey, EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId,
    PlaintextDataKey, SigningKey, SymmetricSigningKey,
};

// Standard ESDK suite IDs used throughout these tests:
// - NO_KDF non-signing (00 78): non-signing baseline.
// - HKDF-SHA256 + ECDSA-P256 (02 14): 32-byte signing key, 33-byte verify key.
// - HKDF-SHA384 + ECDSA-P384 (03 78): 48-byte signing key, 49-byte verify key.
const NO_SIGN_SUITE: EsdkAlgorithmSuiteId = EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf;
const P256_SIGN_SUITE: EsdkAlgorithmSuiteId =
    EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256;
const SIGN_SUITE: EsdkAlgorithmSuiteId =
    EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384;

fn make_ec_with_keys(keys: &[&str]) -> EncryptionContext {
    keys.iter().map(|&k| (k, "val")).collect()
}

fn make_edk() -> EncryptedDataKey {
    EncryptedDataKey::new("p".to_string(), b"i".to_vec(), b"c".to_vec())
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
    let reck = BTreeSet::new();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = EncryptionMaterials::new(NO_SIGN_SUITE.into(), vec![], ec, reck, None, None, None);
    assert!(result.is_ok());
}

#[test]
fn test_valid_construction_with_all_optional_fields() {
    let ec = make_ec_with_keys(&["k1", "aws-crypto-public-key"]);
    let reck = BTreeSet::from(["k1".to_string()]);
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    // ESDK signing suite: asymmetric signing only (no symmetric_signing_keys).
    let result = EncryptionMaterials::new(
        SIGN_SUITE.into(),
        vec![edk],
        ec,
        reck,
        Some(pdk),
        Some(sk),
        None,
    );
    assert!(result.is_ok());
}

#[test]
fn test_required_ec_keys_must_be_subset() {
    let ec = make_ec_with_keys(&["existing"]);
    let reck = BTreeSet::from(["missing".to_string()]);

    let result = EncryptionMaterials::new(NO_SIGN_SUITE.into(), vec![], ec, reck, None, None, None);
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

    let result =
        EncryptionMaterials::new(NO_SIGN_SUITE.into(), vec![edk], ec, reck, None, None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("must be empty"));
}

#[test]
fn test_signing_key_rejected_without_asymmetric_signing() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let sk = SigningKey::new(b"sign".to_vec());

    let result =
        EncryptionMaterials::new(NO_SIGN_SUITE.into(), vec![], ec, reck, None, Some(sk), None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Signing key must not be present")
    );
}

#[test]
fn test_signing_key_accepted_regardless_of_length() {
    // The spec constrains the signing key's presence and the algorithm it must
    // suit, not its byte length (`structures.md#signing-key`), and the Dafny
    // MPL likewise checks presence only. So a signing suite accepts a signing
    // key of any length: the raw-scalar sizes below, and the DER lengths that
    // `aws-mpl-primitives` actually emits (121 bytes for P-256, 167 for P-384)
    // and that `ecdsa_sign_digest` requires.
    let cases: [(EsdkAlgorithmSuiteId, SigningKey); 4] = [
        (P256_SIGN_SUITE, p256_signing_key()),
        (SIGN_SUITE, p384_signing_key()),
        (P256_SIGN_SUITE, SigningKey::new(vec![0u8; 121])),
        (SIGN_SUITE, SigningKey::new(vec![0u8; 167])),
    ];
    for (suite_id, sk) in cases {
        let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
        let reck = BTreeSet::new();
        let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
        let edk = make_edk();

        let result = EncryptionMaterials::new(
            suite_id.into(),
            vec![edk],
            ec,
            reck,
            Some(pdk),
            Some(sk),
            None,
        );
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
    let reck = BTreeSet::new();
    let ssk = vec![SymmetricSigningKey::new(b"sym".to_vec())];
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let edk = make_edk();

    let result = EncryptionMaterials::new(
        NO_SIGN_SUITE.into(),
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
    let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::new(
        SIGN_SUITE.into(),
        vec![edk],
        ec,
        reck,
        Some(pdk),
        Some(sk),
        None,
    )
    .unwrap();
    assert!(mat.validate_aws_crypto_public_key().is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_should_not_include_without_signing() {
    let ec = make_ec_with_keys(&["aws-crypto-public-key"]);
    let reck = BTreeSet::new();

    let mat =
        EncryptionMaterials::new(NO_SIGN_SUITE.into(), vec![], ec, reck, None, None, None).unwrap();
    assert!(
        mat.validate_aws_crypto_public_key()
            .unwrap_err()
            .to_string()
            .contains("MUST NOT include")
    );
}

#[test]
fn test_plaintext_data_key_immutability() {
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"secret".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat = EncryptionMaterials::new(
        NO_SIGN_SUITE.into(),
        vec![],
        ec,
        reck,
        Some(pdk),
        None,
        None,
    )
    .unwrap();
    let pdk_ref = mat.plaintext_data_key().unwrap();
    assert_eq!(pdk_ref.as_bytes(), b"secret");
}

#[test]
fn test_plaintext_data_key_zeroize() {
    let mut pdk = PlaintextDataKey::new(b"secret".to_vec());
    pdk.zeroize();
    assert!(pdk.as_bytes().iter().all(|&b| b == 0));
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
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::new(
        SIGN_SUITE.into(),
        vec![edk],
        ec.clone(),
        reck.clone(),
        Some(pdk),
        Some(sk),
        None,
    )
    .unwrap();

    assert_eq!(mat.algorithm_suite_id(), SIGN_SUITE.into());
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

    let mat =
        EncryptionMaterials::new(NO_SIGN_SUITE.into(), vec![], ec, reck, None, None, None).unwrap();

    assert!(mat.plaintext_data_key().is_none());
    assert!(mat.signing_key().is_none());
    assert!(mat.symmetric_signing_keys().is_none());
}

#[test]
fn test_debug_format_includes_all_fields() {
    let ec = make_ec_with_keys(&["k1", "aws-crypto-public-key"]);
    let reck = BTreeSet::from(["k1".to_string()]);
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::new(
        SIGN_SUITE.into(),
        vec![edk],
        ec,
        reck,
        Some(pdk),
        Some(sk),
        None,
    )
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
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let sk = p384_signing_key();
    let edk = make_edk();

    let mat = EncryptionMaterials::new(
        SIGN_SUITE.into(),
        vec![edk],
        ec,
        reck,
        Some(pdk),
        Some(sk),
        None,
    )
    .unwrap();
    let err = mat.validate_aws_crypto_public_key().unwrap_err();
    assert!(err.to_string().contains("MUST include"));
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
        let reck = BTreeSet::new();
        let (sk, edks) = if suite_id == SIGN_SUITE {
            (Some(p384_signing_key()), vec![])
        } else {
            (None, vec![])
        };
        let mat =
            EncryptionMaterials::new(suite_id.into(), edks, ec, reck, None, sk, None).unwrap();
        assert_eq!(
            mat.algorithm_suite(),
            suite_id.specification(),
            "{:?}: algorithm_suite() must equal id.specification()",
            suite_id
        );
    }
}
