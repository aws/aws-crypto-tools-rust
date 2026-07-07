// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use aws_crypto_mpl::structures::{
    AlgorithmSuite, EncryptedDataKey, EncryptionContext, EncryptionMaterials, PlaintextDataKey,
    SigningKey, SymmetricSigningKey,
};

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

#[test]
fn test_valid_construction_minimal() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = EncryptionMaterials::new(suite, vec![], ec, reck, None, None, None);
    assert!(result.is_ok());
}

#[test]
fn test_valid_construction_with_all_optional_fields() {
    let suite = AlgorithmSuite::new(true, true);
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = SigningKey::new(b"sign".to_vec());
    let ssk = vec![SymmetricSigningKey::new(b"sym".to_vec())];
    let edk = make_edk();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result =
        EncryptionMaterials::new(suite, vec![edk], ec, reck, Some(pdk), Some(sk), Some(ssk));
    assert!(result.is_ok());
}

#[test]
fn test_required_ec_keys_must_be_subset() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = make_ec_with_keys(&[b"existing"]);
    let reck = BTreeSet::from([b"missing".to_vec()]);

    let result = EncryptionMaterials::new(suite, vec![], ec, reck, None, None, None);
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
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let edk = make_edk();

    let result = EncryptionMaterials::new(suite, vec![edk], ec, reck, None, None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("must be empty"));
}

#[test]
fn test_signing_key_rejected_without_asymmetric_signing() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let sk = SigningKey::new(b"sign".to_vec());

    let result = EncryptionMaterials::new(suite, vec![], ec, reck, None, Some(sk), None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Signing key must not be present")
    );
}

#[test]
fn test_symmetric_keys_rejected_without_symmetric_signing() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let ssk = vec![SymmetricSigningKey::new(b"sym".to_vec())];
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let edk = make_edk();

    let result = EncryptionMaterials::new(suite, vec![edk], ec, reck, Some(pdk), None, Some(ssk));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Symmetric signing keys must not be present")
    );
}

#[test]
fn test_symmetric_keys_length_must_match_edks() {
    let suite = AlgorithmSuite::new(false, true);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let edk1 = make_edk();
    let edk2 = make_edk();
    // Only 1 symmetric key but 2 EDKs
    let ssk = vec![SymmetricSigningKey::new(b"sym".to_vec())];

    let result = EncryptionMaterials::new(
        suite,
        vec![edk1, edk2],
        ec,
        reck,
        Some(pdk),
        None,
        Some(ssk),
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("length"));
}

#[test]
fn test_symmetric_keys_required_when_edks_present() {
    // Companion to test_symmetric_keys_length_must_match_edks: covers the
    // None-side of the invariant. When the suite has symmetric signing AND
    // the EDK list is non-empty, the symmetric_signing_keys list MUST be
    // present (it MAY be omitted only when EDKs are empty).
    let suite = AlgorithmSuite::new(false, true);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let edk = make_edk();

    let result = EncryptionMaterials::new(suite, vec![edk], ec, reck, Some(pdk), None, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Symmetric signing keys must be present")
    );
}

#[test]
fn test_symmetric_keys_may_be_omitted_when_edks_empty() {
    let suite = AlgorithmSuite::new(false, true);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    let result = EncryptionMaterials::new(suite, vec![], ec, reck, None, None, None);
    assert!(result.is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_happy_path() {
    let suite = AlgorithmSuite::new(true, false);
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let sk = SigningKey::new(b"sign".to_vec());
    let edk = make_edk();

    let mat =
        EncryptionMaterials::new(suite, vec![edk], ec, reck, Some(pdk), Some(sk), None).unwrap();
    assert!(mat.validate_aws_crypto_public_key().is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_should_not_include_without_signing() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();

    let mat = EncryptionMaterials::new(suite, vec![], ec, reck, None, None, None).unwrap();
    assert!(
        mat.validate_aws_crypto_public_key()
            .unwrap_err()
            .to_string()
            .contains("MUST NOT include")
    );
}

#[test]
fn test_plaintext_data_key_immutability() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"secret".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat = EncryptionMaterials::new(suite, vec![], ec, reck, Some(pdk), None, None).unwrap();
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
    let suite = AlgorithmSuite::new(true, true);
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = SigningKey::new(b"sign-bytes".to_vec());
    let ssk = vec![SymmetricSigningKey::new(b"sym-bytes".to_vec())];
    let edk = make_edk();

    let mat = EncryptionMaterials::new(
        suite,
        vec![edk],
        ec.clone(),
        reck.clone(),
        Some(pdk),
        Some(sk),
        Some(ssk),
    )
    .unwrap();

    assert_eq!(*mat.algorithm_suite(), suite);
    assert_eq!(mat.encrypted_data_keys().len(), 1);
    assert_eq!(*mat.encryption_context(), ec);
    assert_eq!(*mat.required_encryption_context_keys(), reck);
    assert_eq!(mat.signing_key().unwrap().as_bytes(), b"sign-bytes");
    assert_eq!(mat.symmetric_signing_keys().unwrap().len(), 1);
}

#[test]
fn test_field_getters_return_none_for_omitted_optional_fields() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    let mat = EncryptionMaterials::new(suite, vec![], ec, reck, None, None, None).unwrap();

    assert!(mat.plaintext_data_key().is_none());
    assert!(mat.signing_key().is_none());
    assert!(mat.symmetric_signing_keys().is_none());
}

#[test]
fn test_debug_format_includes_all_fields() {
    let suite = AlgorithmSuite::new(true, true);
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret-key".to_vec());
    let sk = SigningKey::new(b"sign-bytes".to_vec());
    let ssk = vec![SymmetricSigningKey::new(b"sym-bytes".to_vec())];
    let edk = make_edk();

    let mat = EncryptionMaterials::new(suite, vec![edk], ec, reck, Some(pdk), Some(sk), Some(ssk))
        .unwrap();

    let s = format!("{:?}", mat);
    assert!(s.contains("EncryptionMaterials"));
    assert!(s.contains("algorithm_suite"));
    assert!(s.contains("encrypted_data_keys"));
    assert!(s.contains("encryption_context"));
    assert!(s.contains("required_encryption_context_keys"));
    assert!(s.contains("plaintext_data_key"));
    assert!(s.contains("signing_key"));
    assert!(s.contains("symmetric_signing_keys"));
}

#[test]
fn test_validate_aws_crypto_public_key_should_include_with_signing() {
    let suite = AlgorithmSuite::new(true, false);
    let ec = make_ec_with_keys(&[b"other-key"]);
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());
    let sk = SigningKey::new(b"sign".to_vec());
    let edk = make_edk();

    let mat =
        EncryptionMaterials::new(suite, vec![edk], ec, reck, Some(pdk), Some(sk), None).unwrap();
    let err = mat.validate_aws_crypto_public_key().unwrap_err();
    assert!(err.to_string().contains("MUST include"));
}
