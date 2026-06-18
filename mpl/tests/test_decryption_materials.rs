// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use aws_crypto_mpl::structures::{
    AlgorithmSuite, DecryptionMaterials, EncryptionContext, PlaintextDataKey, SymmetricSigningKey,
    VerificationKey,
};

fn make_ec_with_keys(keys: &[&[u8]]) -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    for k in keys {
        ec.insert(k.to_vec(), b"val".to_vec());
    }
    ec
}

#[test]
fn test_valid_construction_minimal() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = DecryptionMaterials::new(suite, ec, reck, None, None, None);
    assert!(result.is_ok());
}

#[test]
fn test_valid_construction_with_all_optional_fields() {
    let suite = AlgorithmSuite::new(true, true);
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = VerificationKey::new(b"verify".to_vec());
    let ssk = SymmetricSigningKey::new(b"sym".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = DecryptionMaterials::new(suite, ec, reck, Some(pdk), Some(vk), Some(ssk));
    assert!(result.is_ok());
}

#[test]
fn test_required_ec_keys_must_be_subset() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = make_ec_with_keys(&[b"existing"]);
    let reck = BTreeSet::from([b"missing".to_vec()]);

    let result = DecryptionMaterials::new(suite, ec, reck, None, None, None);
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
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let ssk = SymmetricSigningKey::new(b"sym".to_vec());

    let result = DecryptionMaterials::new(suite, ec, reck, None, None, Some(ssk));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Symmetric signing key must not be present")
    );
}

#[test]
fn test_verification_key_rejected_without_asymmetric_signing() {
    // Mirror of test_signing_key_rejected_without_asymmetric_signing in
    // test_encryption_materials.rs: a verification key on a non-signing suite
    // is internally inconsistent and MUST be rejected at construction.
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let vk = VerificationKey::new(b"verify".to_vec());

    let result = DecryptionMaterials::new(suite, ec, reck, None, Some(vk), None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .message
            .contains("Verification key must not be present")
    );
}

#[test]
fn test_symmetric_key_iff_plaintext_data_key() {
    let suite = AlgorithmSuite::new(false, true);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());

    // PDK present but no SSK → error
    let result = DecryptionMaterials::new(suite, ec.clone(), reck.clone(), Some(pdk), None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("if and only if"));

    // SSK present but no PDK → error
    let ssk = SymmetricSigningKey::new(b"sym".to_vec());
    let result = DecryptionMaterials::new(suite, ec, reck, None, None, Some(ssk));
    assert!(result.unwrap_err().to_string().contains("if and only if"));
}

#[test]
fn test_validate_aws_crypto_public_key_happy_path() {
    let suite = AlgorithmSuite::new(true, false);
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();
    let vk = VerificationKey::new(b"verify".to_vec());

    let mat = DecryptionMaterials::new(suite, ec, reck, None, Some(vk), None).unwrap();
    assert!(mat.validate_aws_crypto_public_key().is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_should_not_include_without_verification() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();

    let mat = DecryptionMaterials::new(suite, ec, reck, None, None, None).unwrap();
    assert!(
        mat.validate_aws_crypto_public_key()
            .unwrap_err()
            .to_string()
            .contains("SHOULD NOT include")
    );
}

#[test]
fn test_plaintext_data_key_immutability_decryption() {
    let suite = AlgorithmSuite::new(false, true);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let ssk = SymmetricSigningKey::new(b"sym".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat = DecryptionMaterials::new(suite, ec, reck, Some(pdk), None, Some(ssk)).unwrap();
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
    let suite = AlgorithmSuite::new(true, true);
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = VerificationKey::new(b"verify".to_vec());
    let ssk = SymmetricSigningKey::new(b"sym".to_vec());

    let mat = DecryptionMaterials::new(
        suite,
        ec.clone(),
        reck.clone(),
        Some(pdk),
        Some(vk),
        Some(ssk),
    )
    .unwrap();

    assert_eq!(*mat.algorithm_suite(), suite);
    assert_eq!(*mat.encryption_context(), ec);
    assert_eq!(*mat.required_encryption_context_keys(), reck);

    assert_eq!(mat.verification_key().unwrap().as_bytes(), b"verify");
    assert_eq!(mat.symmetric_signing_key().unwrap().as_bytes(), b"sym");
}

#[test]
fn test_field_getters_return_none_for_omitted_optional_fields() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();

    let mat = DecryptionMaterials::new(suite, ec, reck, None, None, None).unwrap();

    assert!(mat.plaintext_data_key().is_none());
    assert!(mat.verification_key().is_none());
    assert!(mat.symmetric_signing_key().is_none());
}

#[test]
fn test_debug_format_includes_all_fields() {
    let suite = AlgorithmSuite::new(true, true);
    let ec = make_ec_with_keys(&[b"k1", b"aws-crypto-public-key"]);
    let reck = BTreeSet::from([b"k1".to_vec()]);
    let pdk = PlaintextDataKey::new(b"secret".to_vec());
    let vk = VerificationKey::new(b"verify".to_vec());
    let ssk = SymmetricSigningKey::new(b"sym".to_vec());

    let mat = DecryptionMaterials::new(suite, ec, reck, Some(pdk), Some(vk), Some(ssk)).unwrap();
    let debug = format!("{:?}", mat);

    assert!(debug.contains("DecryptionMaterials"));
    assert!(debug.contains("algorithm_suite"));
    assert!(debug.contains("encryption_context"));
    assert!(debug.contains("required_encryption_context_keys"));
    assert!(debug.contains("plaintext_data_key"));
    assert!(debug.contains("verification_key"));
    assert!(debug.contains("symmetric_signing_key"));
}

#[test]
fn test_validate_aws_crypto_public_key_should_include_with_verification() {
    let suite = AlgorithmSuite::new(true, false);
    // EC does NOT contain aws-crypto-public-key, but verification key IS present
    let ec = make_ec_with_keys(&[b"other-key"]);
    let reck = BTreeSet::new();
    let vk = VerificationKey::new(b"verify".to_vec());

    let mat = DecryptionMaterials::new(suite, ec, reck, None, Some(vk), None).unwrap();
    let err = mat.validate_aws_crypto_public_key().unwrap_err();
    assert!(err.to_string().contains("SHOULD include"));
}
