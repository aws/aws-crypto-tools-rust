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

    //= ../spec/framework/structures.md#required-encryption-context-keys-1
    //= type=test
    //# Every key in Required Encryption Context Keys
    //# MUST be a key in the [encryption context](#encryption-context-2).
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

    //= ../spec/framework/structures.md#symmetric-signing-key
    //= type=test
    //# If the algorithm suite does not contain a symmetric signing algorithm,
    //# the symmetric signing key MUST NOT be included in the materials.
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
fn test_symmetric_key_iff_plaintext_data_key() {
    let suite = AlgorithmSuite::new(false, true);
    let ec = EncryptionContext::new();
    let reck = BTreeSet::new();
    let pdk = PlaintextDataKey::new(b"key".to_vec());

    // PDK present but no SSK → error
    //= ../spec/framework/structures.md#symmetric-signing-key
    //= type=test
    //# If the algorithm suite does contain a symmetric signing algorithm,
    //# the symmetric signing key MUST also be included in the materials
    //# if and only if the materials also include a [plaintext data key](#plaintext-data-key-1).
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

    //= ../spec/framework/structures.md#encryption-context-2
    //= type=test
    //# If a [decryption materials](#decryption-materials) contains a [verification key](#verification-key),
    //# the [encryption context](#encryption-context) SHOULD include the reserved key `aws-crypto-public-key`.
    let mat = DecryptionMaterials::new(suite, ec, reck, None, Some(vk), None).unwrap();
    assert!(mat.validate_aws_crypto_public_key().is_ok());
}

#[test]
fn test_validate_aws_crypto_public_key_should_not_include_without_verification() {
    let suite = AlgorithmSuite::new(false, false);
    let ec = make_ec_with_keys(&[b"aws-crypto-public-key"]);
    let reck = BTreeSet::new();

    //= ../spec/framework/structures.md#encryption-context-2
    //= type=test
    //# If a [decryption materials](#decryption-materials) does not contain a [verification key](#verification-key),
    //# the [encryption context](#encryption-context) SHOULD NOT include the reserved key `aws-crypto-public-key`.
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
    //= ../spec/framework/structures.md#plaintext-data-key-1
    //= type=test
    //# The plaintext data key SHOULD offer an interface to zero the plaintext data key.
    let mut pdk = PlaintextDataKey::new(b"secret-dec".to_vec());
    pdk.zeroize();
    assert!(pdk.as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn test_symmetric_signing_key_debug_redacted_dec() {
    //= ../spec/framework/structures.md#symmetric-signing-key
    //= type=test
    //# This value MUST be kept secret.
    let ssk = SymmetricSigningKey::new(b"sym-secret-key".to_vec());
    let debug_output = format!("{:?}", ssk);
    assert!(!debug_output.contains("sym-secret-key"));
    assert!(debug_output.contains("REDACTED"));
}
