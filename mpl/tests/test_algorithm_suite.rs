// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for algorithm_suite key type accessors and Debug impls.

use aws_crypto_mpl::structures::{
    PlaintextDataKey, SigningKey, SymmetricSigningKey, VerificationKey,
};

#[test]
fn test_plaintext_data_key_accessors() {
    let pdk = PlaintextDataKey::new(b"abc".to_vec());
    assert_eq!(pdk.as_bytes(), b"abc");
    assert_eq!(pdk.len(), 3);
    assert!(!pdk.is_empty());

    let empty = PlaintextDataKey::new(vec![]);
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

#[test]
fn test_plaintext_data_key_debug_redacts() {
    // Verifies that the custom Debug impl redacts secret material.
    // The spec says the plaintext data key MUST "Be kept secret" (structures.md#plaintext-data-key).
    let pdk = PlaintextDataKey::new(b"super-secret".to_vec());
    let debug_output = format!("{:?}", pdk);
    assert!(
        debug_output.contains("REDACTED"),
        "Debug must redact key material, got: {debug_output}"
    );
    assert!(
        debug_output.contains("12 bytes"),
        "Debug must show byte count, got: {debug_output}"
    );
    assert!(
        !debug_output.contains("super-secret"),
        "Debug must NOT reveal key material, got: {debug_output}"
    );
}

#[test]
fn test_signing_key_accessors() {
    let sk = SigningKey::new(b"sk".to_vec());
    assert_eq!(sk.as_bytes(), b"sk");
    assert_eq!(sk.len(), 2);
    assert!(!sk.is_empty());

    let empty = SigningKey::new(vec![]);
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

#[test]
fn test_verification_key_accessors() {
    let vk = VerificationKey::new(b"vk".to_vec());
    assert_eq!(vk.as_bytes(), b"vk");
    assert_eq!(vk.len(), 2);
    assert!(!vk.is_empty());

    let empty = VerificationKey::new(vec![]);
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

#[test]
fn test_symmetric_signing_key_accessors() {
    let ssk = SymmetricSigningKey::new(b"sym-key".to_vec());
    assert_eq!(ssk.as_bytes(), b"sym-key");
    assert_eq!(ssk.len(), 7);
    assert!(!ssk.is_empty());

    let empty = SymmetricSigningKey::new(vec![]);
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}
