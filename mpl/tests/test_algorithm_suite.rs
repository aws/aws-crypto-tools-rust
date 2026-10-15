// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for algorithm_suite key type accessors and Debug impls.

use aws_crypto_mpl::types::{PlaintextDataKey, SigningKey, SymmetricSigningKey, VerificationKey};

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
fn test_signing_key_debug_redacts() {
    // Signing keys hold private-key material — the custom Debug impl MUST
    // redact the bytes (structures.md#signing-key).
    let sk = SigningKey::new(b"super-secret".to_vec());
    let debug_output = format!("{:?}", sk);
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
fn test_verification_key_debug_shows_bytes() {
    // Verification keys are public material (the counterpart to a private
    // SigningKey), so unlike the other three key newtypes they intentionally
    // use `#[derive(Debug)]` rather than a redacting impl. This test pins
    // that design choice so a future accidental swap to a redacting impl
    // produces a deliberate test failure.
    //
    // Bytes chosen with distinct values so their decimal-formatted form
    // (produced by the derived Debug on `VerificationKey(Vec<u8>)`) is
    // unambiguously present in the output.
    let vk = VerificationKey::new(vec![0xAB, 0xCD, 0xEF, 0x01]);
    let debug_output = format!("{:?}", vk);
    assert!(
        !debug_output.contains("REDACTED"),
        "VerificationKey Debug must NOT redact (public material), got: {debug_output}"
    );
    // Derived Debug for a `Vec<u8>` newtype prints each byte as decimal.
    assert!(
        debug_output.contains("171"),
        "VerificationKey Debug must expose bytes; missing 171 (=0xAB) in: {debug_output}"
    );
    assert!(
        debug_output.contains("205"),
        "VerificationKey Debug must expose bytes; missing 205 (=0xCD) in: {debug_output}"
    );
    assert!(
        debug_output.contains("239"),
        "VerificationKey Debug must expose bytes; missing 239 (=0xEF) in: {debug_output}"
    );
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

#[test]
fn test_symmetric_signing_key_debug_redacts() {
    // Symmetric signing keys hold secret HMAC key material — Debug MUST redact.
    let ssk = SymmetricSigningKey::new(b"super-secret-hmac".to_vec());
    let debug_output = format!("{:?}", ssk);
    assert!(
        debug_output.contains("REDACTED"),
        "Debug must redact key material, got: {debug_output}"
    );
    assert!(
        debug_output.contains("17 bytes"),
        "Debug must show byte count, got: {debug_output}"
    );
    assert!(
        !debug_output.contains("super-secret-hmac"),
        "Debug must NOT reveal key material, got: {debug_output}"
    );
}
