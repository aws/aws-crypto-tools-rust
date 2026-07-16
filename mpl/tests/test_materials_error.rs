// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `MaterialsError` constructors, the `kind()` accessor, and
//! the `Display` impl. These tests exist to cover every executable line in
//! `mpl/src/structures/error.rs` so the project's CI gate
//! (`cargo llvm-cov --fail-under-lines 100`) passes.

use aws_crypto_mpl::structures::{MaterialsError, MaterialsErrorKind};

#[test]
fn test_new_constructor_yields_validation_kind() {
    let err = MaterialsError::new("validation failed");
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert_eq!(err.message, "validation failed");
    assert_eq!(err.kind(), &MaterialsErrorKind::Validation);
}

#[test]
fn test_no_behavior_attempted_constructor() {
    let err = MaterialsError::no_behavior_attempted("on_encrypt: nothing attempted");
    assert_eq!(err.kind, MaterialsErrorKind::NoBehaviorAttempted);
    assert_eq!(err.message, "on_encrypt: nothing attempted");
    assert_eq!(err.kind(), &MaterialsErrorKind::NoBehaviorAttempted);
}

#[test]
fn test_plaintext_data_key_already_present_constructor() {
    let err = MaterialsError::plaintext_data_key_already_present("PDK already on materials");
    assert_eq!(err.kind, MaterialsErrorKind::PlaintextDataKeyAlreadyPresent);
    assert_eq!(err.message, "PDK already on materials");
    assert_eq!(
        err.kind(),
        &MaterialsErrorKind::PlaintextDataKeyAlreadyPresent
    );
}

#[test]
fn test_no_matching_data_key_constructor() {
    let err = MaterialsError::no_matching_data_key("no EDK matched");
    assert_eq!(err.kind, MaterialsErrorKind::NoMatchingDataKey);
    assert_eq!(err.message, "no EDK matched");
    assert_eq!(err.kind(), &MaterialsErrorKind::NoMatchingDataKey);
}

#[test]
fn test_keyring_failed_constructor() {
    let err = MaterialsError::keyring_failed("HSM unavailable");
    assert_eq!(err.kind, MaterialsErrorKind::KeyringFailed);
    assert_eq!(err.message, "HSM unavailable");
    assert_eq!(err.kind(), &MaterialsErrorKind::KeyringFailed);
}

#[test]
fn test_required_encryption_context_key_missing_constructor() {
    let err = MaterialsError::required_encryption_context_key_missing(
        "RECK key b\"region\" not present in materials EC",
    );
    assert_eq!(
        err.kind,
        MaterialsErrorKind::RequiredEncryptionContextKeyMissing
    );
    assert_eq!(
        err.message,
        "RECK key b\"region\" not present in materials EC"
    );
    assert_eq!(
        err.kind(),
        &MaterialsErrorKind::RequiredEncryptionContextKeyMissing
    );
}

#[test]
fn test_encryption_context_value_mismatch_constructor() {
    let err = MaterialsError::encryption_context_value_mismatch(
        "key b\"purpose\" reproduced=foo stored=bar",
    );
    assert_eq!(err.kind, MaterialsErrorKind::EncryptionContextValueMismatch);
    assert_eq!(err.message, "key b\"purpose\" reproduced=foo stored=bar");
    assert_eq!(
        err.kind(),
        &MaterialsErrorKind::EncryptionContextValueMismatch
    );
}

#[test]
fn test_aws_crypto_public_key_missing_constructor() {
    let err = MaterialsError::aws_crypto_public_key_missing(
        "signing suite EC missing aws-crypto-public-key",
    );
    assert_eq!(err.kind, MaterialsErrorKind::AwsCryptoPublicKeyMissing);
    assert_eq!(
        err.message,
        "signing suite EC missing aws-crypto-public-key"
    );
    assert_eq!(err.kind(), &MaterialsErrorKind::AwsCryptoPublicKeyMissing);
}

#[test]
fn test_aws_crypto_public_key_unexpected_constructor() {
    let err = MaterialsError::aws_crypto_public_key_unexpected(
        "non-signing suite EC contains aws-crypto-public-key",
    );
    assert_eq!(err.kind, MaterialsErrorKind::AwsCryptoPublicKeyUnexpected);
    assert_eq!(
        err.message,
        "non-signing suite EC contains aws-crypto-public-key"
    );
    assert_eq!(
        err.kind(),
        &MaterialsErrorKind::AwsCryptoPublicKeyUnexpected
    );
}

#[test]
fn test_display_includes_kind_and_message() {
    let err = MaterialsError::keyring_failed("rate-limited");
    let formatted = format!("{err}");
    assert!(
        formatted.contains("MaterialsError"),
        "Display output names the error type; got: {formatted}"
    );
    assert!(
        formatted.contains("KeyringFailed"),
        "Display output includes the kind; got: {formatted}"
    );
    assert!(
        formatted.contains("rate-limited"),
        "Display output includes the message; got: {formatted}"
    );
}

#[test]
fn test_display_for_validation_kind() {
    let err = MaterialsError::new("invalid input");
    let formatted = format!("{err}");
    assert!(
        formatted.contains("Validation"),
        "Display output includes the Validation kind; got: {formatted}"
    );
    assert!(
        formatted.contains("invalid input"),
        "Display output includes the message; got: {formatted}"
    );
}

#[test]
fn test_clone_and_equality() {
    let err = MaterialsError::no_matching_data_key("none matched");
    let cloned = err.clone();
    assert_eq!(err, cloned);
    assert_eq!(err.kind, cloned.kind);
    assert_eq!(err.message, cloned.message);
}

#[test]
fn test_kind_clone_and_equality() {
    let kind = MaterialsErrorKind::PlaintextDataKeyAlreadyPresent;
    let cloned = kind.clone();
    assert_eq!(kind, cloned);
    // Debug print covers the derive on the enum.
    let debug = format!("{kind:?}");
    assert!(debug.contains("PlaintextDataKeyAlreadyPresent"));
}

#[test]
fn test_error_trait_implemented() {
    // Smoke test that std::error::Error is implemented (trait-object safety).
    fn assert_error_trait<E: std::error::Error>(_: &E) {}
    let err = MaterialsError::new("trait check");
    assert_error_trait(&err);
}

#[test]
fn test_new_with_cause_constructor() {
    let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad utf-8");
    let err = MaterialsError::new_with_cause("failed to validate", inner);
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert_eq!(err.message, "failed to validate");
    assert!(err.cause.is_some(), "cause should be populated");
}

#[test]
fn test_keyring_failed_with_cause_constructor() {
    let inner = std::io::Error::new(std::io::ErrorKind::TimedOut, "HSM timeout");
    let err = MaterialsError::keyring_failed_with_cause("keyring on_encrypt failed", inner);
    assert_eq!(err.kind, MaterialsErrorKind::KeyringFailed);
    assert_eq!(err.message, "keyring on_encrypt failed");
    assert!(err.cause.is_some(), "cause should be populated");
}

#[test]
fn test_error_source_returns_none_when_no_cause() {
    use std::error::Error;
    let err = MaterialsError::new("no cause");
    assert!(
        err.source().is_none(),
        "Error::source() must be None when cause is None"
    );
}

#[test]
fn test_error_source_returns_wrapped_cause() {
    use std::error::Error;
    let inner = std::io::Error::new(std::io::ErrorKind::TimedOut, "downstream timed out");
    let err = MaterialsError::keyring_failed_with_cause("HSM call failed", inner);
    let source = err.source().expect("source should be present");
    assert!(
        source.to_string().contains("downstream timed out"),
        "source should expose the wrapped error's message; got: {source}"
    );
}

#[test]
fn test_partial_eq_ignores_cause() {
    // Two errors with the same kind + message but differing causes MUST
    // compare equal, matching esdk's contract: `dyn Error` is not `Eq`,
    // so equality is defined over `kind` + `message` only.
    let no_cause = MaterialsError::keyring_failed("rate-limited");
    let with_cause = MaterialsError::keyring_failed_with_cause(
        "rate-limited",
        std::io::Error::other("throttled"),
    );
    assert_eq!(no_cause, with_cause);
}

#[test]
fn test_partial_eq_distinguishes_kind_and_message() {
    let a = MaterialsError::keyring_failed("boom");
    let different_kind = MaterialsError::no_matching_data_key("boom");
    let different_message = MaterialsError::keyring_failed("nope");
    assert_ne!(a, different_kind);
    assert_ne!(a, different_message);
}
