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
fn test_plaintext_already_present_constructor() {
    let err = MaterialsError::plaintext_already_present("PDK already on materials");
    assert_eq!(err.kind, MaterialsErrorKind::PlaintextAlreadyPresent);
    assert_eq!(err.message, "PDK already on materials");
    assert_eq!(err.kind(), &MaterialsErrorKind::PlaintextAlreadyPresent);
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
    let kind = MaterialsErrorKind::PlaintextAlreadyPresent;
    let cloned = kind.clone();
    assert_eq!(kind, cloned);
    // Debug print covers the derive on the enum.
    let debug = format!("{kind:?}");
    assert!(debug.contains("PlaintextAlreadyPresent"));
}

#[test]
fn test_error_trait_implemented() {
    // Smoke test that std::error::Error is implemented (trait-object safety).
    fn assert_error_trait<E: std::error::Error>(_: &E) {}
    let err = MaterialsError::new("trait check");
    assert_error_trait(&err);
}
