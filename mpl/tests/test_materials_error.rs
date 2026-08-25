// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `MaterialsError` constructors, the `kind()` accessor, and
//! the `Display` impl. These tests exist to cover every executable line in
//! `mpl/src/structures/error.rs` so the project's CI gate
//! (`cargo llvm-cov --fail-under-lines 100`) passes.

use std::error::Error as _;

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
fn test_display_renders_the_collected_errors() {
    let err = MaterialsError::collection(
        MaterialsErrorKind::KeyringFailed,
        "every attempt failed",
        vec![
            MaterialsError::keyring_failed("first attempt"),
            MaterialsError::keyring_failed("second attempt"),
        ],
    );

    // The collected failures live only in `collected`; Display is what renders
    // them, so the message stays a description of the overall failure.
    assert_eq!(err.message, "every attempt failed");
    assert!(!err.message.contains("first attempt"));

    let rendered = err.to_string();
    assert_eq!(
        rendered,
        "MaterialsError(KeyringFailed): every attempt failed (collected errors: \
         [MaterialsError(KeyringFailed): first attempt; \
         MaterialsError(KeyringFailed): second attempt])",
    );
}

#[test]
fn test_display_omits_the_collected_clause_when_there_is_nothing_collected() {
    let err = MaterialsError::keyring_failed("a single failure");
    assert_eq!(
        err.to_string(),
        "MaterialsError(KeyringFailed): a single failure",
        "an error that aggregates nothing must render exactly as before",
    );
}

#[test]
fn test_collection_keeps_the_kind_it_was_given() {
    // Aggregate-ness is orthogonal to kind: a keyring whose every candidate was
    // rejected by its own provider filter aggregates those rejections but is
    // still categorically a no-match, not a decryption failure.
    let err = MaterialsError::collection(
        MaterialsErrorKind::NoMatchingDataKey,
        "no encrypted data key matched this keyring",
        vec![MaterialsError::no_matching_data_key("EDK 0 did not match")],
    );

    assert_eq!(err.kind, MaterialsErrorKind::NoMatchingDataKey);
    assert!(err.is_collection());
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
fn test_ordinary_constructors_collect_nothing() {
    // `collected` is only populated by the aggregate constructor, so every
    // other error reports an empty collection rather than `Option`-wrapping it.
    assert!(
        MaterialsError::keyring_failed("one failure")
            .collected_errors()
            .is_empty()
    );
    assert!(MaterialsError::new("invalid").collected_errors().is_empty());
    assert!(!MaterialsError::keyring_failed("one failure").is_collection());
}

#[test]
fn test_keyring_failed_collection_keeps_every_error_typed() {
    let collected = vec![
        MaterialsError::keyring_failed("first attempt"),
        MaterialsError::new("second attempt was invalid"),
    ];

    let err = MaterialsError::collection(
        MaterialsErrorKind::KeyringFailed,
        "all attempts failed",
        collected.clone(),
    );

    assert_eq!(err.kind, MaterialsErrorKind::KeyringFailed);
    assert!(err.is_collection());
    assert_eq!(err.message, "all attempts failed");
    // Typed and in order, including an error of a different kind — the
    // aggregate does not flatten or normalise what it collected.
    assert_eq!(err.collected_errors(), collected.as_slice());
    assert_eq!(
        err.collected_errors()[1].kind,
        MaterialsErrorKind::Validation,
    );
}

#[test]
fn test_keyring_failed_collection_nominates_a_cause_only_when_unambiguous() {
    let one = MaterialsError::collection(
        MaterialsErrorKind::KeyringFailed,
        "one attempt failed",
        vec![MaterialsError::keyring_failed("the only attempt")],
    );
    let only = one
        .source()
        .expect("a single collected error is an unambiguous cause")
        .downcast_ref::<MaterialsError>()
        .expect("the cause is the collected MaterialsError");
    assert_eq!(only.message, "the only attempt");

    let several = MaterialsError::collection(
        MaterialsErrorKind::KeyringFailed,
        "two attempts failed",
        vec![
            MaterialsError::keyring_failed("first"),
            MaterialsError::keyring_failed("second"),
        ],
    );
    assert!(
        several.source().is_none(),
        "with several failures there is no single one to nominate as the cause",
    );
}

#[test]
fn test_equality_distinguishes_different_collected_errors() {
    let base = |collected| {
        MaterialsError::collection(MaterialsErrorKind::KeyringFailed, "same", collected)
    };

    let first = base(vec![MaterialsError::keyring_failed("first")]);
    let second = base(vec![MaterialsError::keyring_failed("second")]);

    // Same kind and message, different collected failures. `collected` is
    // compared, unlike `cause`, so these are not the same error.
    assert_eq!(first.kind, second.kind);
    assert_eq!(first.message, second.message);
    assert_ne!(first, second);
    assert_eq!(first, first.clone());
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
