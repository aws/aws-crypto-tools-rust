// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `aws_crypto_mpl::Error`.

use std::error::Error as _;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use aws_crypto_mpl::{Error, ErrorKind};

#[test]
fn new_keeps_kind_and_message_and_has_no_source() {
    let err = Error::new(ErrorKind::Validation, "bad input");
    assert_eq!(err.kind(), ErrorKind::Validation);
    assert_eq!(err.message(), "bad input");
    assert!(err.source().is_none());
    assert!(err.collected().is_empty());
}

#[test]
fn with_cause_exposes_the_cause_through_source() {
    let err = Error::with_cause(
        ErrorKind::Remote,
        "DynamoDB GetItem failed",
        IoError::new(IoErrorKind::ConnectionReset, "reset"),
    );
    let source = err.source().expect("the cause is the source");
    assert_eq!(source.to_string(), "reset");
}

#[test]
fn throttled_and_transport_kinds_are_retryable_by_default() {
    for kind in [ErrorKind::RemoteThrottled, ErrorKind::RemoteTransport] {
        assert!(Error::new(kind, "x").is_retryable(), "{kind:?}");
    }
    for kind in [
        ErrorKind::Validation,
        ErrorKind::Cryptographic,
        ErrorKind::RemoteAccessDenied,
        ErrorKind::Remote,
        ErrorKind::Internal,
    ] {
        assert!(!Error::new(kind, "x").is_retryable(), "{kind:?}");
    }
}

#[test]
fn wrap_keeps_the_inner_kind_and_retryability() {
    let inner = Error::new(ErrorKind::RemoteThrottled, "DynamoDB GetItem failed");
    let outer = Error::wrap("HierarchicalKeyring: get_active_branch_key failed", inner);
    assert_eq!(outer.kind(), ErrorKind::RemoteThrottled);
    assert!(outer.is_retryable());
    assert_eq!(
        outer.message(),
        "HierarchicalKeyring: get_active_branch_key failed"
    );
    let source = outer.source().expect("the inner error is the source");
    assert_eq!(
        source.downcast_ref::<Error>().map(Error::message),
        Some("DynamoDB GetItem failed")
    );
}

#[test]
fn collection_keeps_every_error_and_nominates_a_cause_only_when_unambiguous() {
    let a = Error::new(ErrorKind::Cryptographic, "EDK 0: tag mismatch");
    let b = Error::new(ErrorKind::Cryptographic, "EDK 1: tag mismatch");

    let one = Error::collection(
        ErrorKind::Cryptographic,
        "no EDK decrypted",
        vec![a.clone()],
    );
    assert_eq!(one.collected(), vec![a.clone()]);
    assert!(
        one.source().is_some(),
        "a single collected error is the source"
    );

    let two = Error::collection(ErrorKind::Cryptographic, "no EDK decrypted", vec![a, b]);
    assert_eq!(two.collected().len(), 2);
    assert!(
        two.source().is_none(),
        "several collected errors have no single source"
    );
}

#[test]
fn collection_is_retryable_only_if_every_collected_error_is() {
    let throttled = Error::new(ErrorKind::RemoteThrottled, "throttled");
    let denied = Error::new(ErrorKind::RemoteAccessDenied, "denied");
    let all = Error::collection(
        ErrorKind::RemoteThrottled,
        "m",
        vec![throttled.clone(), throttled.clone()],
    );
    assert!(all.is_retryable());
    let mixed = Error::collection(ErrorKind::Remote, "m", vec![throttled, denied]);
    assert!(!mixed.is_retryable());
}

#[test]
fn display_renders_kind_message_and_collected_errors() {
    assert_eq!(
        Error::new(ErrorKind::Validation, "bad input").to_string(),
        "Validation: bad input"
    );
    let err = Error::collection(
        ErrorKind::Cryptographic,
        "no EDK decrypted",
        vec![
            Error::new(ErrorKind::Cryptographic, "EDK 0"),
            Error::new(ErrorKind::Cryptographic, "EDK 1"),
        ],
    );
    assert_eq!(
        err.to_string(),
        "Cryptographic: no EDK decrypted (collected errors: [Cryptographic: EDK 0; Cryptographic: EDK 1])"
    );
}

#[test]
fn equality_compares_kind_message_and_collected_but_not_cause() {
    let plain = Error::new(ErrorKind::Remote, "m");
    let caused = Error::with_cause(ErrorKind::Remote, "m", IoError::other("x"));
    assert_eq!(plain, caused);
    assert_ne!(plain, Error::new(ErrorKind::Internal, "m"));
    assert_ne!(plain, Error::new(ErrorKind::Remote, "other"));
}
