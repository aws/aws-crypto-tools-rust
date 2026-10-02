// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the primitives' error type and the shared error types.

use std::error::Error as _;

use aws_mpl_primitives::error::{
    ConflictReason, CryptographicError, InternalError, Resource, RetryKind, Service,
};
use aws_mpl_primitives::{DigestAlg, Error, hkdf};

fn make_error() -> Error {
    // A known-bad HKDF request, which fails the same way every time.
    let mut okm = [0u8; 20];
    hkdf(DigestAlg::Sha256, &[], &[0u8; 16], &[&[]], &mut okm).unwrap_err()
}

#[test]
fn a_primitive_failure_is_a_non_retryable_cryptographic_error() {
    let err = make_error();
    assert!(matches!(err, Error::Cryptographic(_)));
    assert!(!err.is_retryable());
    assert_eq!(err.name(), "Cryptographic");
    assert_eq!(err.service(), None);
    assert_eq!(err.resource(), None);
}

#[test]
fn display_is_the_variant_then_the_message() {
    let err = make_error();
    assert_eq!(err.to_string(), format!("Cryptographic: {}", err.message()));
}

#[test]
fn a_struct_converts_into_its_variant() {
    let err: Error = CryptographicError::new("tag mismatch").into();
    assert!(err.is_cryptographic());
    assert_eq!(err.message(), "tag mismatch");
    assert!(err.source().is_none());
}

#[test]
fn the_builder_sets_the_message_source_and_retry_kind() {
    let built = InternalError::builder()
        .retry_kind(RetryKind::Transient)
        .source(std::io::Error::other("cause"))
        .message("m")
        .build();
    assert_eq!(built.message(), "m");
    assert_eq!(built.retry_kind(), Some(RetryKind::Transient));
    assert_eq!(built.source().unwrap().to_string(), "cause");
    assert_eq!(built.to_string(), "Internal: m");
}

#[test]
fn alternate_display_prints_the_source_chain() {
    let inner = Error::from(CryptographicError::new("tag mismatch"));
    let err = Error::from(InternalError::new("outer").with_source(inner));
    assert_eq!(
        format!("{err:#}"),
        "Internal: outer: Cryptographic: tag mismatch"
    );
    assert_eq!(err.to_string(), "Internal: outer");
}

#[test]
fn find_source_searches_the_chain_including_self() {
    let err = Error::from(InternalError::new("outer").with_source(std::io::Error::other("io")));
    assert!(err.find_source::<Error>().is_some());
    assert_eq!(
        err.find_source::<std::io::Error>().map(ToString::to_string),
        Some("io".to_owned())
    );
    assert!(err.find_source::<std::fmt::Error>().is_none());
}

#[test]
fn service_and_resource_display() {
    assert_eq!(Service::Kms.to_string(), "AWS KMS");
    assert_eq!(Service::DynamoDb.to_string(), "Amazon DynamoDB");
    assert_eq!(Service::Kms.as_str(), "kms");
    assert_eq!(Service::DynamoDb.as_str(), "dynamodb");
    let cases = [
        (
            Resource::KmsKey("arn:aws:kms:k".into()),
            "KMS key arn:aws:kms:k",
        ),
        (
            Resource::DynamoDbTable("KeyStoreTable".into()),
            "table KeyStoreTable",
        ),
        (
            Resource::BranchKey("my-branch-key".into()),
            "branch key my-branch-key",
        ),
        (Resource::Cache, "materials cache"),
        (
            Resource::Keyring("my-namespace/my-key".into()),
            "keyring my-namespace/my-key",
        ),
        (Resource::Cmm("default".into()), "CMM default"),
    ];
    for (resource, text) in cases {
        assert_eq!(resource.to_string(), text);
    }
    assert_eq!(RetryKind::Throttling.to_string(), "throttling");
    assert_ne!(
        ConflictReason::AlreadyExists,
        ConflictReason::ConcurrentModification
    );
}

#[test]
fn errors_are_send_sync_and_static() {
    fn check<T: Send + Sync + 'static>() {}
    check::<Error>();
    check::<CryptographicError>();
}
