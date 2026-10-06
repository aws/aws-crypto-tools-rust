// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the primitives' error type and the shared error types.

use std::error::Error as _;

use aws_mpl_primitives::error::{
    BranchKey, Cache, CmmResource, ConflictReason, CryptographicError, DataKeyInfo, DynamoDbTable,
    InternalError, KeyringResource, KmsKey, Resource, RetryKind, Service,
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
            Resource::KmsKey(KmsKey::new("arn:aws:kms:k")),
            "KMS key arn:aws:kms:k",
        ),
        (
            Resource::DynamoDbTable(DynamoDbTable::new("KeyStoreTable")),
            "table KeyStoreTable",
        ),
        (
            Resource::BranchKey(BranchKey::new("my-branch-key")),
            "branch key my-branch-key",
        ),
        (Resource::Cache(Cache::new()), "materials cache"),
        (
            Resource::Keyring(KeyringResource::new("my-namespace/my-key")),
            "keyring my-namespace/my-key",
        ),
        (Resource::Cmm(CmmResource::new("default")), "CMM default"),
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
fn each_resource_payload_converts_into_its_variant() {
    let key = Resource::from(KmsKey::new("arn:aws:kms:k"));
    assert!(matches!(&key, Resource::KmsKey(k) if k.arn() == "arn:aws:kms:k"));
    let table = Resource::from(DynamoDbTable::new("KeyStoreTable"));
    assert!(matches!(&table, Resource::DynamoDbTable(t) if t.name() == "KeyStoreTable"));
    let branch_key = Resource::from(BranchKey::new("my-branch-key"));
    assert!(matches!(&branch_key, Resource::BranchKey(b) if b.id() == "my-branch-key"));
    assert!(matches!(
        Resource::from(Cache::default()),
        Resource::Cache(_)
    ));
    let keyring = Resource::from(KeyringResource::new("ns/key"));
    assert!(matches!(&keyring, Resource::Keyring(k) if k.name() == "ns/key"));
    let cmm = Resource::from(CmmResource::new("default"));
    assert!(matches!(&cmm, Resource::Cmm(c) if c.name() == "default"));
}

#[test]
fn a_kms_key_reads_its_region_and_account_from_a_kms_arn() {
    let cases = [
        (
            "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            Some(("us-west-2", "111122223333")),
        ),
        (
            "arn:aws:kms:eu-west-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab",
            Some(("eu-west-1", "111122223333")),
        ),
        (
            "arn:aws-cn:kms:cn-north-1:111122223333:alias/my-alias",
            Some(("cn-north-1", "111122223333")),
        ),
        ("1234abcd-12ab-34cd-56ef-1234567890ab", None),
        ("mrk-1234abcd12ab34cd56ef1234567890ab", None),
        ("alias/my-alias", None),
        ("arn:aws:kms:k", None),
        ("arn:aws:s3:us-west-2:111122223333:key/k", None),
        ("arn:aws:kms:us-west-2:111122223333:grant/g", None),
        ("arn:aws:kms:us-west-2:111122223333:key/", None),
        ("arn:aws:kms::111122223333:key/k", None),
        ("arn:aws:kms:us-west-2::key/k", None),
        ("arn::kms:us-west-2:111122223333:key/k", None),
        ("", None),
    ];
    for (arn, expected) in cases {
        let key = KmsKey::new(arn);
        assert_eq!(key.arn(), arn);
        assert_eq!(key.region(), expected.map(|(r, _)| r), "{arn}");
        assert_eq!(key.account(), expected.map(|(_, a)| a), "{arn}");
    }
    let debug = format!(
        "{:?}",
        KmsKey::new("arn:aws:kms:us-west-2:111122223333:key/k")
    );
    assert!(debug.contains("region: Some(\"us-west-2\")"), "{debug}");
    assert!(debug.contains("account: Some(\"111122223333\")"), "{debug}");
}

#[test]
fn a_branch_key_has_a_version_only_when_given_one() {
    let unversioned = BranchKey::new("my-branch-key");
    assert_eq!(unversioned.version(), None);
    let versioned = unversioned.clone().with_version("v1");
    assert_eq!(versioned.id(), "my-branch-key");
    assert_eq!(versioned.version(), Some("v1"));
    assert_ne!(versioned, unversioned);
    assert_eq!(
        Resource::from(versioned.clone()).to_string(),
        "branch key my-branch-key"
    );
    assert!(format!("{versioned:?}").contains("version: Some(\"v1\")"));
}

#[test]
fn data_key_info_debug_shows_utf8_info_as_text_and_other_info_as_hex() {
    let text = DataKeyInfo::new("aws-kms-hierarchy", b"my-branch-key".to_vec());
    assert_eq!(text.key_provider_id(), "aws-kms-hierarchy");
    assert_eq!(text.key_provider_info(), b"my-branch-key");
    assert_eq!(
        format!("{text:?}"),
        r#"DataKeyInfo { key_provider_id: "aws-kms-hierarchy", key_provider_info: "my-branch-key" }"#
    );
    let binary = DataKeyInfo::new("raw", vec![0x00, 0xab, 0xff]);
    assert_eq!(
        format!("{binary:?}"),
        r#"DataKeyInfo { key_provider_id: "raw", key_provider_info: 0x00abff }"#
    );
}

#[test]
fn retry_kinds_print_their_names() {
    let cases = [
        (RetryKind::Transient, "transient"),
        (RetryKind::Throttling, "throttling"),
        (RetryKind::Server, "server"),
        (RetryKind::Client, "client"),
    ];
    for (kind, text) in cases {
        assert_eq!(kind.as_str(), text);
        assert_eq!(kind.to_string(), text);
    }
}

#[test]
fn with_source_on_the_error_sets_the_source() {
    let err = Error::from(InternalError::new("outer")).with_source(std::io::Error::other("io"));
    assert_eq!(err.source().unwrap().to_string(), "io");
    assert_eq!(format!("{err:#}"), "Internal: outer: io");
}

#[test]
fn a_single_error_is_its_own_only_failure() {
    let err = Error::from(InternalError::new("outer").with_source(make_error()));
    assert_eq!(err.collection(), None);
    assert!(err.collected().is_empty());
    let failures = err.failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].name(), "Internal");
    assert_eq!(failures[0].message(), "outer");
}

#[test]
fn debug_shows_the_variant_message_and_source() {
    let err = Error::from(InternalError::new("outer").with_source(std::io::Error::other("io")));
    let debug = format!("{err:?}");
    assert!(debug.starts_with("Internal(InternalError {"), "{debug}");
    assert!(debug.contains("message: \"outer\""), "{debug}");
    assert!(debug.contains("source:"), "{debug}");
}

#[test]
fn a_clone_keeps_the_source_chain() {
    let err = Error::from(InternalError::new("outer").with_source(std::io::Error::other("io")));
    let clone = err.clone();
    assert_eq!(format!("{clone:#}"), format!("{err:#}"));
    assert!(clone.find_source::<std::io::Error>().is_some());
}

#[test]
fn errors_are_send_sync_and_static() {
    fn check<T: Send + Sync + 'static>() {}
    check::<Error>();
    check::<CryptographicError>();
}
