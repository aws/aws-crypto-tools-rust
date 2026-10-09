// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! An MPL error keeps its variant, retry kind, and details when it becomes an ESDK error.

use aws_crypto_mpl::error as mpl;
use aws_esdk::error::{BranchKey, Cache, ConflictReason, Error, Resource, RetryKind, Service};

fn every_mpl_variant() -> Vec<mpl::Error> {
    vec![
        mpl::ValidationError::new("v").into(),
        mpl::InvalidMaterialsError::new("im").into(),
        mpl::EncryptionContextMismatchError::new("ec").into(),
        mpl::NoMatchingDataKeyError::new("nm").into(),
        mpl::CryptographicError::new("c").into(),
        mpl::AccessDeniedError::new("ad").into(),
        mpl::ResourceNotFoundError::new("rnf").into(),
        mpl::ThrottlingError::new("t").into(),
        mpl::ConflictError::new("cf").into(),
        mpl::ServiceError::new("s").into(),
        mpl::DispatchError::new("d").into(),
        mpl::InternalError::new("i").into(),
    ]
}

#[test]
fn every_mpl_variant_keeps_its_name() {
    for inner in every_mpl_variant() {
        let name = inner.name();
        let outer = inner;
        let same = matches!(
            (&outer, name),
            (Error::Validation(_), "Validation")
                | (Error::InvalidMaterials(_), "InvalidMaterials")
                | (
                    Error::EncryptionContextMismatch(_),
                    "EncryptionContextMismatch"
                )
                | (Error::NoMatchingDataKey(_), "NoMatchingDataKey")
                | (Error::Cryptographic(_), "Cryptographic")
                | (Error::AccessDenied(_), "AccessDenied")
                | (Error::ResourceNotFound(_), "ResourceNotFound")
                | (Error::Throttling(_), "Throttling")
                | (Error::Conflict(_), "Conflict")
                | (Error::Service(_), "Service")
                | (Error::Dispatch(_), "Dispatch")
                | (Error::Internal(_), "Internal")
        );
        assert!(same, "{name} became {}", outer.name());
        assert!(outer.find_source::<mpl::Error>().is_some());
    }
}

#[test]
fn the_conversion_keeps_retry_kind_details_and_reason() {
    let inner = mpl::ConflictError::builder()
        .message("branch key my-branch-key was rotated concurrently")
        .request_id("Q2N0")
        .reason(ConflictReason::ConcurrentModification)
        .code("TransactionCanceledException")
        .resource(Resource::BranchKey(BranchKey::new("my-branch-key")))
        .service(Service::DynamoDb)
        .build();
    let Error::Conflict(e) = mpl::Error::from(inner) else {
        panic!("expected Conflict");
    };
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BranchKey::new("my-branch-key")))
    );
    assert_eq!(e.code(), Some("TransactionCanceledException"));
    assert_eq!(e.request_id(), Some("Q2N0"));
    assert_eq!(e.reason(), Some(&ConflictReason::ConcurrentModification));
    assert!(!e.is_retryable());

    let throttled = mpl::Error::from(
        mpl::ThrottlingError::builder()
            .resource(Resource::Cache(Cache::new()))
            .build(),
    );
    assert_eq!(throttled.retry_kind(), Some(RetryKind::Throttling));
    assert_eq!(throttled.service(), None);
    assert_eq!(throttled.resource(), Some(&Resource::Cache(Cache::new())));
}
