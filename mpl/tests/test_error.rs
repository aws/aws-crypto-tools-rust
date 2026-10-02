// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `aws_crypto_mpl::Error`'s public surface.

use std::error::Error as _;
use std::io::Error as IoError;

use aws_crypto_mpl::Error;
use aws_crypto_mpl::error::{
    AccessDeniedError, CryptographicError, ProvideErrorKind, ProvideErrorMetadata, RequestId,
    Resource, RetryErrorKind, RetryKind, Service, ServiceError, ValidationError,
};

#[test]
fn a_struct_converts_into_its_variant() {
    let err = Error::from(ValidationError::new("bad input"));
    assert!(err.is_validation());
    assert!(matches!(err, Error::Validation(_)));
    assert_eq!(err.message(), "bad input");
    assert!(!err.is_retryable());
    assert!(err.source().is_none());
}

#[test]
fn display_is_the_variant_then_the_message() {
    assert_eq!(
        Error::from(ValidationError::new("bad input")).to_string(),
        "Validation: bad input"
    );
}

#[test]
fn with_source_attaches_the_cause() {
    let err = Error::from(CryptographicError::new("m").with_source(IoError::other("reset")));
    assert_eq!(err.source().expect("the cause").to_string(), "reset");
}

#[test]
fn a_built_remote_error_names_its_service_and_resource() {
    let err: Error = AccessDeniedError::builder()
        .message("denied")
        .service(Service::Kms)
        .resource(Resource::KmsKey("arn".into()))
        .build()
        .into();
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert_eq!(e.service(), Some(Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey("arn".into())));
    assert_eq!(e.code(), None);
    assert_eq!(e.request_id(), None);
}

#[test]
fn the_sdk_traits_answer_from_the_error() {
    let err: Error = ServiceError::builder()
        .message("throttled")
        .service(Service::DynamoDb)
        .retry_kind(RetryKind::Throttling)
        .build()
        .into();
    assert!(err.is_retryable());
    assert_eq!(
        err.retryable_error_kind(),
        Some(RetryErrorKind::ThrottlingError)
    );
    assert_eq!(ProvideErrorMetadata::code(&err), None);
    assert_eq!(RequestId::request_id(&err), None);
    assert_eq!(err.meta().code(), None);
}

#[test]
fn the_short_constructors_make_each_variant() {
    let cases = [
        (Error::validation("m"), "Validation"),
        (Error::invalid_materials("m"), "InvalidMaterials"),
        (
            Error::encryption_context_mismatch("m"),
            "EncryptionContextMismatch",
        ),
        (Error::no_matching_data_key("m"), "NoMatchingDataKey"),
        (Error::cryptographic("m"), "Cryptographic"),
        (Error::internal("m"), "Internal"),
    ];
    for (err, name) in cases {
        assert_eq!(err.name(), name);
        assert_eq!(err.message(), "m");
        assert!(!err.is_retryable());
        let err = err.with_source(IoError::other("cause"));
        assert!(err.find_source::<IoError>().is_some(), "{name}");
    }
}

#[test]
fn builders_set_every_field_in_any_order() {
    use aws_crypto_mpl::error::{ConflictError, ConflictReason};
    let built = ConflictError::builder()
        .reason(ConflictReason::AlreadyExists)
        .request_id("r")
        .resource(Resource::BranchKey("b".into()))
        .retry_kind(RetryKind::Transient)
        .code("c")
        .source(IoError::other("cause"))
        .service(Service::DynamoDb)
        .message("m")
        .build();
    assert_eq!(built.message(), "m");
    assert_eq!(built.service(), Some(Service::DynamoDb));
    assert_eq!(built.resource(), Some(&Resource::BranchKey("b".into())));
    assert_eq!(built.code(), Some("c"));
    assert_eq!(built.request_id(), Some("r"));
    assert_eq!(built.reason(), Some(ConflictReason::AlreadyExists));
    assert_eq!(built.retry_kind(), Some(RetryKind::Transient));
    assert_eq!(built.source().expect("the cause").to_string(), "cause");
}

#[test]
fn is_credentials_is_true_only_for_credential_codes() {
    let denied = |code: &str| AccessDeniedError::builder().code(code).build();
    assert!(denied("ExpiredTokenException").is_credentials());
    assert!(denied("UnrecognizedClientException").is_credentials());
    assert!(denied("InvalidSignatureException").is_credentials());
    assert!(!denied("AccessDeniedException").is_credentials());
    assert!(!AccessDeniedError::new("no code").is_credentials());
}

fn denied(request_id: &str) -> Error {
    AccessDeniedError::builder()
        .message("AWS KMS Decrypt failed")
        .service(Service::Kms)
        .resource(Resource::KmsKey("arn".into()))
        .code("AccessDeniedException")
        .request_id(request_id)
        .build()
        .into()
}

#[test]
fn aggregate_of_one_error_returns_it() {
    let err = Error::aggregate("all failed", vec![denied("r1")]);
    assert_eq!(err.message(), "AWS KMS Decrypt failed");
    assert!(err.collected().is_empty());
}

#[test]
fn aggregate_keeps_the_details_every_error_shares() {
    let err = Error::aggregate("all failed", vec![denied("r1"), denied("r2")]);
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert_eq!(e.service(), Some(Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey("arn".into())));
    assert_eq!(e.code(), Some("AccessDeniedException"));
    // The request IDs differ, so the aggregate has none.
    assert_eq!(e.request_id(), None);
    assert_eq!(err.collected().len(), 2);
}

#[test]
fn aggregate_of_mixed_errors_takes_the_first_variant_by_priority() {
    use aws_crypto_mpl::error::ThrottlingError;
    let err = Error::aggregate(
        "all failed",
        vec![
            Error::no_matching_data_key("a"),
            Error::cryptographic("b"),
            ThrottlingError::new("c").into(),
            Error::invalid_materials("d"),
        ],
    );
    assert!(err.is_throttling(), "{err:?}");
    assert_eq!(err.retry_kind(), Some(RetryKind::Throttling));
}

#[test]
fn alternate_display_drops_what_each_level_repeats() {
    let inner: Error = ServiceError::builder()
        .message("AWS KMS Decrypt failed")
        .service(Service::Kms)
        .resource(Resource::KmsKey("inner-arn".into()))
        .code("KMSInvalidStateException")
        .build()
        .into();
    let middle = Error::from(
        ServiceError::builder()
            .message("could not get the key")
            .service(Service::Kms)
            .code("KMSInvalidStateException")
            .source(inner)
            .build(),
    );
    let outer = Error::from(
        AccessDeniedError::builder()
            .message("outer")
            .service(Service::Kms)
            .source(middle)
            .build(),
    );
    assert_eq!(
        format!("{outer:#}"),
        "AccessDenied: outer (AWS KMS): \
         Service: could not get the key (KMSInvalidStateException): \
         AWS KMS Decrypt failed (KMS key inner-arn)"
    );
}

#[test]
fn a_collection_prints_each_collected_error() {
    let err = Error::aggregate(
        "no encrypted data key decrypted",
        vec![
            Error::from(
                aws_crypto_mpl::error::NoMatchingDataKeyError::builder()
                    .message("a")
                    .resource(Resource::Keyring("child-1".into()))
                    .build(),
            ),
            Error::from(
                aws_crypto_mpl::error::NoMatchingDataKeyError::builder()
                    .message("b")
                    .resource(Resource::Keyring("child-2".into()))
                    .build(),
            ),
        ],
    );
    assert_eq!(
        err.to_string(),
        "NoMatchingDataKey: no encrypted data key decrypted; tried: child-1, child-2"
    );
    assert_eq!(
        format!("{err:#}"),
        "NoMatchingDataKey: no encrypted data key decrypted; tried: child-1, child-2: 2 errors: [\
         NoMatchingDataKey: a (keyring child-1); NoMatchingDataKey: b (keyring child-2)]"
    );
}
