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
