// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the error shape `define_error!` generates.

use std::error::Error as _;

use aws_mpl_primitives::error::{DisplayErrorContext, Resource, RetryKind, Service};
use aws_mpl_primitives::{CryptographicError, DigestAlg, Error, hkdf};

fn make_error() -> Error {
    // A known-bad HKDF request, which fails the same way every time.
    let mut okm = [0u8; 20];
    hkdf(DigestAlg::Sha256, &[], &[0u8; 16], &[&[]], &mut okm).unwrap_err()
}

#[test]
fn a_primitive_failure_is_a_non_retryable_cryptographic_error() {
    let err = make_error();
    assert!(err.is_cryptographic());
    assert!(!err.is_retryable());
    assert!(matches!(err, Error::Cryptographic(_)));
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
    let built = CryptographicError::builder()
        .message("m")
        .source(std::io::Error::other("cause"))
        .retry_kind(RetryKind::Transient)
        .build();
    assert_eq!(built.message(), "m");
    assert!(built.is_retryable());
    assert_eq!(built.source().unwrap().to_string(), "cause");
}

mod other_library {
    aws_mpl_primitives::define_error! {
        /// An error from another library.
        pub enum Error {
            Cryptographic(CryptographicError, is_cryptographic),
            AccessDenied(AccessDeniedError, is_access_denied, remote),
            /// A kind only this library has.
            Extra(ExtraError, is_extra),
            Internal(InternalError, is_internal),
        }
    }

    pub fn from_prim(message: &str, inner: aws_mpl_primitives::Error) -> Error {
        Error::from_inner(message, inner)
    }

    pub fn denied() -> Error {
        AccessDeniedError::builder()
            .message("denied")
            .service(super::Service::Kms)
            .resource(super::Resource::KmsKey("arn".into()))
            .build()
            .into()
    }

    pub fn wrapped(message: &str, inner: Error) -> Error {
        Error::wrap(message, inner)
    }

    pub fn extra() -> Error {
        ExtraError::new("only here").into()
    }
}

#[test]
fn from_inner_keeps_the_variant_by_name_with_its_own_message() {
    let inner: Error = CryptographicError::new("tag mismatch").into();
    let outer = other_library::from_prim("could not decrypt", inner);
    assert!(outer.is_cryptographic());
    assert_eq!(outer.message(), "could not decrypt");
    assert_eq!(
        DisplayErrorContext(&outer).to_string(),
        "Cryptographic: could not decrypt: Cryptographic: tag mismatch"
    );
}

#[test]
fn a_remote_error_names_its_service_and_resource_through_wrapping() {
    let outer = other_library::wrapped("could not get the key", other_library::denied());
    let other_library::Error::AccessDenied(e) = &outer else {
        panic!("expected AccessDenied, got {outer:?}");
    };
    assert_eq!(e.service(), Some(Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey("arn".into())));
    assert_eq!(e.code(), None);
}

mod third_library {
    aws_mpl_primitives::define_error! {
        /// A library without `Extra`.
        pub enum Error {
            Cryptographic(CryptographicError, is_cryptographic),
            Internal(InternalError, is_internal),
        }
    }

    pub fn from_other(inner: super::other_library::Error) -> Error {
        Error::from_inner("m", inner)
    }
}

#[test]
fn from_inner_maps_a_variant_with_no_shared_name_to_internal() {
    assert!(third_library::from_other(other_library::extra()).is_internal());
}
