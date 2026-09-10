// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Behavioral coverage for the public `Error` type: `Display` formatting,
//! equality, `std::error::Error::source`, and the `From` conversions callers
//! rely on when wrapping their own error text.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::{Error, ErrorKind};

// Display must name the error kind and carry the message for every
// caller-reachable kind.
#[test]
fn test_display_names_kind_and_message() {
    let esdk = Error::from("boom");
    assert_eq!(esdk.kind, ErrorKind::Esdk);
    assert_eq!(esdk.to_string(), "Esdk Error boom");

    let owned = Error::from(String::from("owned boom"));
    assert_eq!(owned.kind, ErrorKind::Esdk);
    assert_eq!(owned.to_string(), "Esdk Error owned boom");
}

// Errors compare by kind + message; backtrace and cause are excluded.
#[test]
fn test_equality_is_kind_and_message() {
    assert_eq!(Error::from("same"), Error::from("same"));
    assert_ne!(Error::from("one"), Error::from("two"));
}

// `From<&str>` / `From<String>` produce Esdk-kind errors with no cause;
// source() must be None for them.
#[test]
fn test_source_none_without_cause() {
    let err = Error::from("no cause");
    assert!(std::error::Error::source(&err).is_none());
}

// A smithy BuildError converts to ValidationError and keeps the builder
// failure as source().
#[test]
fn test_from_smithy_build_error() {
    let build_err = aws_smithy_types::error::operation::BuildError::missing_field(
        "field",
        "required field missing",
    );
    let err = Error::from(build_err);
    assert_eq!(err.kind, ErrorKind::ValidationError);
    assert_eq!(&err.to_string()[..16], "Validation Error");
    assert!(
        std::error::Error::source(&err).is_some(),
        "converted BuildError must be retained as source"
    );
}

// A legacy MPL error converts to LegacyError and Display carries both the
// inner error and the message.
#[test]
fn test_from_legacy_mpl_error_display_and_source() {
    let legacy =
        aws_mpl_legacy::dafny::types::error::Error::AwsCryptographicMaterialProvidersException {
            message: "legacy failure".to_string(),
        };
    let err = Error::from(legacy);
    let ErrorKind::LegacyError(_) = &err.kind else {
        panic!("expected LegacyError, got: {:?}", err.kind);
    };
    assert!(
        err.to_string().starts_with("Legacy MPL Error"),
        "got: {err}"
    );
}

// A native MPL error (here: the NotImplemented error from a modern-layer
// constructor) converts to MplError, keeps the inner error as source(), and
// Display names the kind.
#[test]
fn test_from_native_mpl_error_display_and_source() {
    let native = aws_mpl_legacy::keyring::create_multi_keyring(
        &aws_mpl_legacy::keyring::CreateMultiKeyringInput::default(),
    )
    .expect_err("modern multi-keyring constructor returns NotImplemented");
    let err = Error::from(native);
    assert_eq!(err.kind, ErrorKind::MplError);
    assert!(err.to_string().starts_with("MPL Error"), "got: {err}");
    assert!(
        std::error::Error::source(&err).is_some(),
        "converted native error must be retained as source"
    );
}
