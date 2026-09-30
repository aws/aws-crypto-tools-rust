// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Error` trait-implementation coverage

use aws_mpl_primitives::{AesGcm, DigestAlg, Error, ErrorKind, aes_encrypt, hkdf};

fn make_error() -> Error {
    // A known-bad HKDF request, which fails the same way every time.
    let mut okm = [0u8; 20];
    hkdf(DigestAlg::Sha256, &[], &[0u8; 16], &[&[]], &mut okm).unwrap_err()
}

#[test]
fn test_error_is_cryptographic_and_display_is_the_message() {
    let err = make_error();
    assert_eq!(err.kind(), ErrorKind::Cryptographic);
    assert!(!err.is_retryable());
    assert_eq!(err.to_string(), err.message());
}

#[test]
fn test_error_partial_eq_matches_on_message_only() {
    // `Error::eq` ignores the backtrace, so two errors from the same call path are equal.
    let err1 = make_error();
    let err2 = make_error();
    assert_eq!(err1, err2);
}

#[test]
fn test_error_partial_eq_differs_when_messages_differ() {
    let err_hkdf = make_error();
    // Trigger a different error path with a different message.
    let mut ct = Vec::new();
    let err_aes = aes_encrypt(
        AesGcm::Aes256Gcm,
        &[2u8; 11],
        &[1u8; 32],
        b"m",
        b"",
        &mut ct,
    )
    .unwrap_err();
    assert_ne!(err_hkdf, err_aes);
}

#[test]
fn test_error_clone_preserves_message() {
    let err = make_error();
    let cloned = err.clone();
    assert_eq!(err, cloned);
    assert_eq!(err.message(), cloned.message());
}

#[test]
fn test_error_implements_std_error_trait() {
    // Exercises the `impl std::error::Error for Error` path.
    let err = make_error();
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

mod other_library {
    aws_mpl_primitives::define_error! {
        /// An error from another library.
        Error,
        /// Its kinds.
        ErrorKind;
        /// A kind only this library has.
        Extra,
    }
}

#[test]
fn from_inner_keeps_the_kind_by_name_with_its_own_message() {
    let inner = Error::new(ErrorKind::Cryptographic, "tag mismatch");
    let outer = other_library::Error::from_inner("could not decrypt", inner);
    assert_eq!(outer.kind(), other_library::ErrorKind::Cryptographic);
    assert_eq!(outer.to_string(), "could not decrypt");
    let source = std::error::Error::source(&outer).expect("the inner error is the source");
    assert_eq!(source.to_string(), "tag mismatch");
}

#[test]
fn from_inner_maps_a_kind_with_no_shared_name_to_internal() {
    let inner = other_library::Error::new(other_library::ErrorKind::Extra, "only here");
    assert_eq!(Error::from_inner("m", inner).kind(), ErrorKind::Internal);
}

#[test]
fn display_error_context_prints_every_layer_once() {
    use aws_mpl_primitives::error::DisplayErrorContext;
    let inner = Error::new(ErrorKind::Cryptographic, "authentication tag did not match");
    let outer = other_library::Error::from_inner("could not decrypt", inner);
    assert_eq!(
        DisplayErrorContext(&outer).to_string(),
        "could not decrypt: authentication tag did not match"
    );
}
