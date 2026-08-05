// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Error` trait-implementation coverage

use aws_mpl_primitives::{AesGcm, DigestAlg, Error, aes_encrypt, hkdf};

fn make_error() -> Error {
    // Trigger an error via a known-bad HKDF request. Its message is
    // deterministic ("Invalid key length ...").
    let mut okm = [0u8; 20];
    hkdf(DigestAlg::Sha256, &[], &[0u8; 16], &[&[]], &mut okm).unwrap_err()
}

#[test]
fn test_error_display_starts_with_crypto_error_prefix() {
    let err = make_error();
    let display = format!("{err}");
    assert!(display.starts_with("Crypto Error "));
    assert!(display.contains("Invalid key length"));
}

#[test]
fn test_error_partial_eq_matches_on_message_only() {
    // `Error::eq` compares `.message` only, so two errors from the same call
    // path compare equal. The backtrace never participates, and it is usually
    // not even distinct: `Error` captures with `Backtrace::capture()`, which
    // honours `RUST_BACKTRACE` and yields `<disabled>` when it is unset, so
    // in a default run these two backtraces are byte-identical. They differ
    // only under `RUST_BACKTRACE=1`, and `eq` ignores them either way.
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
    assert_eq!(err.message, cloned.message);
}

#[test]
fn test_error_implements_std_error_trait() {
    // Exercises the `impl std::error::Error for Error` path.
    let err = make_error();
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}
