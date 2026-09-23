// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for spec/client-apis/decrypt.md#get-the-decryption-materials
//! and spec/client-apis/decrypt.md#input,
//! focusing on the Reproduced Encryption Context requirement.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;
use aws_esdk::*;
use fixtures::*;
use test_helpers::test_keyring;

// Positive-path round-trip with the same encryption context on encrypt and
// decrypt, using a local raw AES keyring (no network/credentials dependency).
#[tokio::test(flavor = "multi_thread")]
async fn test_encryption_context_on_decrypt() {
    let asdf = "asdf".as_bytes();

    let raw_aes_keyring = test_keyring().await;

    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::AB);

    let encrypt_output = encrypt(&EncryptInput::with_keyring(
        asdf,
        encryption_context.clone(),
        raw_aes_keyring.clone(),
    ))
    .await
    .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext;

    let decrypt_output = decrypt(&DecryptInput::with_keyring(
        &esdk_ciphertext,
        encryption_context,
        raw_aes_keyring,
    ))
    .await
    .unwrap();

    assert_eq!(decrypt_output.plaintext, asdf);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mismatched_encryption_context_on_decrypt() {
    let asdf = "asdf".as_bytes();

    let raw_aes_keyring = test_keyring().await;

    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::A);
    let bad_encryption_context =
        small_mismatched_encryption_context(SmallEncryptionContextVariation::A);

    let encrypt_output = encrypt(&EncryptInput::with_keyring(
        asdf,
        encryption_context.clone(),
        raw_aes_keyring.clone(),
    ))
    .await
    .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext;

    let mut decrypt_input =
        DecryptInput::with_keyring(&esdk_ciphertext, bad_encryption_context, raw_aes_keyring);
    let err = decrypt(&decrypt_input)
        .await
        .expect_err("decrypt must fail when reproduced encryption context has mismatched values");

    // We expect to fail because although the same key is present on the ec,
    // the value is different. The MPL's reproduced-EC validation produces a
    // pinned error message identifying the mechanism.
    assert_eq!(
        err.kind,
        ErrorKind::MplError,
        "expected MplError, got: {:?}",
        err.kind
    );
    let inner = err.to_string();
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Mismatched reproduced EC value triggers MPL "does not match reproduced encryption context" error, proving the reproduced EC was used
    //# - Reproduced Encryption Context: This MUST be the [input](#input) encryption context.
    assert!(
        inner.contains("does not match reproduced encryption context"),
        "expected reproduced-EC mismatch error, got: {inner}"
    );

    decrypt_input.encryption_context = encryption_context;
    // Test that if we supply the right ec we will succeed.
    let _ = decrypt(&decrypt_input).await.unwrap();

    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# - Decrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
    decrypt_input.encryption_context = EncryptionContext::new();
    let _ = decrypt(&decrypt_input).await.unwrap();
}
