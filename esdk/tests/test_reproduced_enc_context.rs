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

    let encrypt_output = encrypt(
        &EncryptInput::builder()
            .plaintext(asdf)
            .encryption_context(encryption_context.clone())
            .keyring(raw_aes_keyring.clone())
            .build()
            .unwrap(),
    )
    .await
    .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext;

    let decrypt_output = decrypt(
        &DecryptInput::builder()
            .ciphertext(&esdk_ciphertext)
            .encryption_context(encryption_context)
            .keyring(raw_aes_keyring)
            .build()
            .unwrap(),
    )
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

    let encrypt_output = encrypt(
        &EncryptInput::builder()
            .plaintext(asdf)
            .encryption_context(encryption_context.clone())
            .keyring(raw_aes_keyring.clone())
            .build()
            .unwrap(),
    )
    .await
    .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext;

    let decrypt_builder = DecryptInput::builder()
        .ciphertext(&esdk_ciphertext)
        .keyring(raw_aes_keyring);
    let decrypt_input = decrypt_builder
        .clone()
        .encryption_context(bad_encryption_context)
        .build()
        .unwrap();
    let err = decrypt(&decrypt_input)
        .await
        .expect_err("decrypt must fail when reproduced encryption context has mismatched values");

    // We expect to fail because although the same key is present on the ec,
    // the value is different. The MPL's reproduced-EC validation produces a
    // pinned error message identifying the mechanism.
    assert_eq!(
        err.kind(),
        ErrorKind::EncryptionContextMismatch,
        "expected EncryptionContextMismatch, got: {:?}",
        err.kind()
    );
    let inner = std::error::Error::source(&err)
        .map(ToString::to_string)
        .unwrap_or_default();
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Mismatched reproduced EC value triggers MPL "does not match reproduced encryption context" error, proving the reproduced EC was used
    //# - Reproduced Encryption Context: This MUST be the [input](#input) encryption context.
    assert!(
        inner.contains("does not match reproduced encryption context"),
        "expected reproduced-EC mismatch error, got: {inner}"
    );

    // Test that if we supply the right ec we will succeed.
    let decrypt_input = decrypt_builder
        .clone()
        .encryption_context(encryption_context)
        .build()
        .unwrap();
    let _ = decrypt(&decrypt_input).await.unwrap();

    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# - Decrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
    let decrypt_input = decrypt_builder.build().unwrap();
    let _ = decrypt(&decrypt_input).await.unwrap();
}
