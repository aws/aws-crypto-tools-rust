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
use test_helpers::{kms_keyring, test_keyring};

// Positive-path round-trip with the same encryption context on encrypt and
// decrypt, using a local raw AES keyring (no network/credentials dependency).
#[tokio::test(flavor = "multi_thread")]
async fn test_encryption_context_on_decrypt() {
    let asdf = "asdf".as_bytes();

    let (namespace, name) = namespace_and_name(0);
    let mpl = mpl();
    let raw_aes_keyring = mpl
        .create_raw_aes_keyring()
        .key_namespace(namespace)
        .key_name(name)
        .wrapping_key(aws_smithy_types::Blob::new([0; 32]))
        .wrapping_alg(aws_mpl_legacy::dafny::types::AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await
        .unwrap();

    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::AB);

    let encrypt_output = encrypt(&EncryptInput::with_legacy_keyring(
        asdf,
        encryption_context.clone(),
        raw_aes_keyring.clone(),
    ))
    .await
    .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext;

    let decrypt_output = decrypt(&DecryptInput::with_legacy_keyring(
        &esdk_ciphertext,
        encryption_context,
        raw_aes_keyring,
    ))
    .await
    .unwrap();

    assert_eq!(decrypt_output.plaintext, asdf);
}

// Mirrors the Dafny TestReproducedEncryptionContext.TestEncryptionContextOnDecryptFailure
// test: a KMS keyring decrypt supplying more reproduced encryption context
// than was used on encrypt must fail.
#[tokio::test(flavor = "multi_thread")]
async fn test_encryption_context_on_decrypt_failure() {
    let asdf = "asdf".as_bytes();

    let kms_keyring = kms_keyring().await;

    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::A);
    let incorrect_reproduced_encryption_context =
        small_encryption_context(SmallEncryptionContextVariation::AB);

    let encrypt_output = encrypt(&EncryptInput::with_legacy_keyring(
        asdf,
        encryption_context,
        kms_keyring.clone(),
    ))
    .await
    .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext;

    // We expect to fail because we pass more encryption context than was used on encrypt.
    let err = decrypt(&DecryptInput::with_legacy_keyring(
        &esdk_ciphertext,
        incorrect_reproduced_encryption_context,
        kms_keyring,
    ))
    .await
    .expect_err(
        "decrypt must fail when reproduced encryption context adds a key not on the message",
    );

    // The reproduced encryption context is passed to KMS on Decrypt, so KMS
    // rejects the data key unwrap for the extra pair.
    let ErrorKind::LegacyError(legacy) = &err.kind else {
        panic!("expected LegacyError, got: {:?}", err.kind);
    };
    let inner = format!("{legacy:?}");
    assert!(
        inner.contains("No Configured KMS Key was able to decrypt the Data Key"),
        "expected KMS data-key unwrap failure, got: {inner}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mismatched_encryption_context_on_decrypt() {
    let asdf = "asdf".as_bytes();

    let (namespace, name) = namespace_and_name(0);
    let mpl = mpl();
    let raw_aes_keyring = mpl
        .create_raw_aes_keyring()
        .key_namespace(namespace)
        .key_name(name)
        .wrapping_key(aws_smithy_types::Blob::new([0; 32]))
        .wrapping_alg(aws_mpl_legacy::dafny::types::AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await
        .unwrap();

    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::A);
    let bad_encryption_context =
        small_mismatched_encryption_context(SmallEncryptionContextVariation::A);

    let encrypt_output = encrypt(&EncryptInput::with_legacy_keyring(
        asdf,
        encryption_context.clone(),
        raw_aes_keyring.clone(),
    ))
    .await
    .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext;

    let mut decrypt_input = DecryptInput::with_legacy_keyring(
        &esdk_ciphertext,
        bad_encryption_context,
        raw_aes_keyring,
    );
    let err = decrypt(&decrypt_input)
        .await
        .expect_err("decrypt must fail when reproduced encryption context has mismatched values");

    // We expect to fail because although the same key is present on the ec,
    // the value is different. The MPL's reproduced-EC validation produces a
    // pinned error message identifying the mechanism.
    let ErrorKind::LegacyError(legacy) = &err.kind else {
        panic!("expected LegacyError, got: {:?}", err.kind);
    };
    let inner = format!("{legacy:?}");
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

// Native counterpart of the Dafny
// TestRequiredEncryptionContext.TestRemoveOnDecryptIsBackwardsCompatibleHappyCase
// test, minus the required encryption context CMM (the native MPL does not
// provide one): a message with all encryption context stored in the header
// decrypts when a strict subset of that context is supplied as reproduced
// encryption context.
#[tokio::test(flavor = "multi_thread")]
async fn test_subset_reproduced_encryption_context_on_decrypt() {
    let asdf = "asdf".as_bytes();

    let raw_aes_keyring = test_keyring().await;

    // All encryption context is stored in the message
    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::AB);
    let subset_reproduced_encryption_context =
        small_encryption_context(SmallEncryptionContextVariation::A);

    let encrypt_output = encrypt(&EncryptInput::with_legacy_keyring(
        asdf,
        encryption_context,
        raw_aes_keyring.clone(),
    ))
    .await
    .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext;

    let decrypt_output = decrypt(&DecryptInput::with_legacy_keyring(
        &esdk_ciphertext,
        subset_reproduced_encryption_context,
        raw_aes_keyring,
    ))
    .await
    .unwrap();

    assert_eq!(decrypt_output.plaintext, asdf);
}
