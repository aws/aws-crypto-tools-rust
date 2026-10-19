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

    let esdk = Client::default();
    let encrypt_output = esdk
        .encrypt()
        .plaintext(asdf)
        .encryption_context(encryption_context.clone())
        .keyring(raw_aes_keyring.clone())
        .send()
        .await
        .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext();

    let decrypt_output = esdk
        .decrypt()
        .ciphertext(esdk_ciphertext)
        .encryption_context(encryption_context)
        .keyring(raw_aes_keyring)
        .send()
        .await
        .unwrap();

    assert_eq!(decrypt_output.plaintext(), asdf);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mismatched_encryption_context_on_decrypt() {
    let asdf = "asdf".as_bytes();

    let raw_aes_keyring = test_keyring().await;

    let encryption_context = small_encryption_context(SmallEncryptionContextVariation::A);
    let bad_encryption_context =
        small_mismatched_encryption_context(SmallEncryptionContextVariation::A);

    let esdk = Client::default();
    let encrypt_output = esdk
        .encrypt()
        .plaintext(asdf)
        .encryption_context(encryption_context.clone())
        .keyring(raw_aes_keyring.clone())
        .send()
        .await
        .unwrap();

    let esdk_ciphertext = encrypt_output.ciphertext();

    let decrypt_builder = esdk
        .decrypt()
        .ciphertext(esdk_ciphertext)
        .keyring(raw_aes_keyring);
    let err = decrypt_builder
        .clone()
        .encryption_context(bad_encryption_context)
        .send()
        .await
        .expect_err("decrypt must fail when reproduced encryption context has mismatched values");

    // Same key, different value.
    assert!(
        err.is_encryption_context_mismatch(),
        "expected EncryptionContextMismatch, got: {:?}",
        err
    );
    let source = std::error::Error::source(&err)
        .and_then(|e| e.downcast_ref::<aws_crypto_mpl::Error>())
        .expect("the MPL error is the source");
    assert!(source.is_encryption_context_mismatch(), "{:?}", source);
    //= spec/client-apis/decrypt.md#get-the-decryption-materials
    //= type=test
    //= reason=Mismatched reproduced EC value fails the MPL reproduced-EC check with EncryptionContextMismatch, proving the reproduced EC was used
    //# - Reproduced Encryption Context: This MUST be the [input](#input) encryption context.

    // Test that if we supply the right ec we will succeed.
    let _ = decrypt_builder
        .clone()
        .encryption_context(encryption_context)
        .send()
        .await
        .unwrap();

    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# - Decrypt operation input MUST accept an optional [Encryption Context](#encryption-context) argument.
    let _ = decrypt_builder.send().await.unwrap();
}
