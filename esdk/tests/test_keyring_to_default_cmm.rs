// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for keyring-to-default-CMM requirements:
//! - spec/client-apis/decrypt.md#keyring
//! - spec/client-apis/encrypt.md#get-the-encryption-materials
//!
//! Strategy: a black-box round-trip with a keyring proves nothing about *which*
//! CMM was constructed — any working CMM that wraps the keyring would pass. To
//! actually prove "the keyring path constructs a default CMM (not some other
//! CMM)," each test below exercises *cross-compatibility*: encrypt under one
//! path (e.g. an explicit default CMM constructed independently) and decrypt
//! under the other (the keyring → default-CMM-internal path). If the keyring
//! path constructed any CMM other than the default-CMM-of-K, the materials
//! would diverge and the cross-decrypt would fail.
//!
//! This is the strongest property we can assert without a spy on the CMM
//! construction in `materials.rs` — the MPL doesn't expose a way to ask a
//! CMM "are you the default CMM?" at runtime.
//!

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_crypto_mpl::Error as MplError;
use aws_esdk::*;
use std::error::Error as _;
use test_helpers::*;

/// Helper: independently construct a default CMM from a keyring via the MPL.
/// Mirrors the call in `materials.rs::create_cmm_from_input` for the
/// keyring arm.
fn default_cmm_from(
    keyring: aws_crypto_mpl::keyring::RawAesKeyring,
) -> aws_crypto_mpl::cmm::DefaultCmm {
    aws_crypto_mpl::cmm::DefaultCmm::new(keyring)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_keyring_constructs_default_cmm_for_decrypt() {
    // Cross-compat: encrypt with an *explicit* default CMM built from K, then
    // decrypt with K alone. If decrypt's keyring path constructed any CMM
    // other than `create_default_cryptographic_materials_manager(K)`, the
    // decryption materials would diverge and decrypt would fail.
    let keyring = test_keyring().await;
    let pt = b"keyring constructs default cmm for decrypt";
    let mut ec = EncryptionContext::new();
    ec.insert("purpose", "keyring-cmm-test");

    let default_cmm = default_cmm_from(keyring.clone());
    let enc_input = EncryptInput::builder()
        .plaintext(pt)
        .encryption_context(ec.clone())
        .cmm(default_cmm)
        .build()
        .unwrap();
    let ct = encrypt(&enc_input)
        .await
        .expect("encrypt with explicit default CMM must succeed");

    let dec_input = DecryptInput::builder()
        .ciphertext(&ct.ciphertext)
        .encryption_context(ec)
        .keyring(keyring)
        .build()
        .unwrap();
    //= spec/client-apis/decrypt.md#keyring
    //= type=test
    //= reason=Ciphertext encrypted under an explicit default CMM decrypts under the keyring path; a different CMM would diverge on materials
    //# If the Keyring is provided as the input, the client MUST construct a [default CMM](../framework/default-cmm.md) that uses this keyring,
    //# to obtain the [decryption materials](../framework/structures.md#decryption-materials) that is required for decryption.
    //
    //= spec/client-apis/decrypt.md#keyring
    //= type=test
    //= reason=The keyring path obtains decryption materials for the explicit-default-CMM ciphertext, proving the materials path matches
    //# This default CMM constructed from the keyring MUST obtain the decryption materials required for decryption.
    let result = decrypt(&dec_input)
        .await
        .expect("decrypt with keyring must succeed on explicit-default-CMM ciphertext");
    assert_eq!(result.plaintext, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_keyring_constructs_default_cmm_for_encrypt() {
    // Cross-compat (other direction): encrypt with K alone (exercising the
    // encrypt-side keyring → default-CMM path), then decrypt with an
    // *explicit* default CMM built from K. If encrypt's keyring path
    // constructed any CMM other than the default-CMM-of-K, the explicit
    // default CMM would not be able to decrypt the message.
    let keyring = test_keyring().await;
    let pt = b"keyring constructs default cmm for encrypt";
    let ec = EncryptionContext::new();

    let enc_input = EncryptInput::builder()
        .plaintext(pt)
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let ct = encrypt(&enc_input)
        .await
        .expect("encrypt with keyring must succeed");

    let default_cmm = default_cmm_from(keyring);
    let dec_input = DecryptInput::builder()
        .ciphertext(&ct.ciphertext)
        .encryption_context(ec)
        .cmm(default_cmm)
        .build()
        .unwrap();
    //= spec/client-apis/encrypt.md#get-the-encryption-materials
    //= type=test
    //= reason=Ciphertext produced via the keyring path decrypts under an explicit default CMM, proving the encrypt-side path constructs a default CMM
    //# If instead the caller supplied a [keyring](../framework/keyring-interface.md),
    //# this behavior MUST use a [default CMM](../framework/default-cmm.md)
    //# constructed using the caller-supplied keyring as input.
    let result = decrypt(&dec_input)
        .await
        .expect("decrypt with explicit default CMM must succeed on keyring-encrypted ciphertext");
    assert_eq!(result.plaintext, pt);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_fails_with_wrong_keyring() {
    // Negative: a keyring whose key material differs from the encrypt-side
    // keyring cannot unwrap any EDK in the message. Exercises the failure
    // mode of the keyring → default-CMM path.
    let keyring = test_keyring().await;
    let pt = b"negative test keyring to default cmm";
    let enc_input = EncryptInput::builder()
        .plaintext(pt)
        .keyring(keyring)
        .build()
        .unwrap();
    let ct = encrypt(&enc_input).await.unwrap().ciphertext;

    let wrong_keyring = aes_keyring(1).await;
    let dec_input = DecryptInput::builder()
        .ciphertext(&ct)
        .keyring(wrong_keyring)
        .build()
        .unwrap();
    let result = decrypt(&dec_input).await;
    let err = result.expect_err(
        "decrypt must fail when default CMM cannot obtain decryption materials with wrong keyring",
    );
    assert!(
        err.is_no_matching_data_key(),
        "expected NoMatchingDataKey, got: {:?}",
        err
    );
    // Assert the MPL's typed error kind, not its message.
    let cause = err
        .source()
        .expect("the MPL error is the source")
        .downcast_ref::<MplError>()
        .expect("the source is an aws_crypto_mpl::Error");
    assert!(
        cause.is_no_matching_data_key(),
        "wrong keyring must fail with NoMatchingDataKey, got: {cause:?}"
    );
}
