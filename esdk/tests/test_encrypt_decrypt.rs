// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::{EncryptionContext, Esdk};
use std::num::NonZeroU32;
use test_helpers::test_keyring;

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_decrypt() {
    let keyring = test_keyring().await;
    let esdk = Esdk::default();
    let plaintext = b"hello esdk";
    let ec = EncryptionContext::new();

    //= spec/client-apis/client.md#encrypt
    //= type=test
    //# The AWS Encryption SDK Client MUST provide an [encrypt](./encrypt.md#input) function
    //# that adheres to [encrypt](./encrypt.md).
    let encrypt_output = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();

    //= spec/client-apis/client.md#decrypt
    //= type=test
    //# The AWS Encryption SDK Client MUST provide an [decrypt](./decrypt.md#input) function
    //# that adheres to [decrypt](./decrypt.md).
    let decrypt_output = esdk
        .decrypt()
        .ciphertext(&encrypt_output.ciphertext)
        .encryption_context(ec)
        .keyring(keyring)
        .send()
        .await
        .unwrap();

    assert_eq!(decrypt_output.plaintext, plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bad_decrypt_input() {
    let result = Esdk::default().decrypt().ciphertext(b"").send().await;

    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# The Decrypt operation MUST validate that exactly one of a keyring or CMM was provided by the caller.
    //
    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# If the caller does not provide exactly one of a keyring or CMM, the Decrypt operation MUST fail.
    let err = result.expect_err("decrypt must fail when no keyring or CMM is set");
    assert!(
        err.is_validation(),
        "expected Validation error, got {:?}",
        err
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_decrypt_short() {
    let keyring = test_keyring().await;
    let esdk = Esdk::default();
    let plaintext = b"hello esdk";
    let ec = EncryptionContext::new();
    let esdk_ciphertext = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(ec.clone())
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .ciphertext;
    let cipher_len: usize = esdk_ciphertext.len();
    // Truncate the last byte of the ciphertext. For the default signing suite this
    // chops off the final byte of the footer signature, so decrypt fails with a Serialization error.
    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //= reason=Truncating the ciphertext's last byte makes footer deserialization fail; decrypt MUST halt with an error
    //# - If all bytes have been provided and this operation
    //# is unable to complete the above steps with the consumable encrypted message bytes,
    //# this operation MUST halt and indicate a failure to the caller.
    let err = esdk
        .decrypt()
        .ciphertext(&esdk_ciphertext[..cipher_len - 1])
        .encryption_context(ec)
        .keyring(keyring)
        .send()
        .await
        .expect_err("truncated ciphertext must fail decrypt");
    assert!(
        err.is_serialization(),
        "truncated ciphertext must produce a Serialization error, got: {:?} ({})",
        err,
        err.message()
    );
}

// Proves that an encryption context provided at encrypt time round-trips:
// the (key, value) pair appears in DecryptOutput.encryption_context.
#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_decrypt_ec() {
    let keyring = test_keyring().await;
    let esdk = Esdk::default();
    let plaintext = b"hello esdk";
    let encryption_context = fixtures::ec_of(&[("stuff", "junk")]);
    let esdk_ciphertext = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .ciphertext;
    let decrypt_output = esdk
        .decrypt()
        .ciphertext(&esdk_ciphertext)
        .encryption_context(EncryptionContext::new())
        .keyring(keyring)
        .send()
        .await
        .unwrap();

    assert_eq!(decrypt_output.plaintext, plaintext);
    assert_eq!(
        decrypt_output.encryption_context.get("stuff"),
        Some("junk"),
        "input EC pair (stuff, junk) must round-trip to the decrypt output, got: {:?}",
        decrypt_output.encryption_context
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_decrypt_bad_ec() {
    let keyring = test_keyring().await;
    let plaintext = b"hello esdk";
    let encryption_context = fixtures::ec_of(&[("aws-crypto-stuff", "junk")]);
    let encrypt_output = Esdk::default()
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context)
        .keyring(keyring)
        .send()
        .await;

    //= spec/client-apis/encrypt.md#encryption-context
    //= type=test
    //# If the input encryption context contains any entries with a key beginning with `aws-crypto-`,
    //# the encryption operation MUST fail.
    let err = encrypt_output.expect_err("encrypt must fail for aws-crypto- EC key");
    assert!(
        err.is_validation(),
        "expected Validation error for reserved 'aws-crypto-' prefix, got: {:?} ({})",
        err,
        err.message()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bad_encrypt_input() {
    let result = Esdk::default()
        .encrypt()
        .plaintext(b"hello esdk")
        .send()
        .await;

    //= spec/client-apis/encrypt.md#input
    //= type=test
    //# The Encrypt operation MUST validate that exactly one keyring or CMM was provided by the caller.
    //
    //= spec/client-apis/encrypt.md#input
    //= type=test
    //# If the caller does not provide exactly one of a keyring or CMM, the Encrypt operation MUST fail.
    let err = result.expect_err("encrypt must fail when no keyring or CMM is set");
    assert!(
        err.is_validation(),
        "expected Validation error, got {:?}",
        err
    );
}

// Sweeps frame_length from 4 (multi-frame) up to plaintext.len() (single
// full frame), round-tripping at each length to confirm encrypt+decrypt
// agree across both frame-count regimes.
#[tokio::test(flavor = "multi_thread")]
async fn test_encrypt_decrypt_varied_frame_lengths() {
    let keyring = test_keyring().await;
    let esdk = Esdk::default();
    let plaintext = "0123456789abcdef".as_bytes();
    let ec = EncryptionContext::new();
    for i in 4..=plaintext.len() {
        let frame_length =
            NonZeroU32::new(u32::try_from(i).expect("frame length fits u32")).unwrap();
        let esdk_ciphertext = esdk
            .encrypt()
            .plaintext(plaintext)
            .encryption_context(ec.clone())
            .keyring(keyring.clone())
            .frame_length(frame_length)
            .send()
            .await
            .unwrap_or_else(|e| panic!("encrypt failed (frame_len={i}): {e:?}"))
            .ciphertext;
        let decrypt_output = esdk
            .decrypt()
            .ciphertext(&esdk_ciphertext)
            .encryption_context(ec.clone())
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap_or_else(|e| panic!("decrypt failed (frame_len={i}): {e:?}"));
        assert_eq!(
            decrypt_output.plaintext, plaintext,
            "round-trip mismatch at frame_len={i}"
        );
    }
}
