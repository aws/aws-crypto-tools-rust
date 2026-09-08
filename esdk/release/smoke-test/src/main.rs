// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone consumer of `aws-esdk` that runs one encrypt/decrypt round-trip.
//!
//! A clean run proves the released crate builds against its published
//! dependencies and that its core encrypt/decrypt API works. The raw-AES
//! keyring keeps the round-trip local: no AWS credentials or network calls.

use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt, mpl};
use aws_mpl_legacy::dafny::types::AesWrappingAlg;
use aws_smithy_types::Blob;

#[tokio::main]
async fn main() {
    let plaintext: &[u8] = b"aws-esdk git-to-Brazil release smoke test";

    let keyring = mpl()
        .create_raw_aes_keyring()
        .key_namespace("aws-esdk-release-smoke-test".to_string())
        .key_name("smoke-test-key".to_string())
        .wrapping_key(Blob::new([0u8; 32]))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await
        .expect("build raw AES keyring");

    let encryption_context = EncryptionContext::new();

    let ciphertext = encrypt(&EncryptInput::with_legacy_keyring(
        plaintext,
        encryption_context.clone(),
        keyring.clone(),
    ))
    .await
    .expect("encrypt")
    .ciphertext;

    let decrypted = decrypt(&DecryptInput::with_legacy_keyring(
        &ciphertext,
        encryption_context,
        keyring,
    ))
    .await
    .expect("decrypt")
    .plaintext;

    assert_eq!(decrypted, plaintext, "round-trip plaintext mismatch");

    println!(
        "OK: aws-esdk encrypt/decrypt round-trip succeeded ({} ciphertext bytes)",
        ciphertext.len()
    );
}
