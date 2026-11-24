// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone consumer of `aws-esdk` that runs one encrypt/decrypt round-trip.
//!
//! A clean run proves the released crate builds against its published
//! dependencies and that its core encrypt/decrypt API works. The raw-AES
//! keyring keeps the round-trip local: no AWS credentials or network calls.

use aws_esdk::keyring::RawAesKeyring;
use aws_esdk::types::AesWrappingAlg;

#[tokio::main]
async fn main() {
    let plaintext: &[u8] = b"aws-esdk git-to-Brazil release smoke test";

    let keyring = RawAesKeyring::builder()
        .key_namespace("aws-esdk-release-smoke-test")
        .key_name("smoke-test-key")
        .wrapping_key(vec![0u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .expect("build raw AES keyring");

    let esdk = aws_esdk::Client::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await
        .expect("encrypt");
    let ciphertext = encrypted.ciphertext();

    let decrypted = esdk
        .decrypt()
        .ciphertext(ciphertext)
        .keyring(keyring)
        .send()
        .await
        .expect("decrypt");

    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "round-trip plaintext mismatch"
    );

    println!(
        "OK: aws-esdk encrypt/decrypt round-trip succeeded ({} ciphertext bytes)",
        ciphertext.len()
    );
}
