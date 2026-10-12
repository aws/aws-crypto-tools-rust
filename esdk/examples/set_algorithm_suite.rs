// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts with a chosen algorithm suite instead of the default.
//!
//! The default suite, `AlgAes256GcmHkdfSha512CommitKeyEcdsaP384`, commits to the data key and signs the message.
//! Signing lets a decryptor verify that the message came from someone allowed to encrypt,
//! not just someone allowed to decrypt.
//! When encryptors and decryptors are equally trusted, a suite without signing is faster.
//! This example uses `AlgAes256GcmHkdfSha512CommitKey`, which commits but does not sign.
//!
//! The algorithm suite protects the message with the data key.
//! It is separate from the keyring's wrapping algorithm, which protects the data key.
//!
//! Runs offline.

use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::{AlgorithmSuiteId, EncryptionContext, Esdk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()?;

    let plaintext = b"Hello World";

    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "example");

    let esdk = Esdk::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context.clone())
        .keyring(keyring.clone())
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .send()
        .await?;
    assert_eq!(
        encrypted.algorithm_suite_id,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
    );

    // Decrypt reads the algorithm suite from the message, so it is not set here.
    let decrypted = esdk
        .decrypt()
        .ciphertext(&encrypted.ciphertext)
        .encryption_context(encryption_context)
        .keyring(keyring)
        .send()
        .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encrypted and decrypted with a non-signing algorithm suite.");
    Ok(())
}
