// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a raw AES keyring.

use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt, mpl};
use aws_mpl_legacy::dafny::types::AesWrappingAlg;
use aws_smithy_types::Blob;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only: a real application must source its wrapping key from a secure store and never hardcode it.
    let wrapping_key = [0x01u8; 32];

    // The namespace and name identify this wrapping key.
    // Decrypt must use a keyring with the same namespace, name, key, and algorithm.
    let keyring = mpl()
        .create_raw_aes_keyring()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(Blob::new(wrapping_key))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await?;

    let plaintext = b"Hello World";

    let encrypted = encrypt(&EncryptInput::with_legacy_keyring(
        plaintext,
        EncryptionContext::new(),
        keyring.clone(),
    ))
    .await?;

    let decrypted = decrypt(&DecryptInput::with_legacy_keyring(
        &encrypted.ciphertext,
        EncryptionContext::new(),
        keyring,
    ))
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}
