// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a raw AES keyring.

use std::sync::Arc;

use aws_crypto_mpl::{AesGcm, Keyring, RawAesKeyring};
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only: a real application must source its wrapping key from a secure store and never hardcode it.
    let wrapping_key = vec![0x01u8; 32];

    // The namespace and name identify this wrapping key.
    // Decrypt must use a keyring with the same namespace, name, key, and algorithm.
    let keyring: Arc<dyn Keyring> = Arc::new(RawAesKeyring::new(
        "my-key-namespace",
        "my-key-name",
        wrapping_key,
        AesGcm::Aes256Gcm,
    )?);

    let plaintext = b"Hello World";

    let encrypted = encrypt(&EncryptInput::with_keyring(
        plaintext,
        EncryptionContext::new(),
        keyring.clone(),
    ))
    .await?;

    let decrypted = decrypt(&DecryptInput::with_keyring(
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
