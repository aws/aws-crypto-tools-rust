// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a raw AES keyring.

use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only: a real application must source its wrapping key from a secure store and never hardcode it.
    let wrapping_key = vec![0x01u8; 32];

    // The namespace and name identify this wrapping key.
    // Decrypt must use a keyring with the same namespace, name, key, and algorithm.
    let keyring = RawAesKeyring::new(
        "my-key-namespace",
        "my-key-name",
        wrapping_key,
        AesGcm::Aes256Gcm,
    )?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "example");
    encryption_context.insert("is not", "secret");

    let encrypted = encrypt(
        &EncryptInput::builder()
            .plaintext(plaintext)
            .encryption_context(encryption_context.clone())
            .keyring(keyring.clone())
            .build()?,
    )
    .await?;

    // Decrypt fails unless the message's encryption context contains every pair given here.
    let decrypted = decrypt(
        &DecryptInput::builder()
            .ciphertext(&encrypted.ciphertext)
            .encryption_context(encryption_context)
            .keyring(keyring)
            .build()?,
    )
    .await?;

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}
