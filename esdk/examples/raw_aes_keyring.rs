// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts and decrypts a message with a raw AES keyring.
//!
//! Runs offline.

use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::error::Error;
use aws_esdk::{EncryptionContext, Esdk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let wrapping_key = vec![0x01u8; 32];

    // The namespace and name identify this wrapping key.
    // Decrypt must use a keyring with the same namespace, name, key, and algorithm.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(wrapping_key)
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "example");
    encryption_context.insert("is not", "secret");

    let esdk = Esdk::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context.clone())
        .keyring(keyring.clone())
        .send()
        .await?;

    let result = esdk
        .decrypt()
        .ciphertext(&encrypted.ciphertext)
        .encryption_context(encryption_context)
        .keyring(keyring)
        .send()
        .await;
    let decrypted = match result {
        Ok(output) => output,
        Err(e) => {
            match &e {
                Error::NoMatchingDataKey(_) => {
                    eprintln!("the message was encrypted under a different keyring");
                }
                Error::Cryptographic(_) | Error::Serialization(_) => {
                    eprintln!("the message is corrupt or was tampered with");
                }
                _ => eprintln!("decrypt failed: {e}"),
            }
            return Err(e.into());
        }
    };

    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}
