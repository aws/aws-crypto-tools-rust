// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines a custom keyring by implementing the [`Keyring`] trait.
//!
//! `RequireContextKeyring` wraps a raw AES keyring and refuses any message
//! whose encryption context lacks a `department` key.
//!
//! Runs offline.

use aws_crypto_mpl::keyring::{OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use aws_crypto_mpl::{AesGcm, Error as MplError, Keyring, RawAesKeyring, async_trait};
use aws_esdk::error::Error;
use aws_esdk::{EncryptionContext, Esdk};

/// The encryption context key every message must carry.
const REQUIRED_KEY: &str = "department";

#[derive(Clone)]
struct RequireContextKeyring {
    inner: RawAesKeyring,
}

fn check(encryption_context: &EncryptionContext) -> Result<(), MplError> {
    if encryption_context.contains_key(REQUIRED_KEY) {
        Ok(())
    } else {
        Err(MplError::validation(format!(
            "the encryption context must contain {REQUIRED_KEY:?}"
        )))
    }
}

#[async_trait]
impl Keyring for RequireContextKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        check(input.materials().encryption_context())?;
        Keyring::on_encrypt(&self.inner, input).await
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        check(input.materials().encryption_context())?;
        Keyring::on_decrypt(&self.inner, input).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let inner = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x2A; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()?;
    let keyring = RequireContextKeyring { inner };

    let plaintext = b"Hello World";

    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("department", "finance");

    let esdk = Esdk::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .encryption_context(encryption_context.clone())
        .keyring(keyring.clone())
        .send()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(&encrypted.ciphertext)
        .encryption_context(encryption_context)
        .keyring(keyring.clone())
        .send()
        .await?;
    assert_eq!(
        decrypted.plaintext, plaintext,
        "Decryption failed: plaintext mismatch"
    );

    // The keyring refuses a message without a `department` key.
    let refused = esdk
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring)
        .send()
        .await;
    assert!(
        matches!(refused, Err(Error::Validation(_))),
        "the keyring accepted a message without a department"
    );

    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}
