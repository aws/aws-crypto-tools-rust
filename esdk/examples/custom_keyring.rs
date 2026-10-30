// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines a custom keyring by implementing the [`Keyring`] trait.
//!
//! `AuditKeyring` wraps a raw AES keyring and logs which key providers each call uses.
//!
//! Runs offline.

use aws_esdk::async_trait;
use aws_esdk::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput, RawAesKeyring,
};
use aws_esdk::mpl::Error as MplError;
use aws_esdk::mpl::types::EncryptedDataKey;
use aws_esdk::types::{AesWrappingAlg, EncryptionContext};

/// Wraps another keyring and logs the key providers of the encrypted data keys each call writes or tries.
#[derive(Clone)]
struct AuditKeyring {
    inner: RawAesKeyring,
}

fn providers(edks: &[EncryptedDataKey]) -> Vec<&str> {
    edks.iter().map(EncryptedDataKey::key_provider_id).collect()
}

#[async_trait]
impl Keyring for AuditKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        let output = self
            .inner
            .on_encrypt()
            .materials(input.into_materials())
            .send()
            .await?;
        println!(
            "audit: encrypt wrote data keys for {:?}",
            providers(output.materials().encrypted_data_keys())
        );
        Ok(output)
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        println!(
            "audit: decrypt tried data keys from {:?}",
            providers(input.encrypted_data_keys())
        );
        {
            let (materials, encrypted_data_keys) = input.into_parts();
            self.inner
                .on_decrypt()
                .materials(materials)
                .set_encrypted_data_keys(Some(encrypted_data_keys))
                .send()
        }
        .await
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
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;
    let keyring = AuditKeyring { inner };

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context = EncryptionContext::from([("purpose", "example")]);

    let esdk = aws_esdk::Client::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(keyring.clone())
        .send()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(keyring)
        .send()
        .await?;
    assert_eq!(
        decrypted.plaintext(),
        plaintext,
        "Decryption failed: plaintext mismatch"
    );

    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}
