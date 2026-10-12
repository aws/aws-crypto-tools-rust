// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines a custom keyring by implementing the [`Keyring`] trait.
//!
//! `LocalKekKeyring` wraps each message's data key with AES-256-GCM under a local key-encryption key (KEK).
//! `encrypt` and `decrypt` then use it like any other keyring.
//!
//! Runs offline.

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::Keyring;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::keyring::{OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use aws_crypto_mpl::structures::{EncryptedDataKey, PlaintextDataKey};
use aws_esdk::{EncryptionContext, Esdk};
use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt, generate_random_bytes};

/// Identifies this keyring's encrypted data keys inside the message header.
const PROVIDER_ID: &str = "custom-keyring-example";
const WRAP_IV_LEN: usize = 12;
const WRAP_TAG_LEN: usize = 16;

/// Wraps the data key with AES-256-GCM under a local KEK.
/// Each EDK's ciphertext is `iv || ciphertext || tag`.
#[derive(Clone, Debug)]
struct LocalKekKeyring {
    kek: [u8; 32],
}

impl LocalKekKeyring {
    /// Wraps `data_key` under the KEK with a fresh random IV.
    fn wrap(&self, data_key: &[u8]) -> Result<EncryptedDataKey, MplError> {
        let mut iv = vec![0u8; WRAP_IV_LEN];
        generate_random_bytes(&mut iv)
            .map_err(|e| MplError::cryptographic("failed to generate wrap IV").with_source(e))?;
        let mut wrapped = Vec::new();
        aes_encrypt(
            AesGcm::Aes256Gcm,
            &iv,
            &self.kek,
            data_key,
            &[],
            &mut wrapped,
        )
        .map_err(|e| MplError::cryptographic("failed to wrap data key").with_source(e))?;

        let mut edk_ciphertext = iv;
        edk_ciphertext.extend_from_slice(&wrapped);
        EncryptedDataKey::builder()
            .key_provider_id(PROVIDER_ID)
            .key_provider_info(b"kek-v1")
            .ciphertext(edk_ciphertext)
            .build()
    }
}

#[async_trait]
impl Keyring for LocalKekKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        let materials = input.into_materials();
        let materials = match materials.plaintext_data_key() {
            // Another keyring already generated the data key: wrap it and add our EDK.
            Some(pdk) => {
                let edk = self.wrap(pdk.as_bytes())?;
                materials.add_encrypted_data_key(edk)
            }
            // No data key yet: generate one, wrap it, and add both.
            None => {
                let mut data_key = vec![0u8; materials.algorithm_suite().encryption_key_length()];
                generate_random_bytes(&mut data_key).map_err(|e| {
                    MplError::cryptographic("failed to generate data key").with_source(e)
                })?;
                let edk = self.wrap(&data_key)?;
                materials.add_data_key(PlaintextDataKey::new(data_key), edk)
            }
        }?;
        Ok(materials.into())
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        let (materials, encrypted_data_keys) = input.into_parts();
        if materials.plaintext_data_key().is_some() {
            return Err(MplError::invalid_materials(
                "on_decrypt requires materials without a plaintext data key",
            ));
        }

        let key_len = materials.algorithm_suite().encryption_key_length();

        for edk in &encrypted_data_keys {
            // Skip EDKs written by other keyrings.
            if edk.key_provider_id() != PROVIDER_ID {
                continue;
            }
            let bytes = edk.ciphertext();
            if bytes.len() != WRAP_IV_LEN + key_len + WRAP_TAG_LEN {
                return Err(MplError::cryptographic(
                    "EDK ciphertext has unexpected length",
                ));
            }
            let (iv, rest) = bytes.split_at(WRAP_IV_LEN);
            let (wrapped_key, tag) = rest.split_at(key_len);
            let mut data_key = vec![0u8; key_len];
            aes_decrypt(
                AesGcm::Aes256Gcm,
                &self.kek,
                wrapped_key,
                tag,
                iv,
                &[],
                &mut data_key,
            )
            .map_err(|e| MplError::cryptographic("failed to unwrap data key").with_source(e))?;
            return Ok(materials
                .add_data_key(PlaintextDataKey::new(data_key))?
                .into());
        }

        Err(MplError::no_matching_data_key(
            "no EDK matched this keyring",
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its KEK from a secure store, never hardcode it.
    let keyring = LocalKekKeyring { kek: [0x2A; 32] };

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
    println!("Success! Encryption and decryption completed successfully.");
    Ok(())
}
