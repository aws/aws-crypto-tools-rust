// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A keyring decides how each message's data key is protected.
//! AWS provides a set of keyrings that meet most use cases.
//! If your use case is not covered by AWS-provided keyrings, you can implement
//! your own by implementing the [`Keyring`] trait.
//!
//! `LocalKekKeyring` wraps each data key with AES-256-GCM under a local
//! key-encryption key (KEK); the rest of the example uses it like any other keyring.

use aws_crypto_mpl::Keyring;
use aws_crypto_mpl::structures::{
    DecryptionMaterials, EncryptedDataKey, EncryptionMaterials, PlaintextDataKey,
};
use aws_crypto_mpl::{Error as MplError, ErrorKind};
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};
use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt, generate_random_bytes};

/// Identifies this keyring's encrypted data keys inside the message header.
const PROVIDER_ID: &str = "custom-keyring-example";
const WRAP_IV_LEN: usize = 12;
const WRAP_TAG_LEN: usize = 16;

/// A caller-implemented keyring. Wraps the data key with AES-256-GCM under a
/// local KEK and stores `iv || ciphertext || tag` as the EDK ciphertext.
#[derive(Clone, Debug)]
struct LocalKekKeyring {
    kek: [u8; 32],
}

impl LocalKekKeyring {
    /// Wrap `data_key` under the KEK with a fresh IV, as this keyring's EDK.
    fn wrap(&self, data_key: &[u8]) -> Result<EncryptedDataKey, MplError> {
        let mut iv = vec![0u8; WRAP_IV_LEN];
        generate_random_bytes(&mut iv).map_err(|e| {
            MplError::with_cause(ErrorKind::Cryptographic, "failed to generate wrap IV", e)
        })?;
        let mut wrapped = Vec::new();
        aes_encrypt(
            AesGcm::Aes256Gcm,
            &iv,
            &self.kek,
            data_key,
            &[],
            &mut wrapped,
        )
        .map_err(|e| {
            MplError::with_cause(ErrorKind::Cryptographic, "failed to wrap data key", e)
        })?;

        let mut edk_ciphertext = iv;
        edk_ciphertext.extend_from_slice(&wrapped);
        EncryptedDataKey::builder()
            .key_provider_id(PROVIDER_ID)
            .key_provider_info(b"kek-v1")
            .ciphertext(edk_ciphertext)
            .build()
    }
}

#[async_trait::async_trait]
impl Keyring for LocalKekKeyring {
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MplError> {
        match materials.plaintext_data_key() {
            // Another keyring already generated the data key: wrap it and add our EDK.
            Some(pdk) => {
                let edk = self.wrap(pdk.as_bytes())?;
                materials.add_encrypted_data_key(edk)
            }
            // No data key yet: generate one, wrap it, and add both.
            None => {
                let mut data_key = vec![0u8; materials.algorithm_suite().encryption_key_length()];
                generate_random_bytes(&mut data_key).map_err(|e| {
                    MplError::with_cause(ErrorKind::Cryptographic, "failed to generate data key", e)
                })?;
                let edk = self.wrap(&data_key)?;
                materials.add_data_key(PlaintextDataKey::new(data_key), edk)
            }
        }
    }

    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MplError> {
        if materials.plaintext_data_key().is_some() {
            return Err(MplError::new(
                ErrorKind::InvalidMaterials,
                "on_decrypt requires materials without a plaintext data key",
            ));
        }

        // Data key length in bytes, from the algorithm suite in the materials.
        let key_len = materials.algorithm_suite().encryption_key_length();

        // Unwrap the data key from the EDK this keyring produced.
        for edk in encrypted_data_keys {
            if edk.key_provider_id() != PROVIDER_ID {
                continue;
            }
            let bytes = edk.ciphertext();
            if bytes.len() != WRAP_IV_LEN + key_len + WRAP_TAG_LEN {
                return Err(MplError::new(
                    ErrorKind::Cryptographic,
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
            .map_err(|e| {
                MplError::with_cause(ErrorKind::Cryptographic, "failed to unwrap data key", e)
            })?;
            return materials.add_data_key(PlaintextDataKey::new(data_key));
        }

        Err(MplError::new(
            ErrorKind::NoMatchingDataKey,
            "no EDK matched this keyring",
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only: a real application must source its KEK from a secure store and never hardcode it.
    let keyring = LocalKekKeyring { kek: [0x2A; 32] };

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
