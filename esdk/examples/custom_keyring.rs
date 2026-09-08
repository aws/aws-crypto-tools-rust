// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A caller-implemented keyring driven through the public encrypt/decrypt API.
//! Runs offline.
//!
//! When the AWS-provided keyrings don't fit your use case, implement the
//! keyring interface yourself. This one wraps each message's data key with
//! AES-256-GCM under a local key-encryption key (KEK), storing
//! `iv || ciphertext || tag` as the encrypted data key.

// The MPL keyring trait returns the large `aws_mpl_legacy` error type by value.
#![allow(clippy::result_large_err)]

use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt};
use aws_mpl_legacy::dafny::operation::on_decrypt::{OnDecryptInput, OnDecryptOutput};
use aws_mpl_legacy::dafny::operation::on_encrypt::{OnEncryptInput, OnEncryptOutput};
use aws_mpl_legacy::dafny::types::error::Error as MplError;
use aws_mpl_legacy::dafny::types::keyring::{Keyring, KeyringRef};
use aws_mpl_legacy::dafny::types::{Encrypt, EncryptedDataKey};
use aws_mpl_legacy::primitives::{AesGcm, aes_decrypt, aes_encrypt, generate_random_bytes};
use aws_smithy_types::Blob;

const PROVIDER_ID: &str = "custom-keyring-example";
const WRAP_IV_LEN: usize = 12;
const WRAP_TAG_LEN: usize = 16;

fn keyring_err(message: &str) -> MplError {
    MplError::AwsCryptographicMaterialProvidersException {
        message: message.to_string(),
    }
}

/// Wraps the data key with AES-256-GCM under a local KEK.
#[derive(Debug)]
struct LocalKekKeyring {
    kek: [u8; 32],
}

impl LocalKekKeyring {
    /// Data key length in bytes, from the algorithm suite in the materials.
    fn key_len(suite_encrypt: Option<&Encrypt>) -> Result<usize, MplError> {
        match suite_encrypt {
            Some(Encrypt::AesGcm(g)) => {
                let bytes = g
                    .key_length
                    .ok_or_else(|| keyring_err("algorithm suite missing key length"))?;
                usize::try_from(bytes).map_err(|_| keyring_err("invalid key length"))
            }
            _ => Err(keyring_err("unsupported encryption algorithm")),
        }
    }
}

impl Keyring for LocalKekKeyring {
    fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        let mut materials = input
            .materials
            .ok_or_else(|| keyring_err("on_encrypt requires materials"))?;

        // Generate a data key when the materials don't carry one yet.
        if materials.plaintext_data_key.is_none() {
            let key_len = Self::key_len(
                materials
                    .algorithm_suite
                    .as_ref()
                    .and_then(|s| s.encrypt.as_ref()),
            )?;
            let mut data_key = vec![0u8; key_len];
            generate_random_bytes(&mut data_key)
                .map_err(|_| keyring_err("failed to generate data key"))?;
            materials.plaintext_data_key = Some(Blob::new(data_key));
        }

        // Wrap the data key under the KEK with a fresh IV.
        let data_key = materials
            .plaintext_data_key
            .as_ref()
            .expect("plaintext data key was just ensured")
            .as_ref()
            .to_vec();
        let mut iv = vec![0u8; WRAP_IV_LEN];
        generate_random_bytes(&mut iv).map_err(|_| keyring_err("failed to generate wrap IV"))?;
        let mut wrapped = Vec::new();
        aes_encrypt(
            AesGcm::Aes256Gcm,
            &iv,
            &self.kek,
            &data_key,
            &[],
            &mut wrapped,
        )
        .map_err(|_| keyring_err("failed to wrap data key"))?;

        // Store `iv || ciphertext || tag` as this keyring's encrypted data key.
        let mut edk_ciphertext = iv;
        edk_ciphertext.extend_from_slice(&wrapped);
        let edk = EncryptedDataKey::builder()
            .key_provider_id(PROVIDER_ID)
            .key_provider_info(Blob::new(b"kek-v1".to_vec()))
            .ciphertext(Blob::new(edk_ciphertext))
            .build()
            .map_err(|_| keyring_err("failed to build EDK"))?;
        materials
            .encrypted_data_keys
            .get_or_insert_with(Vec::new)
            .push(edk);

        OnEncryptOutput::builder()
            .materials(materials)
            .build()
            .map_err(|_| keyring_err("failed to build on_encrypt output"))
    }

    fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        let mut materials = input
            .materials
            .ok_or_else(|| keyring_err("on_decrypt requires materials"))?;

        let key_len = Self::key_len(
            materials
                .algorithm_suite
                .as_ref()
                .and_then(|s| s.encrypt.as_ref()),
        )?;

        // Unwrap the data key from the EDK this keyring produced.
        for edk in input.encrypted_data_keys.unwrap_or_default() {
            if edk.key_provider_id.as_deref() != Some(PROVIDER_ID) {
                continue;
            }
            let blob = edk
                .ciphertext
                .ok_or_else(|| keyring_err("EDK missing ciphertext"))?;
            let bytes = blob.as_ref();
            if bytes.len() != WRAP_IV_LEN + key_len + WRAP_TAG_LEN {
                return Err(keyring_err("EDK ciphertext has unexpected length"));
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
            .map_err(|_| keyring_err("failed to unwrap data key"))?;
            materials.plaintext_data_key = Some(Blob::new(data_key));
            return OnDecryptOutput::builder()
                .materials(materials)
                .build()
                .map_err(|_| keyring_err("failed to build on_decrypt output"));
        }

        Err(keyring_err("no EDK matched this keyring"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only: a real application must source its KEK from a
    // secure store and never hardcode it.
    let keyring = KeyringRef::from(LocalKekKeyring { kek: [0x2Au8; 32] });

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
        "round-trip plaintext must match"
    );
    println!("Success! Custom keyring encrypt/decrypt round trip completed.");
    Ok(())
}
