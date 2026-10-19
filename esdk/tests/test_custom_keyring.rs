// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A caller-implemented keyring (native `Keyring` trait) driven through the
//! public encrypt/decrypt API.
//!
//! This pins the keyring extension interface and the behavior the ESDK
//! expects from it. If these tests break, a change has likely broken
//! caller-implemented keyrings.
//!
//! Local because a caller's `Keyring` impl is a native trait, unreachable from
//! the cross-language interop vectors.

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::*;

use aws_crypto_mpl::Error as MplError;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput,
};
use aws_crypto_mpl::types::{
    DecryptionMaterials, EncryptedDataKey, EncryptionMaterials, PlaintextDataKey,
};
use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt, generate_random_bytes};

const PROVIDER_ID: &str = "local-test-keyring";
const WRAP_IV_LEN: usize = 12;
const WRAP_TAG_LEN: usize = 16;

/// Caller-implemented keyring. Wraps the data key with AES-256-GCM under a
/// local KEK and stores `iv || ciphertext || tag` as the EDK ciphertext.
#[derive(Clone, Debug)]
struct LocalKekKeyring {
    kek: [u8; 32],
}

impl LocalKekKeyring {
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
            Some(pdk) => {
                let edk = self.wrap(pdk.as_bytes())?;
                materials.add_encrypted_data_key(edk)
            }
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

#[tokio::test(flavor = "multi_thread")]
async fn custom_keyring_round_trips_via_public_api() {
    let keyring = LocalKekKeyring { kek: [7u8; 32] };
    let plaintext = b"extension interface round trip";

    // Encrypt entirely through the custom keyring.
    let out = Client::default()
        .encrypt()
        .plaintext(plaintext)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap();

    // The custom keyring's EDK is serialized into the message header.
    assert!(
        out.ciphertext()
            .windows(PROVIDER_ID.len())
            .any(|w| w == PROVIDER_ID.as_bytes()),
        "header must carry the custom keyring's provider ID"
    );

    // Decrypt back through the same keyring.
    let dec = Client::default()
        .decrypt()
        .ciphertext(out.ciphertext())
        .keyring(keyring)
        .send()
        .await
        .unwrap();
    assert_eq!(dec.plaintext(), plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_keyring_wrong_kek_fails_decrypt() {
    let enc_keyring = LocalKekKeyring { kek: [7u8; 32] };
    let out = Client::default()
        .encrypt()
        .plaintext(b"wrong kek must fail")
        .keyring(enc_keyring)
        .send()
        .await
        .unwrap();

    // A keyring with a different KEK cannot unwrap the data key.
    let wrong_keyring = LocalKekKeyring { kek: [8u8; 32] };
    let err = Client::default()
        .decrypt()
        .ciphertext(out.ciphertext())
        .keyring(wrong_keyring)
        .send()
        .await
        .expect_err("decrypt under a different KEK must fail");
    assert!(
        err.is_cryptographic(),
        "expected the keyring's unwrap failure, got {:?}",
        err
    );
}

/// Builds materials with a plaintext data key half the suite's length,
/// which the materials builders reject.
#[derive(Clone, Debug)]
struct ShortDataKeyKeyring;

#[async_trait]
impl Keyring for ShortDataKeyKeyring {
    fn name(&self) -> std::borrow::Cow<'_, str> {
        "short".into()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        let m = input.into_materials();
        let short = m.algorithm_suite().encryption_key_length() / 2;
        let err = EncryptionMaterials::builder()
            .algorithm_suite_id(m.algorithm_suite_id())
            .encryption_context(m.encryption_context().clone())
            .plaintext_data_key(PlaintextDataKey::new(vec![0; short]))
            .build()
            .expect_err("build must reject a short plaintext data key");
        Err(err)
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        let m = input.into_materials();
        let short = m.algorithm_suite().encryption_key_length() / 2;
        let err = DecryptionMaterials::builder()
            .algorithm_suite_id(m.algorithm_suite_id())
            .encryption_context(m.encryption_context().clone())
            .plaintext_data_key(PlaintextDataKey::new(vec![0; short]))
            .build()
            .expect_err("build must reject a short plaintext data key");
        Err(err)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_data_key_of_the_wrong_length_is_invalid_materials() {
    let err = Client::default()
        .encrypt()
        .plaintext(b"short key")
        .keyring(ShortDataKeyKeyring)
        .send()
        .await
        .expect_err("a short plaintext data key must fail");
    assert!(err.is_invalid_materials(), "{err:?}");
    assert_eq!(
        err.resource(),
        Some(&aws_esdk::error::Resource::Keyring(
            aws_esdk::error::KeyringResource::new("short")
        ))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_decrypt_plaintext_data_key_of_the_wrong_length_is_invalid_materials() {
    let out = Client::default()
        .encrypt()
        .plaintext(b"short key")
        .keyring(LocalKekKeyring { kek: [7u8; 32] })
        .send()
        .await
        .unwrap();
    let err = Client::default()
        .decrypt()
        .ciphertext(out.ciphertext())
        .keyring(ShortDataKeyKeyring)
        .send()
        .await
        .expect_err("a short plaintext data key must fail");
    assert!(err.is_invalid_materials(), "{err:?}");
}
