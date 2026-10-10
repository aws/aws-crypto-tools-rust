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
use aws_crypto_mpl::structures::{
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

#[async_trait]
impl Keyring for LocalKekKeyring {
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        let materials = input.materials();

        // Data key length in bytes, from the algorithm suite in the materials.
        let key_len = materials.algorithm_suite().encryption_key_length();

        // Reuse the existing data key, or generate one when absent.
        let data_key = match materials.plaintext_data_key() {
            Some(pdk) => pdk.as_bytes().to_vec(),
            None => {
                let mut dk = vec![0u8; key_len];
                generate_random_bytes(&mut dk).map_err(|e| {
                    MplError::from(
                        aws_crypto_mpl::error::CryptographicError::new(
                            "failed to generate data key",
                        )
                        .with_source(e),
                    )
                })?;
                dk
            }
        };

        // Wrap the data key under the KEK with a fresh IV.
        let mut iv = vec![0u8; WRAP_IV_LEN];
        generate_random_bytes(&mut iv).map_err(|e| {
            MplError::from(
                aws_crypto_mpl::error::CryptographicError::new("failed to generate wrap IV")
                    .with_source(e),
            )
        })?;
        let mut wrapped = Vec::new();
        aes_encrypt(
            AesGcm::Aes256Gcm,
            &iv,
            &self.kek,
            &data_key,
            &[],
            &mut wrapped,
        )
        .map_err(|e| {
            MplError::from(
                aws_crypto_mpl::error::CryptographicError::new("failed to wrap data key")
                    .with_source(e),
            )
        })?;

        // Append the wrapped key to the materials as this keyring's EDK.
        let mut edk_ciphertext = iv;
        edk_ciphertext.extend_from_slice(&wrapped);
        let edk = EncryptedDataKey::builder()
            .key_provider_id(PROVIDER_ID.to_string())
            .key_provider_info(b"kek-v1")
            .ciphertext(edk_ciphertext)
            .build()
            .unwrap();

        let mut new_edks = materials.encrypted_data_keys().to_vec();
        new_edks.push(edk);

        // Rebuild the materials with the data key set and our EDK appended,
        // cloning the remaining fields through the accessors.
        let materials = EncryptionMaterials::builder()
            .algorithm_suite_id(materials.algorithm_suite_id())
            .encrypted_data_keys(new_edks)
            .encryption_context(materials.encryption_context().clone())
            .required_encryption_context_keys(materials.required_encryption_context_keys().clone())
            .plaintext_data_key(PlaintextDataKey::new(data_key))
            .set_signing_key(materials.signing_key().cloned())
            .set_symmetric_signing_keys(materials.symmetric_signing_keys().map(<[_]>::to_vec))
            .build()?;
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        let materials = input.materials();

        if materials.plaintext_data_key().is_some() {
            return Err(MplError::from(
                aws_crypto_mpl::error::InvalidMaterialsError::new(
                    "on_decrypt requires materials without a plaintext data key",
                ),
            ));
        }

        // Data key length in bytes, from the algorithm suite in the materials.
        let key_len = materials.algorithm_suite().encryption_key_length();

        // Unwrap the data key from the EDK this keyring produced.
        for edk in input.encrypted_data_keys() {
            if edk.key_provider_id() != PROVIDER_ID {
                continue;
            }
            let bytes = &edk.ciphertext();
            if bytes.len() != WRAP_IV_LEN + key_len + WRAP_TAG_LEN {
                return Err(MplError::from(
                    aws_crypto_mpl::error::CryptographicError::new(
                        "EDK ciphertext has unexpected length",
                    ),
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
                MplError::from(
                    aws_crypto_mpl::error::CryptographicError::new("failed to unwrap data key")
                        .with_source(e),
                )
            })?;
            let materials = DecryptionMaterials::builder()
                .algorithm_suite_id(materials.algorithm_suite_id())
                .encryption_context(materials.encryption_context().clone())
                .required_encryption_context_keys(
                    materials.required_encryption_context_keys().clone(),
                )
                .plaintext_data_key(PlaintextDataKey::new(data_key))
                .set_verification_key(materials.verification_key().cloned())
                .set_symmetric_signing_key(materials.symmetric_signing_key().cloned())
                .build()?;
            return OnDecryptOutput::builder().materials(materials).build();
        }

        Err(MplError::from(
            aws_crypto_mpl::error::NoMatchingDataKeyError::new("no EDK matched this keyring"),
        ))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_keyring_round_trips_via_public_api() {
    let keyring = LocalKekKeyring { kek: [7u8; 32] };
    let plaintext = b"extension interface round trip";

    // Encrypt entirely through the custom keyring.
    let out = encrypt(
        &EncryptInput::builder()
            .plaintext(plaintext)
            .keyring(keyring.clone())
            .build()
            .unwrap(),
    )
    .await
    .unwrap();

    // The custom keyring's EDK is serialized into the message header.
    assert!(
        out.ciphertext
            .windows(PROVIDER_ID.len())
            .any(|w| w == PROVIDER_ID.as_bytes()),
        "header must carry the custom keyring's provider ID"
    );

    // Decrypt back through the same keyring.
    let dec = decrypt(
        &DecryptInput::builder()
            .ciphertext(&out.ciphertext)
            .keyring(keyring)
            .build()
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(dec.plaintext, plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_keyring_wrong_kek_fails_decrypt() {
    let enc_keyring = LocalKekKeyring { kek: [7u8; 32] };
    let out = encrypt(
        &EncryptInput::builder()
            .plaintext(b"wrong kek must fail")
            .keyring(enc_keyring)
            .build()
            .unwrap(),
    )
    .await
    .unwrap();

    // A keyring with a different KEK cannot unwrap the data key.
    let wrong_keyring = LocalKekKeyring { kek: [8u8; 32] };
    let err = decrypt(
        &DecryptInput::builder()
            .ciphertext(&out.ciphertext)
            .keyring(wrong_keyring)
            .build()
            .unwrap(),
    )
    .await
    .expect_err("decrypt under a different KEK must fail");
    assert!(
        err.is_cryptographic(),
        "expected the keyring's unwrap failure, got {:?}",
        err
    );
}

/// Returns a plaintext data key half the suite's length.
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
        let edk = EncryptedDataKey::builder()
            .key_provider_id(PROVIDER_ID)
            .key_provider_info(b"")
            .ciphertext(vec![0; 8])
            .build()?;
        let materials = EncryptionMaterials::builder()
            .algorithm_suite_id(m.algorithm_suite_id())
            .encryption_context(m.encryption_context().clone())
            .encrypted_data_keys(vec![edk])
            .plaintext_data_key(PlaintextDataKey::new(vec![0; short]))
            .set_signing_key(m.signing_key().cloned())
            .build()?;
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        let m = input.into_materials();
        let short = m.algorithm_suite().encryption_key_length() / 2;
        let materials = DecryptionMaterials::builder()
            .algorithm_suite_id(m.algorithm_suite_id())
            .encryption_context(m.encryption_context().clone())
            .plaintext_data_key(PlaintextDataKey::new(vec![0; short]))
            .set_verification_key(m.verification_key().cloned())
            .build()?;
        OnDecryptOutput::builder().materials(materials).build()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_data_key_of_the_wrong_length_is_invalid_materials() {
    let err = encrypt(
        &EncryptInput::builder()
            .plaintext(b"short key")
            .keyring(ShortDataKeyKeyring)
            .build()
            .unwrap(),
    )
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
    let out = encrypt(
        &EncryptInput::builder()
            .plaintext(b"short key")
            .keyring(LocalKekKeyring { kek: [7u8; 32] })
            .build()
            .unwrap(),
    )
    .await
    .unwrap();
    let err = decrypt(
        &DecryptInput::builder()
            .ciphertext(&out.ciphertext)
            .keyring(ShortDataKeyKeyring)
            .build()
            .unwrap(),
    )
    .await
    .expect_err("a short plaintext data key must fail");
    assert!(err.is_invalid_materials(), "{err:?}");
}
