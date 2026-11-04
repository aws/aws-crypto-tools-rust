// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw AES keyring.

use crate::Error;
use crate::builder::required;
use crate::error::{DataKeyInfo, Kind};
use std::borrow::Cow;
use std::sync::Arc;

use crate::keyring::edk_wrapping;
use crate::structures::{AesWrappingAlg, EdkWrapping};
use async_trait::async_trait;
use aws_mpl_primitives::{aes_decrypt, aes_encrypt, generate_random_bytes};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::keyring::Keyring;
use crate::keyring::{OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput};
use crate::structures::{AlgorithmSuite, EncryptedDataKey, PlaintextDataKey};

/// Byte width of the authentication-tag-length field of the serialized key
/// provider information.
const AUTH_TAG_LEN_LEN: usize = 4;

/// Byte width of the IV-length field of the serialized key provider information.
const IV_LEN_LEN: usize = 4;

/// IV length in bytes. Every wrapping algorithm the keyring supports specifies
/// an IV length of 12 bytes, so this constant IS the configured algorithm's IV
/// length for all three key sizes.
const IV_LENGTH: usize = 12;

/// [`IV_LENGTH`] as the `u32` written into and read from the IV-length field of
/// the key provider information.
const IV_LENGTH_FIELD: u32 = 12;

/// Authentication tag length in bytes. As with [`IV_LENGTH`], all three
/// wrapping algorithms specify a 16-byte tag.
const TAG_LENGTH: usize = 16;

/// Authentication tag length in bits, as serialized into the key provider
/// information.
const TAG_LENGTH_BITS: u32 = 128;

/// Key namespace prefix reserved for the AWS KMS keyrings. A raw AES keyring
/// MUST NOT accept a key namespace equal to or starting with this value,
/// because the key namespace becomes the EDK's key provider ID and that value
/// must not claim to have been produced by an AWS KMS keyring. The prefix, not
/// just the exact string, is reserved: the AWS KMS keyrings use `aws-kms`,
/// `aws-kms-hierarchy`, `aws-kms-rsa` and `aws-kms-ecdh` as their key provider
/// IDs.
const RESERVED_KEY_NAMESPACE_PREFIX: &str = "aws-kms";

/// A keyring that wraps and unwraps data keys with a local AES-GCM wrapping key.
///
/// Construct with [`RawAesKeyring::builder`].
/// The keyring uses the serialized encryption context as AES-GCM additional authenticated data.
#[derive(Clone)]
pub struct RawAesKeyring {
    inner: Arc<RawAesKeyringInner>,
}

struct RawAesKeyringInner {
    /// `{key_namespace}/{key_name}`, which `name()` returns.
    name: String,
    key_namespace: String,
    key_name: String,
    wrapping_key: Vec<u8>,
    wrapping_alg: AesWrappingAlg,
}

impl Drop for RawAesKeyringInner {
    fn drop(&mut self) {
        self.wrapping_key.zeroize();
    }
}

impl ZeroizeOnDrop for RawAesKeyringInner {}

impl std::fmt::Debug for RawAesKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawAesKeyring")
            .field("key_namespace", &self.inner.key_namespace)
            .field("key_name", &self.inner.key_name)
            .field(
                "wrapping_key",
                &format_args!("[REDACTED; {} bytes]", self.inner.wrapping_key.len()),
            )
            .field("wrapping_alg", &self.inner.wrapping_alg)
            .finish()
    }
}

impl RawAesKeyring {
    /// `{key_namespace}/{key_name}`.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.inner.name)
    }

    /// Start a builder for `RawAesKeyring`.
    /// Every field is required.
    #[must_use]
    pub fn builder() -> RawAesKeyringBuilder {
        RawAesKeyringBuilder::default()
    }

    /// The key namespace, used as the key provider ID of EDKs this keyring produces.
    #[must_use]
    pub fn key_namespace(&self) -> &str {
        &self.inner.key_namespace
    }

    /// The key name, serialized into the key provider information of EDKs this
    /// keyring produces.
    #[must_use]
    pub fn key_name(&self) -> &str {
        &self.inner.key_name
    }

    /// The configured wrapping algorithm.
    #[must_use]
    pub fn wrapping_alg(&self) -> AesWrappingAlg {
        self.inner.wrapping_alg
    }

    /// Serialize the key provider information:
    /// `key_name || u32(tag_length_bits) || u32(iv_length) || iv`.
    fn serialize_provider_info(&self, iv: &[u8]) -> Vec<u8> {
        debug_assert!(
            iv.len() == IV_LENGTH,
            "serialize_provider_info: iv must be {IV_LENGTH} bytes, got {}",
            iv.len()
        );
        let name = self.inner.key_name.as_bytes();
        let mut info = Vec::with_capacity(name.len() + AUTH_TAG_LEN_LEN + IV_LEN_LEN + iv.len());
        info.extend_from_slice(name);
        info.extend_from_slice(&TAG_LENGTH_BITS.to_be_bytes());
        info.extend_from_slice(&IV_LENGTH_FIELD.to_be_bytes());
        info.extend_from_slice(iv);
        info
    }

    /// Wrap `plaintext_dk` under the wrapping key with a fresh random IV,
    /// authenticating `aad`.
    fn wrap_data_key(
        &self,
        plaintext_dk: &PlaintextDataKey,
        aad: &[u8],
    ) -> Result<EncryptedDataKey, Error> {
        let mut iv = vec![0u8; IV_LENGTH];
        generate_random_bytes(&mut iv).map_err(|e| {
            Error::with_cause(
                Kind::Cryptographic,
                "failed to obtain entropy for the AES-GCM IV",
                e,
            )
        })?;

        // aes_encrypt appends the AES-GCM ciphertext followed by the
        // authentication tag, which is the EDK ciphertext structure.
        let mut ciphertext = Vec::new();
        aes_encrypt(
            self.inner.wrapping_alg.primitive(),
            &iv,
            &self.inner.wrapping_key,
            plaintext_dk.as_bytes(),
            aad,
            &mut ciphertext,
        )
        .map_err(|e| {
            Error::with_cause(
                Kind::Cryptographic,
                "AES-GCM encryption of the plaintext data key failed",
                e,
            )
        })?;

        EncryptedDataKey::builder()
            .key_provider_id(self.inner.key_namespace.as_str())
            .key_provider_info(self.serialize_provider_info(&iv))
            .ciphertext(ciphertext)
            .build()
    }

    /// Return the IV from `edk`'s key provider information if and only if this
    /// keyring should attempt to decrypt `edk`: the key provider ID equals this
    /// keyring's key namespace, the key provider information deserializes, the
    /// key name matches, and the IV and authentication tag lengths equal those
    /// specified by this keyring's wrapping algorithm.
    fn decryptable_edk_iv<'e>(&self, edk: &'e EncryptedDataKey) -> Option<&'e [u8]> {
        if edk.key_provider_id() != self.inner.key_namespace {
            return None;
        }

        let info = edk.key_provider_info();
        let name = self.inner.key_name.as_bytes();
        if info.len() != name.len() + AUTH_TAG_LEN_LEN + IV_LEN_LEN + IV_LENGTH {
            return None;
        }
        let (info_name, rest) = info.split_at(name.len());
        if info_name != name {
            return None;
        }

        let (tag_bits, rest) = rest.split_at(AUTH_TAG_LEN_LEN);
        let tag_bits: [u8; AUTH_TAG_LEN_LEN] = tag_bits.try_into().ok()?;
        if u32::from_be_bytes(tag_bits) != TAG_LENGTH_BITS {
            return None;
        }

        let (iv_len, iv) = rest.split_at(IV_LEN_LEN);
        let iv_len: [u8; IV_LEN_LEN] = iv_len.try_into().ok()?;
        if u32::from_be_bytes(iv_len) != IV_LENGTH_FIELD {
            return None;
        }

        Some(iv)
    }
}

/// Builder for [`RawAesKeyring`].
///
/// Each clone holds its own copy of the wrapping key, zeroized when that clone drops.
#[derive(Clone, Default)]
pub struct RawAesKeyringBuilder {
    key_namespace: Option<String>,
    key_name: Option<String>,
    wrapping_key: Option<Vec<u8>>,
    wrapping_alg: Option<AesWrappingAlg>,
}

impl Drop for RawAesKeyringBuilder {
    fn drop(&mut self) {
        self.wrapping_key.zeroize();
    }
}

impl ZeroizeOnDrop for RawAesKeyringBuilder {}

impl std::fmt::Debug for RawAesKeyringBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawAesKeyringBuilder")
            .field("key_namespace", &self.key_namespace)
            .field("key_name", &self.key_name)
            .field("wrapping_alg", &self.wrapping_alg)
            .finish_non_exhaustive()
    }
}

impl RawAesKeyringBuilder {
    /// Set the key namespace, which becomes the key provider ID of each EDK this keyring produces.
    /// Required, and must not be or start with `aws-kms`.
    #[must_use]
    pub fn key_namespace(mut self, key_namespace: impl Into<String>) -> Self {
        self.key_namespace = Some(key_namespace.into());
        self
    }

    /// Set or clear the key namespace from an `Option`.
    /// To set a value, use [`Self::key_namespace`].
    #[must_use]
    pub fn set_key_namespace(mut self, key_namespace: Option<String>) -> Self {
        self.key_namespace = key_namespace;
        self
    }

    /// The key namespace, if set.
    #[must_use]
    pub fn get_key_namespace(&self) -> &Option<String> {
        &self.key_namespace
    }

    /// Set the key name, which this keyring serializes into the key provider information of each EDK.
    /// Required.
    #[must_use]
    pub fn key_name(mut self, key_name: impl Into<String>) -> Self {
        self.key_name = Some(key_name.into());
        self
    }

    /// Set or clear the key name from an `Option`.
    /// To set a value, use [`Self::key_name`].
    #[must_use]
    pub fn set_key_name(mut self, key_name: Option<String>) -> Self {
        self.key_name = key_name;
        self
    }

    /// The key name, if set.
    #[must_use]
    pub fn get_key_name(&self) -> &Option<String> {
        &self.key_name
    }

    /// Set the wrapping key.
    /// Required.
    ///
    /// The wrapping key must be secret bytes from a cryptographically secure random source.
    /// Its length must be 128, 192, or 256 bits and match the wrapping algorithm.
    #[must_use]
    pub fn wrapping_key(mut self, wrapping_key: impl Into<Vec<u8>>) -> Self {
        self.wrapping_key = Some(wrapping_key.into());
        self
    }

    /// Set or clear the wrapping key from an `Option`.
    /// To set a value, use [`Self::wrapping_key`].
    #[must_use]
    pub fn set_wrapping_key(mut self, wrapping_key: Option<Vec<u8>>) -> Self {
        self.wrapping_key = wrapping_key;
        self
    }

    /// The wrapping key, if set.
    #[must_use]
    pub fn get_wrapping_key(&self) -> &Option<Vec<u8>> {
        &self.wrapping_key
    }

    /// Set the wrapping algorithm.
    /// Required.
    #[must_use]
    pub fn wrapping_alg(mut self, wrapping_alg: AesWrappingAlg) -> Self {
        self.wrapping_alg = Some(wrapping_alg);
        self
    }

    /// Set or clear the wrapping algorithm from an `Option`.
    /// To set a value, use [`Self::wrapping_alg`].
    #[must_use]
    pub fn set_wrapping_alg(mut self, wrapping_alg: Option<AesWrappingAlg>) -> Self {
        self.wrapping_alg = wrapping_alg;
        self
    }

    /// The wrapping algorithm, if set.
    #[must_use]
    pub fn get_wrapping_alg(&self) -> &Option<AesWrappingAlg> {
        &self.wrapping_alg
    }

    /// Build the `RawAesKeyring`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a field is unset,
    ///   the wrapping key's length does not match the wrapping algorithm,
    ///   or the key namespace is or starts with `aws-kms`.
    pub fn build(mut self) -> Result<RawAesKeyring, Error> {
        let key_namespace = required(self.key_namespace.take(), "key_namespace")?;
        let key_name = required(self.key_name.take(), "key_name")?;
        let mut wrapping_key = Zeroizing::new(required(self.wrapping_key.take(), "wrapping_key")?);
        let wrapping_alg = required(self.wrapping_alg.take(), "wrapping_alg")?;

        // A prefix check, not an equality check: `aws-kms-hierarchy`,
        // `aws-kms-rsa` and `aws-kms-ecdh` are the key provider IDs of other
        // AWS KMS keyrings, and an equality check would let this keyring emit
        // encrypted data keys that impersonate them.
        if key_namespace.starts_with(RESERVED_KEY_NAMESPACE_PREFIX) {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "key namespace must not be or start with `{RESERVED_KEY_NAMESPACE_PREFIX}`, got `{key_namespace}`"
                ),
            ));
        }

        let expected_key_len = wrapping_alg.key_length();
        if wrapping_key.len() != expected_key_len {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "wrapping key length ({}) does not match the length specified by {:?} ({expected_key_len})",
                    wrapping_key.len(),
                    wrapping_alg,
                ),
            ));
        }

        Ok(RawAesKeyring {
            inner: Arc::new(RawAesKeyringInner {
                name: format!("{key_namespace}/{key_name}"),
                key_namespace,
                key_name,
                wrapping_key: std::mem::take(&mut *wrapping_key),
                wrapping_alg,
            }),
        })
    }
}

#[async_trait]
impl Keyring for crate::shared::Builtin<RawAesKeyring> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        let materials = input.materials;
        // Serialized before any encryption is attempted, so an unserializable
        // encryption context fails the operation rather than producing an EDK.
        let aad = materials
            .encryption_context()
            .to_bytes()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;

        let suite = materials.algorithm_suite();
        let materials = match (suite.edk_wrapping(), materials.plaintext_data_key()) {
            (EdkWrapping::IntermediateKeyWrapping(_), existing) => {
                // Wrap a fresh intermediate key.
                // Keys derived from it encrypt the plaintext data key and sign the message.
                let (plaintext_dk, generated) = match existing {
                    Some(key) => (key.clone(), false),
                    None => (generate_random_data_key(suite)?, true),
                };
                let ikm = generate_random_data_key(suite)?;
                let provider_edk = self.wrap_data_key(&ikm, &aad)?;
                let (encrypted_pdk, signing_key) =
                    edk_wrapping::encrypt_pdk(&suite, ikm.as_bytes(), &aad, &plaintext_dk)?;
                let mut ciphertext = encrypted_pdk;
                ciphertext.extend_from_slice(provider_edk.ciphertext());
                let edk = EncryptedDataKey::builder()
                    .key_provider_id(provider_edk.key_provider_id())
                    .key_provider_info(provider_edk.key_provider_info().to_vec())
                    .ciphertext(ciphertext)
                    .build()?;
                if generated {
                    materials.add_data_key_with_symmetric_signing_key(
                        plaintext_dk,
                        edk,
                        signing_key,
                    )?
                } else {
                    materials.add_encrypted_data_key_with_symmetric_signing_key(edk, signing_key)?
                }
            }
            (_, Some(plaintext_dk)) => {
                let edk = self.wrap_data_key(plaintext_dk, &aad)?;
                materials.add_encrypted_data_key(edk)?
            }
            (_, None) => {
                let plaintext_dk = generate_random_data_key(suite)?;
                let edk = self.wrap_data_key(&plaintext_dk, &aad)?;
                materials.add_data_key(plaintext_dk, edk)?
            }
        };
        OnEncryptOutput::builder().materials(materials).build()
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        let OnDecryptInput {
            materials,
            encrypted_data_keys,
        } = input;
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                Kind::InvalidMaterials,
                "decryption materials already contain a plaintext data key",
            ));
        }

        // Serialized before the EDK loop, so an unserializable encryption
        // context fails the operation even when no EDK matches this keyring.
        let aad = materials
            .encryption_context()
            .to_bytes()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;

        let expected_dk_len = materials.algorithm_suite().encryption_key_length();

        let mut collected_errors: Vec<Error> = Vec::new();
        // True once an EDK passes the provider filter and so belongs to this
        // keyring. Filter misses are recorded in `collected_errors` too, so a
        // non-empty `collected_errors` does not imply this.
        let mut attempted_decryption = false;
        for (index, edk) in encrypted_data_keys.iter().enumerate() {
            let Some(iv) = self.decryptable_edk_iv(edk) else {
                collected_errors.push(
                    Error::new(Kind::NoMatchingDataKey, format!(
                        "encrypted data key {index} did not match the keyring, expected key provider id {}",
                        self.inner.key_namespace,
                    ))
                    .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from)),
                );
                continue;
            };
            attempted_decryption = true;

            let intermediate = matches!(
                materials.algorithm_suite().edk_wrapping(),
                EdkWrapping::IntermediateKeyWrapping(_)
            );
            let (encrypted_pdk, provider_wrapped) = if intermediate {
                match edk_wrapping::split(&materials.algorithm_suite(), edk.ciphertext()) {
                    Ok((pdk, wrapped)) => (Some(pdk), wrapped),
                    Err(e) => {
                        collected_errors.push(Error::wrap(
                            format!("encrypted data key {index}: Invalid material for Intermediate Unwrapping"),
                            e,
                        ));
                        continue;
                    }
                }
            } else {
                (None, edk.ciphertext())
            };

            if provider_wrapped.len() < TAG_LENGTH {
                collected_errors.push(Error::new(Kind::Cryptographic, format!(
                    "encrypted data key {index}: insufficient data to decrypt: ciphertext is {} bytes, need at least the {TAG_LENGTH}-byte authentication tag",
                    provider_wrapped.len(),
                )));
                continue;
            }
            let (encrypted_key, auth_tag) =
                provider_wrapped.split_at(provider_wrapped.len() - TAG_LENGTH);

            let mut plaintext_dk = Zeroizing::new(vec![0u8; encrypted_key.len()]);
            if let Err(e) = aes_decrypt(
                self.inner.wrapping_alg.primitive(),
                &self.inner.wrapping_key,
                encrypted_key,
                auth_tag,
                iv,
                &aad,
                &mut plaintext_dk,
            ) {
                collected_errors.push(Error::with_cause(
                    Kind::Cryptographic,
                    format!("encrypted data key {index}: AES-GCM decryption failed"),
                    e,
                ));
                continue;
            }

            if plaintext_dk.len() != expected_dk_len {
                collected_errors.push(Error::new(Kind::Cryptographic, format!(
                    "encrypted data key {index}: decrypted data key is {} bytes, expected {expected_dk_len} for the algorithm suite",
                    plaintext_dk.len(),
                )));
                continue;
            }

            if let Some(encrypted_pdk) = encrypted_pdk {
                let (pdk, signing_key) = match edk_wrapping::decrypt_pdk(
                    &materials.algorithm_suite(),
                    &plaintext_dk,
                    &aad,
                    encrypted_pdk,
                ) {
                    Ok(keys) => keys,
                    Err(e) => {
                        collected_errors.push(Error::wrap(
                            format!(
                                "encrypted data key {index}: the plaintext data key did not decrypt"
                            ),
                            e,
                        ));
                        continue;
                    }
                };
                let materials =
                    materials.add_data_key_with_symmetric_signing_key(pdk, signing_key)?;
                return OnDecryptOutput::builder().materials(materials).build();
            }

            let materials = materials.add_data_key(PlaintextDataKey::new(plaintext_dk.to_vec()))?;
            return OnDecryptOutput::builder().materials(materials).build();
        }

        // The early return above is the only path that produces modified
        // materials; reaching this line means no decryption succeeded, so the
        // input `materials` is dropped unmodified.

        // No EDK belonged to this keyring.
        if !attempted_decryption {
            return Err(if collected_errors.is_empty() {
                Error::new(
                    Kind::NoMatchingDataKey,
                    "no encrypted data key was supplied",
                )
            } else {
                Error::all_failed(
                    "no encrypted data key matched this keyring",
                    collected_errors,
                )
            });
        }

        // At least one EDK belonged to this keyring, and none decrypted.
        //
        //   "If no decryption succeeds, the keyring MUST fail"
        //
        // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md#ondecrypt
        Err(Error::all_failed(
            "unable to decrypt any encrypted data key",
            collected_errors,
        ))
    }
}

/// Generate a random plaintext data key of the algorithm suite's configured
/// encryption-key length using the `aws-mpl-primitives` CSPRNG.
fn generate_random_data_key(suite: AlgorithmSuite) -> Result<PlaintextDataKey, Error> {
    let mut bytes = vec![0u8; suite.encryption_key_length()];
    generate_random_bytes(&mut bytes).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to obtain entropy for the plaintext data key",
            e,
        )
    })?;
    Ok(PlaintextDataKey::new(bytes))
}
