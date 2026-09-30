// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw AES keyring.

use crate::{Error, ErrorKind};
use std::sync::Arc;

use async_trait::async_trait;
use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt, generate_random_bytes};

use crate::Keyring;
use crate::structures::{
    AlgorithmSuite, DecryptionMaterials, EncryptedDataKey, EncryptionMaterials, PlaintextDataKey,
};

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
/// Construct with [`RawAesKeyring::builder`]. The [`Keyring`] impl performs
/// AES-GCM encryption of the plaintext data key using the serialized
/// encryption context as additional authenticated data.
#[derive(Clone)]
pub struct RawAesKeyring {
    inner: Arc<RawAesKeyringInner>,
}

struct RawAesKeyringInner {
    key_namespace: String,
    key_name: String,
    wrapping_key: Vec<u8>,
    wrapping_alg: AesGcm,
}

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
    /// Start a builder for `RawAesKeyring`. Every field is required.
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
    pub fn wrapping_alg(&self) -> AesGcm {
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
                ErrorKind::Cryptographic,
                "failed to obtain entropy for the AES-GCM IV",
                e,
            )
        })?;

        // aes_encrypt appends the AES-GCM ciphertext followed by the
        // authentication tag, which is the EDK ciphertext structure.
        let mut ciphertext = Vec::new();
        aes_encrypt(
            self.inner.wrapping_alg,
            &iv,
            &self.inner.wrapping_key,
            plaintext_dk.as_bytes(),
            aad,
            &mut ciphertext,
        )
        .map_err(|e| {
            Error::with_cause(
                ErrorKind::Cryptographic,
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
#[derive(Default)]
pub struct RawAesKeyringBuilder {
    key_namespace: Option<String>,
    key_name: Option<String>,
    wrapping_key: Option<Vec<u8>>,
    wrapping_alg: Option<AesGcm>,
}

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
    /// Set the key namespace, used as the key provider ID of EDKs this
    /// keyring produces. Required. Must not be or start with `aws-kms`.
    #[must_use]
    pub fn key_namespace(mut self, key_namespace: impl Into<String>) -> Self {
        self.key_namespace = Some(key_namespace.into());
        self
    }

    /// Set the key name, serialized into the key provider information of EDKs
    /// this keyring produces. Required.
    #[must_use]
    pub fn key_name(mut self, key_name: impl Into<String>) -> Self {
        self.key_name = Some(key_name.into());
        self
    }

    /// Set the wrapping key. Required.
    ///
    /// The wrapping key MUST be a secret value of cryptographically secure
    /// pseudo-random bytes, randomly generated from a cryptographically secure
    /// entropy source. Its length MUST be 128, 192, or 256 bits and MUST match
    /// the length specified by the wrapping algorithm.
    #[must_use]
    pub fn wrapping_key(mut self, wrapping_key: impl Into<Vec<u8>>) -> Self {
        self.wrapping_key = Some(wrapping_key.into());
        self
    }

    /// Set the wrapping algorithm. Required.
    #[must_use]
    pub const fn wrapping_alg(mut self, wrapping_alg: AesGcm) -> Self {
        self.wrapping_alg = Some(wrapping_alg);
        self
    }

    /// Build the `RawAesKeyring`.
    ///
    /// # Errors
    ///
    /// Returns a `Validation` error when a field is unset, when the wrapping
    /// key's length does not match the length specified by the wrapping
    /// algorithm, or when the key namespace is equal to or starts with the
    /// reserved value `aws-kms`.
    pub fn build(self) -> Result<RawAesKeyring, Error> {
        let Some(key_namespace) = self.key_namespace else {
            return Err(Error::new(
                ErrorKind::Validation,
                "a key namespace is required",
            ));
        };
        let Some(key_name) = self.key_name else {
            return Err(Error::new(ErrorKind::Validation, "a key name is required"));
        };
        let Some(wrapping_key) = self.wrapping_key else {
            return Err(Error::new(
                ErrorKind::Validation,
                "a wrapping key is required",
            ));
        };
        let Some(wrapping_alg) = self.wrapping_alg else {
            return Err(Error::new(
                ErrorKind::Validation,
                "a wrapping algorithm is required",
            ));
        };

        // A prefix check, not an equality check: `aws-kms-hierarchy`,
        // `aws-kms-rsa` and `aws-kms-ecdh` are the key provider IDs of other
        // AWS KMS keyrings, and an equality check would let this keyring emit
        // encrypted data keys that impersonate them.
        if key_namespace.starts_with(RESERVED_KEY_NAMESPACE_PREFIX) {
            return Err(Error::new(
                ErrorKind::Validation,
                format!(
                    "key namespace must not be or start with `{RESERVED_KEY_NAMESPACE_PREFIX}`, got `{key_namespace}`"
                ),
            ));
        }

        let expected_key_len = usize::from(wrapping_alg.key_len());
        if wrapping_key.len() != expected_key_len {
            return Err(Error::new(
                ErrorKind::Validation,
                format!(
                    "wrapping key length ({}) does not match the length specified by {:?} ({expected_key_len})",
                    wrapping_key.len(),
                    wrapping_alg,
                ),
            ));
        }

        Ok(RawAesKeyring {
            inner: Arc::new(RawAesKeyringInner {
                key_namespace,
                key_name,
                wrapping_key,
                wrapping_alg,
            }),
        })
    }
}

#[async_trait]
impl Keyring for RawAesKeyring {
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, Error> {
        // Serialized before any encryption is attempted, so an unserializable
        // encryption context fails the operation rather than producing an EDK.
        let aad = materials
            .encryption_context()
            .serialize()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;

        match materials.plaintext_data_key() {
            Some(plaintext_dk) => {
                let edk = self.wrap_data_key(plaintext_dk, &aad)?;
                materials.add_encrypted_data_key(edk)
            }
            None => {
                let plaintext_dk = generate_random_data_key(materials.algorithm_suite())?;
                let edk = self.wrap_data_key(&plaintext_dk, &aad)?;
                materials.add_data_key(plaintext_dk, edk)
            }
        }
    }

    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, Error> {
        if materials.plaintext_data_key().is_some() {
            return Err(Error::new(
                ErrorKind::InvalidMaterials,
                "decryption materials already contain a plaintext data key",
            ));
        }

        // Serialized before the EDK loop, so an unserializable encryption
        // context fails the operation even when no EDK matches this keyring.
        let aad = materials
            .encryption_context()
            .serialize()
            .map_err(|e| Error::wrap("failed to serialize the encryption context", e))?;

        let expected_dk_len = materials.algorithm_suite().encryption_key_length();

        let mut collected_errors: Vec<Error> = Vec::new();
        // True once an EDK passes the provider filter and so belongs to this
        // keyring. Filter misses are recorded in `collected_errors` too, so a
        // non-empty `collected_errors` does not imply this.
        let mut attempted_decryption = false;
        for (index, edk) in encrypted_data_keys.iter().enumerate() {
            let Some(iv) = self.decryptable_edk_iv(edk) else {
                collected_errors.push(Error::new(ErrorKind::NoMatchingDataKey, format!(
                    "encrypted data key {index} did not match the AES keyring, expected key provider id {}",
                    self.inner.key_namespace,
                )));
                continue;
            };
            attempted_decryption = true;

            if edk.ciphertext().len() < TAG_LENGTH {
                collected_errors.push(Error::new(ErrorKind::Cryptographic, format!(
                    "encrypted data key {index}: insufficient data to decrypt: ciphertext is {} bytes, need at least the {TAG_LENGTH}-byte authentication tag",
                    edk.ciphertext().len(),
                )));
                continue;
            }
            let (encrypted_key, auth_tag) = edk
                .ciphertext()
                .split_at(edk.ciphertext().len() - TAG_LENGTH);

            let mut plaintext_dk = vec![0u8; encrypted_key.len()];
            if let Err(e) = aes_decrypt(
                self.inner.wrapping_alg,
                &self.inner.wrapping_key,
                encrypted_key,
                auth_tag,
                iv,
                &aad,
                &mut plaintext_dk,
            ) {
                collected_errors.push(Error::with_cause(
                    ErrorKind::Cryptographic,
                    format!("encrypted data key {index}: AES-GCM decryption failed"),
                    e,
                ));
                continue;
            }

            if plaintext_dk.len() != expected_dk_len {
                collected_errors.push(Error::new(ErrorKind::Cryptographic, format!(
                    "encrypted data key {index}: decrypted data key is {} bytes, expected {expected_dk_len} for the algorithm suite",
                    plaintext_dk.len(),
                )));
                continue;
            }

            return materials.add_data_key(PlaintextDataKey::new(plaintext_dk));
        }

        // The early return above is the only path that produces modified
        // materials; reaching this line means no decryption succeeded, so the
        // input `materials` is dropped unmodified.

        // Nothing here was this keyring's. The per-EDK rejections ride along on
        // the error, but the category stays `NoMatchingDataKey`: aggregating
        // sub-errors does not change what kind of failure this is.
        if !attempted_decryption {
            return Err(if collected_errors.is_empty() {
                Error::new(
                    ErrorKind::NoMatchingDataKey,
                    "no encrypted data key was supplied",
                )
            } else {
                Error::collection(
                    ErrorKind::NoMatchingDataKey,
                    "no encrypted data key matched this keyring",
                    collected_errors,
                )
            });
        }

        // At least one EDK was this keyring's and decryption still failed. The
        // per-attempt errors stay typed on the returned error, so a caller can
        // inspect each one.
        //
        //   "If no decryption succeeds, the keyring MUST fail"
        //
        // https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md#ondecrypt
        let kind = Error::aggregate_kind(&collected_errors, ErrorKind::Cryptographic);
        Err(Error::collection(
            kind,
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
            ErrorKind::Cryptographic,
            "failed to obtain entropy for the plaintext data key",
            e,
        )
    })?;
    Ok(PlaintextDataKey::new(bytes))
}
