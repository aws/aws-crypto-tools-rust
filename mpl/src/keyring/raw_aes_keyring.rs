// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw AES keyring.

use async_trait::async_trait;
use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt, generate_random_bytes};

use crate::Keyring;
use crate::structures::{
    AlgorithmSuite, DecryptionMaterials, EncryptedDataKey, EncryptionMaterials, MaterialsError,
    PlaintextDataKey,
};

/// Byte width of the authentication-tag-length field of the serialized key
/// provider information.
const AUTH_TAG_LEN_LEN: usize = 4;

/// Byte width of the IV-length field of the serialized key provider information.
const IV_LEN_LEN: usize = 4;

/// IV length in bytes. Every wrapping algorithm the keyring supports specifies
/// an IV length of 12 bytes, so this constant IS the configured algorithm's IV
/// length for all three key sizes.
//= spec/framework/raw-aes-keyring.md#iv-length
//= type=implication
//# This value MUST match the IV length of the keyring's configured [wrapping algorithm](#wrapping-algorithm).
const IV_LENGTH: usize = 12;

/// [`IV_LENGTH`] as the `u32` written into and read from the IV-length field of
/// the key provider information.
const IV_LENGTH_FIELD: u32 = 12;

/// Authentication tag length in bytes. As with [`IV_LENGTH`], all three
/// wrapping algorithms specify a 16-byte tag.
const TAG_LENGTH: usize = 16;

/// Authentication tag length in bits, as serialized into the key provider
/// information.
//= spec/framework/raw-aes-keyring.md#authentication-tag-length
//= type=implication
//# This value MUST match the authentication tag length of the keyring's configured [wrapping algorithm](#wrapping-algorithm).
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
/// See [`RawAesKeyring::new`] for construction. The [`Keyring`] impl performs
/// AES-GCM encryption of the plaintext data key using the serialized
/// encryption context as additional authenticated data.
#[derive(Clone)]
pub struct RawAesKeyring {
    //= spec/framework/keyring-interface.md#key-namespace
    //= type=implication
    //# The key namespace MUST be a string value.
    key_namespace: String,
    //= spec/framework/keyring-interface.md#key-name
    //= type=implication
    //# The key name MUST be a string value.
    key_name: String,
    wrapping_key: Vec<u8>,
    //= spec/framework/raw-aes-keyring.md#wrapping-algorithm
    //= type=implication
    //# The keyring MUST support the following algorithm configurations:
    wrapping_alg: AesGcm,
}

impl std::fmt::Debug for RawAesKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawAesKeyring")
            .field("key_namespace", &self.key_namespace)
            .field("key_name", &self.key_name)
            .field(
                "wrapping_key",
                &format_args!("[REDACTED; {} bytes]", self.wrapping_key.len()),
            )
            .field("wrapping_alg", &self.wrapping_alg)
            .finish()
    }
}

impl RawAesKeyring {
    /// Construct a raw AES keyring.
    ///
    /// `wrapping_key` MUST be a secret value of cryptographically secure
    /// pseudo-random bytes, randomly generated from a cryptographically secure
    /// entropy source. Its length MUST be 128, 192, or 256 bits and MUST match
    /// the length specified by `wrapping_alg`.
    ///
    /// # Errors
    ///
    /// Returns [`MaterialsError`] when `wrapping_key`'s length does not match
    /// the length specified by `wrapping_alg`, or when `key_namespace` is equal
    /// to or starts with the reserved value `aws-kms`.
    //= spec/framework/raw-aes-keyring.md#initialization
    //= type=implication
    //# On keyring initialization,
    //# the caller MUST provide the following:
    pub fn new(
        key_namespace: impl Into<String>,
        key_name: impl Into<String>,
        wrapping_key: Vec<u8>,
        wrapping_alg: AesGcm,
    ) -> Result<Self, MaterialsError> {
        let key_namespace = key_namespace.into();
        // A prefix check, not an equality check: `aws-kms-hierarchy`,
        // `aws-kms-rsa` and `aws-kms-ecdh` are the key provider IDs of other
        // AWS KMS keyrings, and an equality check would let this keyring emit
        // encrypted data keys that impersonate them.
        //= spec/framework/raw-aes-keyring.md#changelog
        //# - [Raw AES keyring MUST NOT accept a key namespace of "aws-kms".](https://github.com/awslabs/aws-encryption-sdk-specification/issues/101)
        if key_namespace.starts_with(RESERVED_KEY_NAMESPACE_PREFIX) {
            return Err(MaterialsError::new(format!(
                "RawAesKeyring: key namespace must not be or start with `{RESERVED_KEY_NAMESPACE_PREFIX}`, got `{key_namespace}`"
            )));
        }

        let expected_key_len = usize::from(wrapping_alg.key_len());
        //= spec/framework/raw-aes-keyring.md#wrapping-algorithm
        //# Initialization MUST fail if the length of the [wrapping key](#wrapping-key) does not match the length specified by the wrapping algorithm.
        //
        //= spec/framework/raw-aes-keyring.md#wrapping-key
        //# The length of the wrapping key MUST be 128, 192, or 256.
        if wrapping_key.len() != expected_key_len {
            return Err(MaterialsError::new(format!(
                "RawAesKeyring: wrapping key length ({}) does not match the length specified by {:?} ({expected_key_len})",
                wrapping_key.len(),
                wrapping_alg,
            )));
        }

        Ok(Self {
            key_namespace,
            key_name: key_name.into(),
            wrapping_key,
            wrapping_alg,
        })
    }

    /// The key namespace, used as the key provider ID of EDKs this keyring produces.
    #[must_use]
    pub fn key_namespace(&self) -> &str {
        &self.key_namespace
    }

    /// The key name, serialized into the key provider information of EDKs this
    /// keyring produces.
    #[must_use]
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// The configured wrapping algorithm.
    #[must_use]
    pub const fn wrapping_alg(&self) -> AesGcm {
        self.wrapping_alg
    }

    /// Serialize the key provider information:
    /// `key_name || u32(tag_length_bits) || u32(iv_length) || iv`.
    fn serialize_provider_info(&self, iv: &[u8]) -> Vec<u8> {
        debug_assert!(
            iv.len() == IV_LENGTH,
            "serialize_provider_info: iv must be {IV_LENGTH} bytes, got {}",
            iv.len()
        );
        let name = self.key_name.as_bytes();
        let mut info = Vec::with_capacity(name.len() + AUTH_TAG_LEN_LEN + IV_LEN_LEN + iv.len());
        info.extend_from_slice(name);
        info.extend_from_slice(&TAG_LENGTH_BITS.to_be_bytes());
        info.extend_from_slice(&IV_LENGTH_FIELD.to_be_bytes());
        info.extend_from_slice(iv);
        info
    }

    /// Return the IV from `edk`'s key provider information if and only if this
    /// keyring should attempt to decrypt `edk`: the key provider ID equals this
    /// keyring's key namespace, the key provider information deserializes, the
    /// key name matches, and the IV and authentication tag lengths equal those
    /// specified by this keyring's wrapping algorithm.
    fn decryptable_edk_iv<'e>(&self, edk: &'e EncryptedDataKey) -> Option<&'e [u8]> {
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# - The key provider ID of the encrypted data key MUST have a value equal to this keyring's [key namespace](./keyring-interface.md#key-namespace).
        if edk.key_provider_id != self.key_namespace {
            return None;
        }

        let info = &edk.key_provider_info;
        let name = self.key_name.as_bytes();
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# - The [ciphertext](#ciphertext) and [key provider information](#key-provider-information) MUST be successfully deserialized.
        if info.len() != name.len() + AUTH_TAG_LEN_LEN + IV_LEN_LEN + IV_LENGTH {
            return None;
        }
        let (info_name, rest) = info.split_at(name.len());
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# - The key name obtained from the encrypted data key's key provider information MUST have a value equal to this keyring's [key name](./keyring-interface.md#key-name).
        if info_name != name {
            return None;
        }

        let (tag_bits, rest) = rest.split_at(AUTH_TAG_LEN_LEN);
        let tag_bits: [u8; AUTH_TAG_LEN_LEN] = tag_bits.try_into().ok()?;
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# - The [authentication tag length](#authentication-tag-length) obtained from the key provider information MUST have a value equal to the length specified by this keyring's [wrapping algorithm](#wrapping-algorithm).
        if u32::from_be_bytes(tag_bits) != TAG_LENGTH_BITS {
            return None;
        }

        let (iv_len, iv) = rest.split_at(IV_LEN_LEN);
        let iv_len: [u8; IV_LEN_LEN] = iv_len.try_into().ok()?;
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# - The [IV length](#iv-length) obtained from the encrypted data key's key provider information MUST have a value equal to the length specified by this keyring's [wrapping algorithm](#wrapping-algorithm).
        if u32::from_be_bytes(iv_len) != IV_LENGTH_FIELD {
            return None;
        }

        Some(iv)
    }
}

#[async_trait]
impl Keyring for RawAesKeyring {
    //= spec/framework/raw-aes-keyring.md#onencrypt
    //= type=implication
    //# OnEncrypt MUST take [encryption materials](structures.md#encryption-materials) as input.
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        // Serialized before any encryption is attempted, so an unserializable
        // encryption context fails the operation rather than producing an EDK.
        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# The keyring MUST attempt to serialize the [encryption materials'](structures.md#encryption-materials)
        //# [encryption context](structures.md#encryption-context-1) according to the [encryption context serialization specification](structures.md#serialization).
        //
        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# If the keyring cannot serialize the encryption context, OnEncrypt MUST fail.
        let aad = materials.encryption_context().serialize().map_err(|e| {
            MaterialsError::keyring_failed_with_cause(
                "RawAesKeyring::on_encrypt: failed to serialize the encryption context",
                e,
            )
        })?;

        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key,
        //# OnEncrypt MUST generate a random plaintext data key and set it on the [encryption materials](structures.md#encryption-materials).
        let plaintext_dk = match materials.plaintext_data_key() {
            Some(pdk) => pdk.clone(),
            None => generate_random_data_key(materials.algorithm_suite())?,
        };

        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# - It MUST use a cryptographically random generated IV of length specified by this keyring's [wrapping algorithm](#wrapping-algorithm).
        let mut iv = vec![0u8; IV_LENGTH];
        generate_random_bytes(&mut iv).map_err(|e| {
            MaterialsError::keyring_failed_with_cause(
                "RawAesKeyring::on_encrypt: failed to obtain entropy for the AES-GCM IV",
                e,
            )
        })?;

        // aes_encrypt appends the AES-GCM ciphertext followed by the
        // authentication tag, which is the EDK ciphertext structure.
        let mut ciphertext = Vec::new();
        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# The keyring MUST encrypt the plaintext data key in the [encryption materials](structures.md#encryption-materials)
        //# using AES-GCM.
        //
        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# - It MUST use this keyring's [wrapping key](#wrapping-key) as the AES-GCM cipher key.
        //
        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# - It MUST use the serialized [encryption context](structures.md#encryption-context-1) as the additional authenticated data (AAD).
        //
        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# - It MUST use an authentication tag bit of length specified by this keyring's [wrapping algorithm](#wrapping-algorithm).
        aes_encrypt(
            self.wrapping_alg,
            &iv,
            &self.wrapping_key,
            plaintext_dk.as_bytes(),
            &aad,
            &mut ciphertext,
        )
        .map_err(|e| {
            MaterialsError::keyring_failed_with_cause(
                "RawAesKeyring::on_encrypt: AES-GCM encryption of the plaintext data key failed",
                e,
            )
        })?;

        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# Based on the ciphertext output of the AES-GCM decryption,
        //# the keyring MUST construct an [encrypted data key](structures.md#encrypted-data-key) with the following specifics:
        let edk = EncryptedDataKey::new(
            self.key_namespace.clone(),
            self.serialize_provider_info(&iv),
            ciphertext,
        );

        // Reaching this point means the wrap succeeded. The input `materials`
        // is owned but never mutated; a fresh value is constructed so a
        // caller's failure handling can re-use the original.
        let mut new_edks = materials.encrypted_data_keys().to_vec();
        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# The keyring MUST append the constructed encrypted data key to the encrypted data key list in the
        //# [encryption materials](structures.md#encryption-materials).
        new_edks.push(edk);
        //= spec/framework/raw-aes-keyring.md#onencrypt
        //# OnEncrypt MUST output the modified [encryption materials](structures.md#encryption-materials).
        EncryptionMaterials::new(
            materials.algorithm_suite_id(),
            new_edks,
            materials.encryption_context().clone(),
            materials.required_encryption_context_keys().clone(),
            Some(plaintext_dk),
            materials.signing_key().cloned(),
            materials.symmetric_signing_keys().map(<[_]>::to_vec),
        )
    }

    //= spec/framework/raw-aes-keyring.md#ondecrypt
    //= type=implication
    //# OnDecrypt MUST take [decryption materials](structures.md#decryption-materials) and
    //# a list of [encrypted data keys](structures.md#encrypted-data-key) as input.
    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError> {
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# If the decryption materials already contain a plaintext data key,
        //# the keyring MUST fail
        //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
        if materials.plaintext_data_key().is_some() {
            return Err(MaterialsError::plaintext_data_key_already_present(
                "RawAesKeyring::on_decrypt: decryption materials already contain a plaintext data key",
            ));
        }

        // Serialized before the EDK loop, so an unserializable encryption
        // context fails the operation even when no EDK matches this keyring.
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# The keyring MUST attempt to serialize the [decryption materials'](structures.md#decryption-materials)
        //# [encryption context](structures.md#encryption-context-1) according to the [encryption context serialization specification](structures.md#serialization).
        //
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# If the keyring cannot serialize the encryption context, OnDecrypt MUST fail.
        let aad = materials.encryption_context().serialize().map_err(|e| {
            MaterialsError::keyring_failed_with_cause(
                "RawAesKeyring::on_decrypt: failed to serialize the encryption context",
                e,
            )
        })?;

        let expected_dk_len = materials.algorithm_suite().encryption_key_length();

        let mut errors: Vec<String> = Vec::new();
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# The keyring MUST perform the following actions on each [encrypted data key](structures.md#encrypted-data-key)
        //# in the input encrypted data key list, serially, until it successfully decrypts one.
        for (index, edk) in encrypted_data_keys.iter().enumerate() {
            //= spec/framework/raw-aes-keyring.md#ondecrypt
            //# For each [encrypted data key](structures.md#encrypted-data-key),
            //# the keyring MUST first attempt to deserialize the [serialized ciphertext](#ciphertext)
            //# to obtain the [encrypted key](#encrypted-key) and [authentication tag](#authentication-tag), and
            //# deserialize the [serialized key provider info](#key-provider-information) to obtain the [key name](./keyring-interface.md#key-name),
            //# [IV](#iv), [IV length](#iv-length), and [authentication tag length](#authentication-tag-length).
            let Some(iv) = self.decryptable_edk_iv(edk) else {
                errors.push(format!(
                    "EncryptedDataKey {index} did not match AESKeyring. Expected: keyProviderId: {}.",
                    self.key_namespace,
                ));
                continue;
            };

            if edk.ciphertext.len() < TAG_LENGTH {
                errors.push(format!(
                    "EncryptedDataKey {index}: insufficient data to decrypt: ciphertext is {} bytes, need at least the {TAG_LENGTH}-byte authentication tag",
                    edk.ciphertext.len(),
                ));
                continue;
            }
            let (encrypted_key, auth_tag) =
                edk.ciphertext.split_at(edk.ciphertext.len() - TAG_LENGTH);

            let mut plaintext_dk = vec![0u8; encrypted_key.len()];
            //= spec/framework/raw-aes-keyring.md#ondecrypt
            //# - It MUST use the [encrypt key](#encrypted-key) obtained from deserialization as the AES-GCM input ciphertext.
            //
            //= spec/framework/raw-aes-keyring.md#ondecrypt
            //# - It MUST use the [authentication tag](#authentication-tag) obtained from deserialization as the AES-GCM input authentication tag.
            //
            //= spec/framework/raw-aes-keyring.md#ondecrypt
            //# - It MUST use this keyring's [wrapping key](#wrapping-key) as the AES-GCM cipher key.
            //
            //= spec/framework/raw-aes-keyring.md#ondecrypt
            //# - It MUST use the [IV](#iv) obtained from deserialization as the AES-GCM IV.
            //
            //= spec/framework/raw-aes-keyring.md#ondecrypt
            //# - It MUST use the serialized [encryption context](structures.md#encryption-context-1) as the AES-GCM AAD.
            if let Err(e) = aes_decrypt(
                self.wrapping_alg,
                &self.wrapping_key,
                encrypted_key,
                auth_tag,
                iv,
                &aad,
                &mut plaintext_dk,
            ) {
                errors.push(format!(
                    "EncryptedDataKey {index}: AES-GCM decryption failed: {e}"
                ));
                continue;
            }

            if plaintext_dk.len() != expected_dk_len {
                errors.push(format!(
                    "EncryptedDataKey {index}: decrypted data key is {} bytes, expected {expected_dk_len} for the algorithm suite",
                    plaintext_dk.len(),
                ));
                continue;
            }

            //= spec/framework/raw-aes-keyring.md#ondecrypt
            //# If a decryption succeeds, this keyring MUST
            //# add the resulting plaintext data key to the decryption materials and return the modified materials.
            return DecryptionMaterials::new(
                materials.algorithm_suite_id(),
                materials.encryption_context().clone(),
                materials.required_encryption_context_keys().clone(),
                Some(PlaintextDataKey::new(plaintext_dk)),
                materials.verification_key().cloned(),
                materials.symmetric_signing_key().cloned(),
            );
        }

        // The early return above is the only path that produces modified
        // materials; reaching this line means no decryption succeeded, so the
        // input `materials` is dropped unmodified.
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# If no decryption succeeds,
        //# the keyring MUST fail
        //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
        Err(MaterialsError::no_matching_data_key(format!(
            "RawAesKeyring::on_decrypt: unable to decrypt any encrypted data key (collected errors: [{}])",
            errors.join("; "),
        )))
    }
}

/// Generate a random plaintext data key of the algorithm suite's configured
/// encryption-key length using the `aws-mpl-primitives` CSPRNG.
fn generate_random_data_key(suite: AlgorithmSuite) -> Result<PlaintextDataKey, MaterialsError> {
    let mut bytes = vec![0u8; suite.encryption_key_length()];
    generate_random_bytes(&mut bytes).map_err(|e| {
        MaterialsError::keyring_failed_with_cause(
            "RawAesKeyring::on_encrypt: failed to obtain entropy for the plaintext data key",
            e,
        )
    })?;
    Ok(PlaintextDataKey::new(bytes))
}
