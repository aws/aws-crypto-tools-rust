// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! KMS keyring: data-key wrapping and unwrapping via AWS KMS.
//!
//! Interoperability note: the [spec](../../spec/s3-encryption/materials/s3-kms-keyring.md)
//! describes `EncryptDataKey` as calling `KMS Encrypt`, but every shipping S3EC
//! reference implementation (Java, Python) instead calls `KMS GenerateDataKey`
//! for the Kms+Context wrapping mode. The Python reference notes the spec is
//! wrong here. To remain wire-compatible with those implementations this
//! keyring uses `GenerateDataKey` on encrypt and `Decrypt` on decrypt.

use std::collections::BTreeMap;

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;

use crate::config::EncryptionAlgorithm;
use crate::error::{Result, S3EncryptionError};

/// The "kms+context" key provider info — the only wrapping algorithm used on
/// encrypt and the fully-supported (non-legacy) decrypt mode.
pub const WRAP_ALG_KMS_CONTEXT: &str = "kms+context";
/// The legacy "kms" (KmsV1) key provider info.
pub const WRAP_ALG_KMS_V1: &str = "kms";
/// The raw AES-GCM ("AES/GCM") key provider info — the non-legacy wrapping
/// algorithm used by the [`AesKeyring`]. Its V3 compressed code is "02".
pub const WRAP_ALG_AES_GCM: &str = "AES/GCM";
/// The raw RSA-OAEP-SHA1 ("RSA-OAEP-SHA1") key provider info — the non-legacy
/// wrapping algorithm used by the [`RsaKeyring`]. Its V3 compressed code is "22".
pub const WRAP_ALG_RSA_OAEP_SHA1: &str = "RSA-OAEP-SHA1";

/// Reserved encryption-context key holding the content algorithm. The S3EC
/// owns this key; callers MUST NOT supply it.
pub const RESERVED_CEK_ALG_KEY: &str = "aws:x-amz-cek-alg";
/// Reserved encryption-context key used by the legacy KmsV1 mode.
pub const RESERVED_KMS_CMK_ID_KEY: &str = "kms_cmk_id";

//= ../spec/s3-encryption/materials/keyrings.md#interface
//= type=implication
//# The Keyring interface and its operations SHOULD adhere to the naming conventions of the implementation language.
//
//= ../spec/s3-encryption/materials/keyrings.md#supported-keyrings
//= type=implication
//# Note: A user MAY create their own custom keyring(s).
/// A KMS-backed keyring that wraps and unwraps content data keys.
#[derive(Clone)]
pub struct KmsKeyring {
    kms: aws_sdk_kms::Client,
    kms_key_id: String,
    enable_legacy_wrapping_algorithms: bool,
}

impl KmsKeyring {
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //# On initialization, the caller MUST provide an AWS KMS key identifier.
    /// Construct a keyring from a KMS client, key identifier, and the legacy
    /// wrapping-algorithm flag.
    pub fn new(
        kms: aws_sdk_kms::Client,
        kms_key_id: String,
        enable_legacy_wrapping_algorithms: bool,
    ) -> Self {
        //= ../spec/s3-encryption/materials/keyrings.md#interface
        //# The Keyring interface and its operations SHOULD adhere to the naming conventions of the implementation language.
        Self {
            kms,
            kms_key_id,
            enable_legacy_wrapping_algorithms,
        }
    }

    /// Build the encryption context for an encrypt request: the caller-supplied
    /// context plus the reserved content-algorithm key.
    ///
    /// The reserved value is the content-cipher value of the suite — the cipher
    /// name (`AES/GCM/NoPadding`) for non-committing suites, and the decimal
    /// suite ID (`115`) for the committing suite.
    pub fn build_encryption_context(
        caller_context: &BTreeMap<String, String>,
        suite: EncryptionAlgorithm,
    ) -> BTreeMap<String, String> {
        let mut context = caller_context.clone();
        context.insert(RESERVED_CEK_ALG_KEY.to_string(), suite.content_cipher_value());
        context
    }

    /// Validate the provided (request) encryption context against the stored
    /// (materials) encryption context for Kms+Context decryption.
    pub fn validate_decryption_context(
        stored: &BTreeMap<String, String>,
        request: &BTreeMap<String, String>,
    ) -> Result<()> {
        if request.contains_key(RESERVED_CEK_ALG_KEY) {
            return Err(S3EncryptionError::Crypto(format!(
                "{RESERVED_CEK_ALG_KEY} is a reserved key for the S3 encryption client"
            )));
        }

        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# When decrypting using Kms+Context mode, the KmsKeyring MUST validate the provided (request) encryption context with the stored (materials) encryption context.
        //
        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# The stored encryption context with the two reserved keys removed MUST match the provided encryption context.
        let mut stripped = stored.clone();
        stripped.remove(RESERVED_CEK_ALG_KEY);
        stripped.remove(RESERVED_KMS_CMK_ID_KEY);

        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# If the stored encryption context with the two reserved keys removed does not match the provided encryption context, the KmsKeyring MUST throw an exception.
        if &stripped != request {
            return Err(S3EncryptionError::Crypto(
                "Provided encryption context does not match information retrieved from S3"
                    .to_string(),
            ));
        }
        Ok(())
    }

    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface MUST include the OnEncrypt operation.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnEncrypt operation MUST accept an instance of EncryptionMaterials as input.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnEncrypt operation MUST return an instance of EncryptionMaterials as output.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    //# The KmsKeyring MUST support encryption using Kms+Context mode.
    /// Wrap a freshly generated data key via `KMS GenerateDataKey`.
    ///
    /// Returns `(plaintext_data_key, encrypted_data_key)`.
    pub async fn wrap(&self, encryption_context: &BTreeMap<String, String>) -> Result<(Vec<u8>, Vec<u8>)> {
        let context: std::collections::HashMap<String, String> =
            encryption_context.clone().into_iter().collect();

        let response = self
            .kms
            .generate_data_key()
            .key_id(&self.kms_key_id)
            .key_spec(DataKeySpec::Aes256)
            .set_encryption_context(Some(context))
            .send()
            .await
            .map_err(|e| S3EncryptionError::Sdk(format!("KMS GenerateDataKey failed: {e}")))?;

        let plaintext = response
            .plaintext()
            .ok_or_else(|| S3EncryptionError::Sdk("KMS GenerateDataKey returned no plaintext".into()))?
            .as_ref()
            .to_vec();
        let encrypted = response
            .ciphertext_blob()
            .ok_or_else(|| {
                S3EncryptionError::Sdk("KMS GenerateDataKey returned no ciphertext".into())
            })?
            .as_ref()
            .to_vec();

        Ok((plaintext, encrypted))
    }

    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface MUST include the OnDecrypt operation.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnDecrypt operation MUST accept an instance of DecryptionMaterials and a collection of EncryptedDataKey instances as input.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnDecrypt operation MUST return an instance of DecryptionMaterials as output.
    /// Unwrap an encrypted data key via `KMS Decrypt`, dispatching on the
    /// wrapping algorithm recorded in the object metadata.
    ///
    /// Returns the plaintext data key.
    pub async fn unwrap(
        &self,
        encrypted_data_key: &[u8],
        wrap_algorithm: &str,
        stored_context: &BTreeMap<String, String>,
        request_context: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>> {
        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
        //# The KmsKeyring MUST determine whether to decrypt using KmsV1 mode or Kms+Context mode.
        match wrap_algorithm {
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
            //# If the Key Provider Info of the Encrypted Data Key is "kms+context", the KmsKeyring MUST attempt to decrypt using Kms+Context mode.
            WRAP_ALG_KMS_CONTEXT => {
                Self::validate_decryption_context(stored_context, request_context)?;
            }
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
            //# If the Key Provider Info of the Encrypted Data Key is "kms", the KmsKeyring MUST attempt to decrypt using KmsV1 mode.
            WRAP_ALG_KMS_V1 => {
                //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
                //# The KmsV1 mode MUST be only enabled when legacy wrapping algorithms are enabled.
                if !self.enable_legacy_wrapping_algorithms {
                    return Err(S3EncryptionError::Crypto(format!(
                        "Enable legacy wrapping algorithms to use legacy key wrapping algorithm: \
                         {wrap_algorithm}"
                    )));
                }
                // KmsV1 does not support caller-supplied encryption context; a
                // non-empty request context would be a downgrade-bypass attempt.
                if !request_context.is_empty() {
                    return Err(S3EncryptionError::Crypto(
                        "encryption context is not supported with the KmsV1 (kms) wrapping \
                         algorithm"
                            .to_string(),
                    ));
                }
            }
            other => {
                return Err(S3EncryptionError::Crypto(format!(
                    "{other} is not a valid key wrapping algorithm"
                )));
            }
        }

        let context: std::collections::HashMap<String, String> =
            stored_context.clone().into_iter().collect();

        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
        let response = self
            .kms
            .decrypt()
            .key_id(&self.kms_key_id)
            .ciphertext_blob(Blob::new(encrypted_data_key.to_vec()))
            .set_encryption_context(Some(context))
            .send()
            .await
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
            .map_err(|e| S3EncryptionError::Sdk(format!("KMS Decrypt failed: {e}")))?;

        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# The KmsKeyring MUST immediately return the plaintext as a collection of bytes.
        let plaintext = response
            .plaintext()
            .ok_or_else(|| S3EncryptionError::Sdk("KMS Decrypt returned no plaintext".into()))?
            .as_ref()
            .to_vec();
        Ok(plaintext)
    }
}

//= ../spec/s3-encryption/materials/keyrings.md#interface
//= type=implication
//# The Keyring interface and its operations SHOULD adhere to the naming conventions of the implementation language.
//
//= ../spec/s3-encryption/materials/keyrings.md#supported-keyrings
//= type=implication
//# Note: A user MAY create their own custom keyring(s).
/// A raw AES keyring that wraps and unwraps content data keys with a
/// caller-supplied AES-256 key using AES-GCM (the non-legacy "AES/GCM"
/// wrapping algorithm).
///
/// Unlike the KMS keyring, a raw keyring performs no network calls and stores
/// no AWS KMS encryption context: the encryption context provides no security
/// benefit for raw keyrings and is not persisted. This is a concrete S3
/// Keyring implementation; the wrap/unwrap below realize its abstract
/// `GenerateDataKey`/`EncryptDataKey`/`DecryptDataKey` methods.
#[derive(Clone)]
pub struct AesKeyring {
    wrapping_key: Vec<u8>,
}

impl AesKeyring {
    /// Construct a raw AES keyring from a wrapping key. The wrapping key must
    /// be a 256-bit (32-byte) AES key; a wrong-length key is rejected lazily by
    /// the AES-GCM primitive when wrapping or unwrapping.
    pub fn new(wrapping_key: Vec<u8>) -> Self {
        Self { wrapping_key }
    }

    /// The AES-GCM AAD bound into a wrapped data key for `suite`: the suite's
    /// content-cipher value (`"115"` for the committing suite,
    /// `"AES/GCM/NoPadding"` for the non-committing suite). This matches the
    /// canonical Java `AesKeyring`, keeping wrapped keys interoperable.
    fn wrap_aad(suite: EncryptionAlgorithm) -> String {
        suite.content_cipher_value()
    }

    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface MUST include the OnEncrypt operation.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnEncrypt operation MUST accept an instance of EncryptionMaterials as input.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnEncrypt operation MUST return an instance of EncryptionMaterials as output.
    //
    //= ../spec/s3-encryption/materials/s3-keyring.md#abstract-methods
    //# - The S3 Keyring MUST define an abstract method GenerateDataKey.
    /// Generate a fresh content data key and wrap it with the configured AES
    /// key (`GenerateDataKey` then `EncryptDataKey`). Returns
    /// `(plaintext_data_key, wrapped_data_key)`. The wrapped form is the
    /// 12-byte GCM IV prepended to the GCM ciphertext-with-tag.
    pub fn wrap(&self, suite: EncryptionAlgorithm) -> Result<(Vec<u8>, Vec<u8>)> {
        let plaintext_data_key = crate::crypto::random_bytes(suite.data_key_length())?;
        let wrapped = self.encrypt_data_key(&plaintext_data_key, suite)?;
        Ok((plaintext_data_key, wrapped))
    }

    //= ../spec/s3-encryption/materials/s3-keyring.md#abstract-methods
    //# - The S3 Keyring MUST define an abstract method EncryptDataKey.
    /// Wrap an already-derived plaintext data key with the configured AES key
    /// (`EncryptDataKey` only, no `GenerateDataKey`). Used by re-encryption,
    /// which preserves the object's existing data key and only re-wraps it
    /// under a new keyring. The wrapped form is the 12-byte GCM IV prepended to
    /// the GCM ciphertext-with-tag.
    pub fn encrypt_data_key(
        &self,
        plaintext_data_key: &[u8],
        suite: EncryptionAlgorithm,
    ) -> Result<Vec<u8>> {
        let aad = Self::wrap_aad(suite);
        crate::crypto::wrap_data_key_aes_gcm(&self.wrapping_key, aad.as_bytes(), plaintext_data_key)
    }

    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface MUST include the OnDecrypt operation.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnDecrypt operation MUST accept an instance of DecryptionMaterials and a collection of EncryptedDataKey instances as input.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnDecrypt operation MUST return an instance of DecryptionMaterials as output.
    //
    //= ../spec/s3-encryption/materials/s3-keyring.md#abstract-methods
    //# - The S3 Keyring MUST define an abstract method DecryptDataKey.
    /// Unwrap a wrapped data key with the configured AES key (`DecryptDataKey`).
    /// `suite` selects the AAD that was bound at wrap time.
    pub fn unwrap(&self, wrapped_data_key: &[u8], suite: EncryptionAlgorithm) -> Result<Vec<u8>> {
        let aad = Self::wrap_aad(suite);
        crate::crypto::unwrap_data_key_aes_gcm(&self.wrapping_key, aad.as_bytes(), wrapped_data_key)
    }
}

//= ../spec/s3-encryption/materials/keyrings.md#interface
//= type=implication
//# The Keyring interface and its operations SHOULD adhere to the naming conventions of the implementation language.
//
//= ../spec/s3-encryption/materials/keyrings.md#supported-keyrings
//= type=implication
//# Note: A user MAY create their own custom keyring(s).
/// A raw RSA keyring that wraps and unwraps content data keys with a
/// caller-supplied RSA key pair using RSA-OAEP-SHA1 (the non-legacy
/// "RSA-OAEP-SHA1" wrapping algorithm).
///
/// Like the [`AesKeyring`] this is a raw (non-KMS) keyring that performs no
/// network calls and stores no AWS KMS encryption context. The wrapping key is
/// the PKCS#8 DER encoding of the RSA private key, exactly as the harness
/// supplies it (`KeyPair.getPrivate().getEncoded()`); the public key used on
/// encrypt is derived from it. The wrapped form follows the canonical Java
/// `RsaKeyring`: a "pseudo data key" that frames the data key together with the
/// suite's content-cipher value, so a wrapped key can only be unwrapped for the
/// algorithm suite it was wrapped for.
#[derive(Clone)]
pub struct RsaKeyring {
    /// PKCS#8 DER-encoded RSA private key.
    private_key_pkcs8: Vec<u8>,
}

impl RsaKeyring {
    /// Construct a raw RSA keyring from a PKCS#8 DER-encoded RSA private key.
    /// A malformed key is rejected lazily by the RSA primitive when wrapping or
    /// unwrapping.
    pub fn new(private_key_pkcs8: Vec<u8>) -> Self {
        Self { private_key_pkcs8 }
    }

    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface MUST include the OnEncrypt operation.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnEncrypt operation MUST accept an instance of EncryptionMaterials as input.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnEncrypt operation MUST return an instance of EncryptionMaterials as output.
    //
    //= ../spec/s3-encryption/materials/s3-keyring.md#abstract-methods
    //# - The S3 Keyring MUST define an abstract method GenerateDataKey.
    /// Generate a fresh content data key and wrap it under the configured RSA
    /// public key (`GenerateDataKey` then `EncryptDataKey`). Returns
    /// `(plaintext_data_key, wrapped_data_key)`. The wrapped form is the
    /// RSA-OAEP-SHA1 ciphertext of the pseudo data key.
    pub fn wrap(&self, suite: EncryptionAlgorithm) -> Result<(Vec<u8>, Vec<u8>)> {
        let plaintext_data_key = crate::crypto::random_bytes(suite.data_key_length())?;
        let wrapped = self.encrypt_data_key(&plaintext_data_key, suite)?;
        Ok((plaintext_data_key, wrapped))
    }

    //= ../spec/s3-encryption/materials/s3-keyring.md#abstract-methods
    //# - The S3 Keyring MUST define an abstract method EncryptDataKey.
    /// Wrap an already-derived plaintext data key under the configured RSA
    /// public key (`EncryptDataKey` only, no `GenerateDataKey`). Used by
    /// re-encryption, which preserves the object's existing data key and only
    /// re-wraps it under a new keyring. The wrapped form is the RSA-OAEP-SHA1
    /// ciphertext of the pseudo data key (which frames the data key with the
    /// suite's content-cipher value).
    pub fn encrypt_data_key(
        &self,
        plaintext_data_key: &[u8],
        suite: EncryptionAlgorithm,
    ) -> Result<Vec<u8>> {
        let content_cipher = suite.content_cipher_value();
        crate::crypto::wrap_data_key_rsa_oaep(
            &self.private_key_pkcs8,
            content_cipher.as_bytes(),
            plaintext_data_key,
        )
    }

    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface MUST include the OnDecrypt operation.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnDecrypt operation MUST accept an instance of DecryptionMaterials and a collection of EncryptedDataKey instances as input.
    //
    //= ../spec/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnDecrypt operation MUST return an instance of DecryptionMaterials as output.
    //
    //= ../spec/s3-encryption/materials/s3-keyring.md#abstract-methods
    //# - The S3 Keyring MUST define an abstract method DecryptDataKey.
    /// Unwrap a wrapped data key with the configured RSA private key
    /// (`DecryptDataKey`). `suite` selects the content-cipher value that was
    /// framed into the pseudo data key at wrap time.
    pub fn unwrap(&self, wrapped_data_key: &[u8], suite: EncryptionAlgorithm) -> Result<Vec<u8>> {
        let content_cipher = suite.content_cipher_value();
        crate::crypto::unwrap_data_key_rsa_oaep(
            &self.private_key_pkcs8,
            content_cipher.as_bytes(),
            wrapped_data_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn build_context_adds_committing_suite_id() {
        let caller = ctx(&[("user", "alice")]);
        let built = KmsKeyring::build_encryption_context(
            &caller,
            EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey,
        );
        assert_eq!(built.get("user").unwrap(), "alice");
        // The committing suite records the decimal suite ID, not the cipher name.
        assert_eq!(built.get(RESERVED_CEK_ALG_KEY).unwrap(), "115");
    }

    #[test]
    fn build_context_adds_gcm_cipher_name() {
        let built = KmsKeyring::build_encryption_context(
            &ctx(&[]),
            EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf,
        );
        assert_eq!(built.get(RESERVED_CEK_ALG_KEY).unwrap(), "AES/GCM/NoPadding");
    }

    #[test]
    fn validate_context_accepts_stored_minus_reserved() {
        let stored = ctx(&[
            ("user", "alice"),
            (RESERVED_CEK_ALG_KEY, "115"),
            (RESERVED_KMS_CMK_ID_KEY, "key-arn"),
        ]);
        let request = ctx(&[("user", "alice")]);
        assert!(KmsKeyring::validate_decryption_context(&stored, &request).is_ok());
    }

    #[test]
    fn validate_context_rejects_mismatch() {
        let stored = ctx(&[("user", "alice"), (RESERVED_CEK_ALG_KEY, "115")]);
        let request = ctx(&[("user", "bob")]);
        let err = KmsKeyring::validate_decryption_context(&stored, &request).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
        // The cross-language harness asserts (case-sensitively) that the
        // decrypt-time context-mismatch message contains this exact phrase,
        // matching the reference (python/java) servers. See
        // RoundTripTests#crossLanguageTestKmsWithSubsetEncCtxFails.
        assert!(
            err.to_string()
                .contains("Provided encryption context does not match information retrieved from S3"),
            "actual: {err}"
        );
    }

    #[test]
    fn validate_context_rejects_missing_subset() {
        // The object was encrypted WITH a caller context, but the decryptor
        // provides NO context at all. Stripping the reserved key still leaves
        // a non-empty stored context, so validation MUST fail closed with the
        // same cross-language message. This mirrors
        // RoundTripTests#crossLanguageTestKmsWithSubsetEncCtxFails, where the
        // GetObject request omits `.metadata(...)` entirely.
        let stored = ctx(&[
            ("user-defined-enc-ctx-key", "user-defined-enc-ctx-value"),
            ("user-defined-enc-ctx-key-2", "user-defined-enc-ctx-value-2"),
            (RESERVED_CEK_ALG_KEY, "AES/GCM/NoPadding"),
        ]);
        let request = ctx(&[]);
        let err = KmsKeyring::validate_decryption_context(&stored, &request).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
        assert!(
            err.to_string()
                .contains("Provided encryption context does not match information retrieved from S3"),
            "actual: {err}"
        );
    }

    #[test]
    fn validate_context_rejects_reserved_key_in_request() {
        let stored = ctx(&[(RESERVED_CEK_ALG_KEY, "115")]);
        let request = ctx(&[(RESERVED_CEK_ALG_KEY, "115")]);
        let err = KmsKeyring::validate_decryption_context(&stored, &request).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn aes_keyring_wrap_unwrap_round_trips() {
        let keyring = AesKeyring::new(vec![0x42u8; 32]);
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let (plaintext_dk, wrapped) = keyring.wrap(suite).unwrap();
        // A fresh 256-bit data key is generated and wrapped (IV + key + tag).
        assert_eq!(plaintext_dk.len(), 32);
        assert_eq!(wrapped.len(), 12 + 32 + 16);
        let recovered = keyring.unwrap(&wrapped, suite).unwrap();
        assert_eq!(recovered, plaintext_dk);
    }

    #[test]
    fn aes_keyring_unwrap_with_wrong_suite_aad_fails() {
        // The wrap AAD is the suite content-cipher value, so unwrapping a
        // committing-suite-wrapped key as a non-committing key must fail.
        let keyring = AesKeyring::new(vec![0x42u8; 32]);
        let (_dk, wrapped) = keyring
            .wrap(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey)
            .unwrap();
        let err = keyring
            .unwrap(&wrapped, EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf)
            .unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn aes_keyring_rejects_wrong_length_key() {
        // A non-256-bit wrapping key is rejected by the AES-256-GCM primitive.
        let keyring = AesKeyring::new(vec![0x42u8; 16]);
        let err = keyring
            .wrap(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey)
            .unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    fn rsa_pkcs8_key() -> Vec<u8> {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
        let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        key.as_der().unwrap().as_ref().to_vec()
    }

    #[test]
    fn rsa_keyring_wrap_unwrap_round_trips() {
        let keyring = RsaKeyring::new(rsa_pkcs8_key());
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let (plaintext_dk, wrapped) = keyring.wrap(suite).unwrap();
        // A fresh 256-bit data key is generated; the wrapped form is the
        // RSA-2048 OAEP ciphertext (256 bytes).
        assert_eq!(plaintext_dk.len(), 32);
        assert_eq!(wrapped.len(), 256);
        let recovered = keyring.unwrap(&wrapped, suite).unwrap();
        assert_eq!(recovered, plaintext_dk);
    }

    #[test]
    fn rsa_keyring_unwrap_with_wrong_suite_fails() {
        // The framed content-cipher value binds the suite, so unwrapping a
        // committing-suite-wrapped key as a non-committing key must fail.
        let keyring = RsaKeyring::new(rsa_pkcs8_key());
        let (_dk, wrapped) = keyring
            .wrap(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey)
            .unwrap();
        let err = keyring
            .unwrap(&wrapped, EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf)
            .unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn rsa_keyring_rejects_invalid_key() {
        let keyring = RsaKeyring::new(b"not a pkcs8 key".to_vec());
        let err = keyring
            .wrap(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey)
            .unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    /// `encrypt_data_key` re-wraps an existing data key (the re-encryption
    /// path: `EncryptDataKey` with no fresh `GenerateDataKey`), and `unwrap`
    /// recovers exactly that data key.
    #[test]
    fn aes_keyring_encrypt_data_key_preserves_existing_key() {
        let keyring = AesKeyring::new(vec![0x42u8; 32]);
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let data_key = vec![0x5Au8; 32];
        let wrapped = keyring.encrypt_data_key(&data_key, suite).unwrap();
        assert_eq!(keyring.unwrap(&wrapped, suite).unwrap(), data_key);
    }

    /// The RSA equivalent: re-wrapping an existing data key under the RSA public
    /// key and recovering it unchanged.
    #[test]
    fn rsa_keyring_encrypt_data_key_preserves_existing_key() {
        let keyring = RsaKeyring::new(rsa_pkcs8_key());
        let suite = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        let data_key = vec![0x5Au8; 32];
        let wrapped = keyring.encrypt_data_key(&data_key, suite).unwrap();
        assert_eq!(keyring.unwrap(&wrapped, suite).unwrap(), data_key);
    }
}
