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

/// Reserved encryption-context key holding the content algorithm. The S3EC
/// owns this key; callers MUST NOT supply it.
pub const RESERVED_CEK_ALG_KEY: &str = "aws:x-amz-cek-alg";
/// Reserved encryption-context key used by the legacy KmsV1 mode.
pub const RESERVED_KMS_CMK_ID_KEY: &str = "kms_cmk_id";

/// A KMS-backed keyring that wraps and unwraps content data keys.
#[derive(Clone)]
pub struct KmsKeyring {
    kms: aws_sdk_kms::Client,
    kms_key_id: String,
    enable_legacy_wrapping_algorithms: bool,
}

impl KmsKeyring {
    //= spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //# On initialization, the caller MUST provide an AWS KMS key identifier.
    /// Construct a keyring from a KMS client, key identifier, and the legacy
    /// wrapping-algorithm flag.
    pub fn new(
        kms: aws_sdk_kms::Client,
        kms_key_id: String,
        enable_legacy_wrapping_algorithms: bool,
    ) -> Self {
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

        //= spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# When decrypting using Kms+Context mode, the KmsKeyring MUST validate the provided (request) encryption context with the stored (materials) encryption context.
        //
        //= spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# The stored encryption context with the two reserved keys removed MUST match the provided encryption context.
        let mut stripped = stored.clone();
        stripped.remove(RESERVED_CEK_ALG_KEY);
        stripped.remove(RESERVED_KMS_CMK_ID_KEY);

        //= spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# If the stored encryption context with the two reserved keys removed does not match the provided encryption context, the KmsKeyring MUST throw an exception.
        if &stripped != request {
            return Err(S3EncryptionError::Crypto(
                "Provided encryption context does not match information retrieved from S3"
                    .to_string(),
            ));
        }
        Ok(())
    }

    //= spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
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
        //= spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
        //# The KmsKeyring MUST determine whether to decrypt using KmsV1 mode or Kms+Context mode.
        match wrap_algorithm {
            //= spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
            //# If the Key Provider Info of the Encrypted Data Key is "kms+context", the KmsKeyring MUST attempt to decrypt using Kms+Context mode.
            WRAP_ALG_KMS_CONTEXT => {
                Self::validate_decryption_context(stored_context, request_context)?;
            }
            //= spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
            //# If the Key Provider Info of the Encrypted Data Key is "kms", the KmsKeyring MUST attempt to decrypt using KmsV1 mode.
            WRAP_ALG_KMS_V1 => {
                //= spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
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

        //= spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
        let response = self
            .kms
            .decrypt()
            .key_id(&self.kms_key_id)
            .ciphertext_blob(Blob::new(encrypted_data_key.to_vec()))
            .set_encryption_context(Some(context))
            .send()
            .await
            //= spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
            .map_err(|e| S3EncryptionError::Sdk(format!("KMS Decrypt failed: {e}")))?;

        //= spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# The KmsKeyring MUST immediately return the plaintext as a collection of bytes.
        let plaintext = response
            .plaintext()
            .ok_or_else(|| S3EncryptionError::Sdk("KMS Decrypt returned no plaintext".into()))?
            .as_ref()
            .to_vec();
        Ok(plaintext)
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
    fn validate_context_rejects_reserved_key_in_request() {
        let stored = ctx(&[(RESERVED_CEK_ALG_KEY, "115")]);
        let request = ctx(&[(RESERVED_CEK_ALG_KEY, "115")]);
        let err = KmsKeyring::validate_decryption_context(&stored, &request).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }
}
