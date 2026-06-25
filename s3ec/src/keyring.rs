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
//
//= ../spec/s3-encryption/materials/s3-kms-keyring.md#interface
//= type=implication
//= reason=KmsKeyring exposes the wrap/unwrap (OnEncrypt/OnDecrypt) keyring operations and the S3 Keyring wrapping behavior
//# The KmsKeyring MUST implement the [Keyring interface](keyrings.md#interface) and include the behavior described in the [S3 Keyring](s3-keyring.md).
/// A KMS-backed keyring that wraps and unwraps content data keys.
#[derive(Clone)]
pub struct KmsKeyring {
    kms: aws_sdk_kms::Client,
    kms_key_id: String,
    enable_legacy_wrapping_algorithms: bool,
}

impl KmsKeyring {
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //= type=implication
    //= reason=new() takes aws_sdk_kms::Client by value; the optional/default-client choice is made by the caller (S3EncryptionClient::from_config)
    //# On initialization, the caller MAY provide an AWS KMS SDK client instance.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //= type=implication
    //= reason=the default KMS client is constructed in S3EncryptionClient::from_config and passed in; KmsKeyring always holds a concrete client
    //# If the caller does not provide an AWS KMS SDK client instance or provides a null value, the KmsKeyring MUST create a default KMS client instance.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //= type=implication
    //= reason=kms_key_id is a non-Optional String parameter; a key identifier is required to construct the keyring
    //# On initialization, the caller MUST provide an AWS KMS key identifier.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //= type=exception
    //= reason=this keyring does not perform the optional null/empty key-id validation; an unusable key id surfaces as a KMS error at call time
    //# The KmsKeyring MAY validate that the AWS KMS key identifier is not null or empty.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //= type=exception
    //= reason=we do not perform the optional not-null/empty validation, so its conditional throw does not apply
    //# If the KmsKeyring validates that the AWS KMS key identifier is not null or empty, then it MUST throw an exception.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //= type=exception
    //= reason=this keyring does not perform the optional KMS-ARN-format validation; an invalid id surfaces as a KMS error at call time
    //# The KmsKeyring MAY validate that the AWS KMS key identifier is [a valid AWS KMS Key identifier](../../framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-identifier).
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#initialization
    //= type=exception
    //= reason=we do not perform the optional KMS-ARN-format validation, so its conditional throw does not apply
    //# If the KmsKeyring validates that the AWS KMS key identifier is not a valid AWS KMS Key identifier, then it MUST throw an exception.
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
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    //= type=implication
    //= reason=there is no KmsV1 encryption code path; wrap() only ever issues a Kms+Context request, so KmsV1 encryption is unsupported by construction
    //# The KmsKeyring MUST NOT support encryption using KmsV1 mode.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //# The KmsKeyring MUST implement the EncryptDataKey method.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //= type=exception
    //= reason=every shipping S3EC reference (Java, Python) calls KMS GenerateDataKey, not Encrypt, for the Kms+Context wrapping mode; this keyring matches them for wire compatibility (see module doc)
    //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //= type=exception
    //= reason=GenerateDataKey produces the plaintext data key itself, so there is no PlaintextDataKey request field to populate from input materials
    //# - `PlaintextDataKey` MUST be the plaintext data key in the [encryption materials](../structures.md#encryption-materials).
    //
    //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
    //= type=exception
    //= reason=a custom API name / user agent is optional (SHOULD) and is not configured on KMS calls in this implementation
    //# - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.
    /// Wrap a freshly generated data key via `KMS GenerateDataKey`.
    ///
    /// Returns `(plaintext_data_key, encrypted_data_key)`.
    pub async fn wrap(&self, encryption_context: &BTreeMap<String, String>) -> Result<(Vec<u8>, Vec<u8>)> {
        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
        //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [encryption materials](../structures.md#encryption-materials).
        let context: std::collections::HashMap<String, String> =
            encryption_context.clone().into_iter().collect();

        let response = self
            .kms
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
            //# - `KeyId` MUST be the configured AWS KMS key identifier.
            .generate_data_key()
            .key_id(&self.kms_key_id)
            .key_spec(DataKeySpec::Aes256)
            .set_encryption_context(Some(context))
            .send()
            .await
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
            //# If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
            .map_err(|e| S3EncryptionError::Sdk(format!("KMS GenerateDataKey failed: {e}")))?;

        let plaintext = response
            .plaintext()
            .ok_or_else(|| S3EncryptionError::Sdk("KMS GenerateDataKey returned no plaintext".into()))?
            .as_ref()
            .to_vec();

        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
        //# If the call to AWS KMS Encrypt is successful, OnEncrypt MUST return the `CiphertextBlob` as a collection of bytes.
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
            //
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
            //# The KmsKeyring MUST support decryption using Kms+Context mode.
            //
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
            //= reason=the Kms+Context arm has no legacy gate, so it is always enabled regardless of enable_legacy_wrapping_algorithms
            //# The Kms+Context mode MUST be enabled as a fully-supported (non-legacy) wrapping algorithm.
            WRAP_ALG_KMS_CONTEXT => {
                Self::validate_decryption_context(stored_context, request_context)?;
            }
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
            //# If the Key Provider Info of the Encrypted Data Key is "kms", the KmsKeyring MUST attempt to decrypt using KmsV1 mode.
            //
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
            //# The KmsKeyring MUST support decryption using KmsV1 mode.
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

        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
        //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
        //
        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
        //
        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
        //= type=exception
        //= reason=a custom API name / user agent is optional (SHOULD) and is not configured on KMS calls in this implementation
        //# - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.
        //
        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
        //= type=exception
        //= reason=a custom API name / user agent is optional (SHOULD) and is not configured on KMS calls in this implementation
        //# - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.
        let response = self
            .kms
            .decrypt()
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            //# - `KeyId` MUST be the configured AWS KMS key identifier.
            //
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# - `KeyId` MUST be the configured AWS KMS key identifier.
            .key_id(&self.kms_key_id)
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
            //
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
            .ciphertext_blob(Blob::new(encrypted_data_key.to_vec()))
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).
            //
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).
            .set_encryption_context(Some(context))
            .send()
            .await
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            //# If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
            //
            //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
            .map_err(|e| S3EncryptionError::Sdk(format!("KMS Decrypt failed: {e}")))?;

        //= ../spec/s3-encryption/materials/s3-kms-keyring.md#kmsv1
        //# The KmsKeyring MUST immediately return the plaintext as a collection of bytes.
        //
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

    //= ../spec/s3-encryption/materials/s3-keyring.md#abstract-methods
    //# - The S3 Keyring MUST define an abstract method DecryptDataKey.
    /// Unwrap a wrapped data key with the configured AES key (`DecryptDataKey`).
    /// `suite` selects the AAD that was bound at wrap time.
    pub fn unwrap(&self, wrapped_data_key: &[u8], suite: EncryptionAlgorithm) -> Result<Vec<u8>> {
        let aad = Self::wrap_aad(suite);
        crate::crypto::unwrap_data_key_aes_gcm(&self.wrapping_key, aad.as_bytes(), wrapped_data_key)
    }
}

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

    /// Generate a fresh content data key and wrap it under the configured RSA
    /// public key (`GenerateDataKey` then `EncryptDataKey`). Returns
    /// `(plaintext_data_key, wrapped_data_key)`. The wrapped form is the
    /// RSA-OAEP-SHA1 ciphertext of the pseudo data key.
    pub fn wrap(&self, suite: EncryptionAlgorithm) -> Result<(Vec<u8>, Vec<u8>)> {
        let plaintext_data_key = crate::crypto::random_bytes(suite.data_key_length())?;
        let wrapped = self.encrypt_data_key(&plaintext_data_key, suite)?;
        Ok((plaintext_data_key, wrapped))
    }

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
