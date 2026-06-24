// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for the S3 Encryption Client.
//!
//! These mirror the test-harness Smithy `S3ECConfig` shape and the
//! configuration requirements in `spec/s3-encryption/client.md`.

use crate::error::{Result, S3EncryptionError};

/// Content-encryption algorithm suite.
///
/// Values match the Smithy `EncryptionAlgorithm` enum used by the
/// cross-implementation test harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// Legacy, unauthenticated AES-CBC. Not permitted for encryption.
    AlgAes256CbcIv16NoKdf,
    /// AES-256-GCM without key commitment (V4 default, non-committing).
    AlgAes256GcmIv12Tag16NoKdf,
    /// AES-256-GCM with HKDF-SHA512 key commitment (V4 committing suite).
    AlgAes256GcmHkdfSha512CommitKey,
}

impl EncryptionAlgorithm {
    /// Parse the Smithy enum string form.
    pub fn from_smithy(s: &str) -> Result<Self> {
        match s {
            "ALG_AES_256_CBC_IV16_NO_KDF" => Ok(Self::AlgAes256CbcIv16NoKdf),
            "ALG_AES_256_GCM_IV12_TAG16_NO_KDF" => Ok(Self::AlgAes256GcmIv12Tag16NoKdf),
            "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY" => Ok(Self::AlgAes256GcmHkdfSha512CommitKey),
            other => Err(S3EncryptionError::Configuration(format!(
                "unknown encryption algorithm: {other}"
            ))),
        }
    }

    /// Whether this suite is a legacy (unauthenticated) content algorithm.
    pub fn is_legacy(self) -> bool {
        matches!(self, Self::AlgAes256CbcIv16NoKdf)
    }

    /// Whether this suite provides key commitment.
    pub fn is_committing(self) -> bool {
        matches!(self, Self::AlgAes256GcmHkdfSha512CommitKey)
    }
}

/// Key commitment policy.
///
/// Values match the Smithy `CommitmentPolicy` enum used by the harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentPolicy {
    /// Require commitment on both encrypt and decrypt.
    RequireEncryptRequireDecrypt,
    /// Require commitment on encrypt, allow either on decrypt.
    RequireEncryptAllowDecrypt,
    /// Forbid commitment on encrypt, allow either on decrypt.
    ForbidEncryptAllowDecrypt,
}

impl CommitmentPolicy {
    /// Parse the Smithy enum string form.
    pub fn from_smithy(s: &str) -> Result<Self> {
        match s {
            "REQUIRE_ENCRYPT_REQUIRE_DECRYPT" => Ok(Self::RequireEncryptRequireDecrypt),
            "REQUIRE_ENCRYPT_ALLOW_DECRYPT" => Ok(Self::RequireEncryptAllowDecrypt),
            "FORBID_ENCRYPT_ALLOW_DECRYPT" => Ok(Self::ForbidEncryptAllowDecrypt),
            other => Err(S3EncryptionError::Configuration(format!(
                "unknown commitment policy: {other}"
            ))),
        }
    }
}

/// Configuration for an [`crate::client::S3EncryptionClient`].
#[derive(Debug, Clone)]
pub struct S3EncryptionConfig {
    /// KMS key identifier (ARN/alias) used by the KMS keyring.
    pub kms_key_id: Option<String>,
    /// Whether legacy wrapping algorithms are permitted on decrypt.
    pub enable_legacy_wrapping_algorithms: bool,
    /// Whether legacy (unauthenticated) content algorithms are permitted on decrypt.
    pub enable_legacy_unauthenticated_modes: bool,
    /// Whether delayed authentication mode is enabled.
    pub enable_delayed_authentication_mode: bool,
    /// Optional buffer size (max ciphertext bytes held in memory).
    pub buffer_size: Option<u64>,
    /// Configured content-encryption algorithm suite.
    pub encryption_algorithm: Option<EncryptionAlgorithm>,
    /// Configured key commitment policy.
    pub commitment_policy: Option<CommitmentPolicy>,
}

// The manual `Default` impl is kept (rather than `#[derive(Default)]`) because
// it hosts the duvet `//=` spec annotations for the "MUST be set to false by
// default" requirements below. Deriving would delete those citations.
#[allow(clippy::derivable_impls)]
impl Default for S3EncryptionConfig {
    fn default() -> Self {
        Self {
            kms_key_id: None,
            //= spec/s3-encryption/client.md#enable-legacy-wrapping-algorithms
            //# The option to enable legacy wrapping algorithms MUST be set to false by default.
            enable_legacy_wrapping_algorithms: false,
            //= spec/s3-encryption/client.md#enable-legacy-unauthenticated-modes
            //# The option to enable legacy unauthenticated modes MUST be set to false by default.
            enable_legacy_unauthenticated_modes: false,
            //= spec/s3-encryption/client.md#enable-delayed-authentication
            //# Delayed Authentication mode MUST be set to false by default.
            enable_delayed_authentication_mode: false,
            buffer_size: None,
            encryption_algorithm: None,
            commitment_policy: None,
        }
    }
}

/// The default content-encryption suite when none is configured: the
/// key-committing AES-GCM suite (persisted as the V3 content format).
pub const DEFAULT_ENCRYPTION_ALGORITHM: EncryptionAlgorithm =
    EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;

/// The default key commitment policy when none is configured.
pub const DEFAULT_COMMITMENT_POLICY: CommitmentPolicy =
    CommitmentPolicy::RequireEncryptRequireDecrypt;

impl S3EncryptionConfig {
    /// The encryption algorithm suite to use for PutObject, applying the
    /// default ([`DEFAULT_ENCRYPTION_ALGORITHM`]) when none is configured.
    pub fn effective_encryption_algorithm(&self) -> EncryptionAlgorithm {
        self.encryption_algorithm
            .unwrap_or(DEFAULT_ENCRYPTION_ALGORITHM)
    }

    /// The key commitment policy to enforce, applying the default
    /// ([`DEFAULT_COMMITMENT_POLICY`]) when none is configured.
    pub fn effective_commitment_policy(&self) -> CommitmentPolicy {
        self.commitment_policy.unwrap_or(DEFAULT_COMMITMENT_POLICY)
    }

    /// Validate the configuration against the requirements in `client.md`.
    pub fn validate(&self) -> Result<()> {
        //= spec/s3-encryption/client.md#set-buffer-size
        //# If Delayed Authentication mode is enabled, and the buffer size has been set to a value other than its default, the S3EC MUST throw an exception.
        if self.enable_delayed_authentication_mode && self.buffer_size.is_some() {
            return Err(S3EncryptionError::Configuration(
                "buffer size must not be set when delayed authentication mode is enabled"
                    .to_string(),
            ));
        }

        if let Some(alg) = self.encryption_algorithm {
            //= spec/s3-encryption/client.md#encryption-algorithm
            //# The S3EC MUST validate that the configured encryption algorithm is not legacy.
            //# If the configured encryption algorithm is legacy, then the S3EC MUST throw an exception.
            if alg.is_legacy() {
                return Err(S3EncryptionError::Configuration(
                    "configured encryption algorithm is legacy and not permitted for encryption"
                        .to_string(),
                ));
            }
        }

        //= spec/s3-encryption/client.md#key-commitment
        //# The S3EC MUST validate the configured Encryption Algorithm against the provided key commitment policy.
        let alg = self.effective_encryption_algorithm();
        match self.effective_commitment_policy() {
            //= spec/s3-encryption/key-commitment.md#commitment-policy
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
            //
            //= spec/s3-encryption/key-commitment.md#commitment-policy
            //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
            CommitmentPolicy::RequireEncryptAllowDecrypt
            | CommitmentPolicy::RequireEncryptRequireDecrypt => {
                if !alg.is_committing() {
                    //= spec/s3-encryption/client.md#key-commitment
                    //# If the configured Encryption Algorithm is incompatible with the key commitment policy, then it MUST throw an exception.
                    return Err(S3EncryptionError::Configuration(
                        "commitment policy requires a key-committing algorithm suite, but the \
                         configured algorithm suite does not support key commitment"
                            .to_string(),
                    ));
                }
            }
            //= spec/s3-encryption/key-commitment.md#commitment-policy
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            CommitmentPolicy::ForbidEncryptAllowDecrypt => {
                if alg.is_committing() {
                    //= spec/s3-encryption/client.md#key-commitment
                    //# If the configured Encryption Algorithm is incompatible with the key commitment policy, then it MUST throw an exception.
                    return Err(S3EncryptionError::Configuration(
                        "commitment policy forbids key-committing algorithm suites, but the \
                         configured algorithm suite supports key commitment"
                            .to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}
