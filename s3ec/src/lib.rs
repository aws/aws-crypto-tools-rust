// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS S3 Encryption Client (S3EC) for Rust.
//!
//! Client-side encryption for Amazon S3 targeting the V4 message format with
//! a KMS keyring and AES-GCM content encryption. This crate is built
//! incrementally against the specification in `spec/s3-encryption`.

pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod keyring;
pub mod metadata;
pub mod suite;

pub use client::S3EncryptionClient;
pub use config::{CommitmentPolicy, EncryptionAlgorithm, S3EncryptionConfig};
pub use error::{Result, S3EncryptionError};
pub use metadata::ObjectMetadata;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_disables_legacy_and_delayed_auth() {
        let cfg = S3EncryptionConfig::default();
        assert!(!cfg.enable_legacy_wrapping_algorithms);
        assert!(!cfg.enable_legacy_unauthenticated_modes);
        assert!(!cfg.enable_delayed_authentication_mode);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn buffer_size_with_delayed_auth_is_rejected() {
        let cfg = S3EncryptionConfig {
            enable_delayed_authentication_mode: true,
            buffer_size: Some(4096),
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(S3EncryptionError::Configuration(_))
        ));
    }

    #[test]
    fn legacy_encryption_algorithm_is_rejected() {
        let cfg = S3EncryptionConfig {
            encryption_algorithm: Some(EncryptionAlgorithm::AlgAes256CbcIv16NoKdf),
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(S3EncryptionError::Configuration(_))
        ));
    }

    #[test]
    fn smithy_enum_parsing_roundtrips() {
        assert_eq!(
            EncryptionAlgorithm::from_smithy("ALG_AES_256_GCM_IV12_TAG16_NO_KDF").unwrap(),
            EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf
        );
        assert_eq!(
            CommitmentPolicy::from_smithy("REQUIRE_ENCRYPT_REQUIRE_DECRYPT").unwrap(),
            CommitmentPolicy::RequireEncryptRequireDecrypt
        );
        assert!(EncryptionAlgorithm::from_smithy("BOGUS").is_err());
    }

    /// FORBID_ENCRYPT_ALLOW_DECRYPT must reject a key-committing encryption
    /// algorithm at config validation time.
    #[test]
    fn forbid_policy_rejects_committing_algorithm() {
        let cfg = S3EncryptionConfig {
            commitment_policy: Some(CommitmentPolicy::ForbidEncryptAllowDecrypt),
            encryption_algorithm: Some(EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey),
            ..Default::default()
        };
        //= ../spec/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
        assert!(matches!(
            cfg.validate(),
            Err(S3EncryptionError::Configuration(_))
        ));
    }

    /// REQUIRE_ENCRYPT_ALLOW_DECRYPT must reject a non-committing encryption
    /// algorithm at config validation time.
    #[test]
    fn require_allow_policy_requires_committing_algorithm() {
        let cfg = S3EncryptionConfig {
            commitment_policy: Some(CommitmentPolicy::RequireEncryptAllowDecrypt),
            encryption_algorithm: Some(EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf),
            ..Default::default()
        };
        //= ../spec/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        assert!(matches!(
            cfg.validate(),
            Err(S3EncryptionError::Configuration(_))
        ));
    }

    /// REQUIRE_ENCRYPT_REQUIRE_DECRYPT must reject a non-committing encryption
    /// algorithm at config validation time.
    #[test]
    fn require_require_policy_requires_committing_algorithm() {
        let cfg = S3EncryptionConfig {
            commitment_policy: Some(CommitmentPolicy::RequireEncryptRequireDecrypt),
            encryption_algorithm: Some(EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf),
            ..Default::default()
        };
        //= ../spec/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        assert!(matches!(
            cfg.validate(),
            Err(S3EncryptionError::Configuration(_))
        ));
    }
}
