// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for the S3 Encryption Client.

/// Errors that can be produced by the S3 Encryption Client.
#[derive(Debug, thiserror::Error)]
pub enum S3EncryptionError {
    /// The client was configured in an invalid way.
    #[error("invalid S3EC configuration: {0}")]
    Configuration(String),

    /// A legacy algorithm was requested while legacy support is disabled.
    #[error("legacy algorithm not permitted: {0}")]
    LegacyNotEnabled(String),

    /// The cryptographic operation failed.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// The on-the-wire ciphertext / metadata could not be parsed.
    #[error("invalid ciphertext format: {0}")]
    Format(String),

    /// An error surfaced by the underlying AWS SDK (S3 or KMS).
    #[error("AWS SDK error: {0}")]
    Sdk(String),
}

/// Convenience result alias for S3EC operations.
pub type Result<T> = std::result::Result<T, S3EncryptionError>;
