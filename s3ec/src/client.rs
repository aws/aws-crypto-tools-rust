// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The top-level S3 Encryption Client (S3EC).

use crate::config::S3EncryptionConfig;
use crate::error::Result;

/// Client-side encrypting wrapper around the AWS S3 client.
///
/// Holds the validated [`S3EncryptionConfig`] together with the wrapped
/// S3 and KMS SDK clients. Content encryption (PutObject) and decryption
/// (GetObject) are layered on in later milestones.
#[derive(Clone)]
pub struct S3EncryptionClient {
    config: S3EncryptionConfig,
    s3: aws_sdk_s3::Client,
    kms: aws_sdk_kms::Client,
}

impl S3EncryptionClient {
    //= spec/s3-encryption/client.md#cryptographic-materials
    //# The S3EC MUST accept either one CMM or one Keyring instance upon initialization.
    /// Construct a client from a validated config and the wrapped SDK clients.
    pub fn new(
        config: S3EncryptionConfig,
        s3: aws_sdk_s3::Client,
        kms: aws_sdk_kms::Client,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self { config, s3, kms })
    }

    /// The client's configuration.
    pub fn config(&self) -> &S3EncryptionConfig {
        &self.config
    }

    /// The wrapped S3 client.
    pub fn s3(&self) -> &aws_sdk_s3::Client {
        &self.s3
    }

    /// The wrapped KMS client.
    pub fn kms(&self) -> &aws_sdk_kms::Client {
        &self.kms
    }
}
