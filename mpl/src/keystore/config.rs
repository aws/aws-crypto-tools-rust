// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for the [`Keystore`](super::Keystore) trait.

/// Information about a configured keystore, returned by
/// [`Keystore::get_key_store_info`](super::Keystore::get_key_store_info).
#[derive(Debug, Clone)]
pub struct KeyStoreInfo {
    /// The keystore identifier.
    pub keystore_id: String,
    /// The DynamoDB table name.
    pub keystore_name: String,
    /// The logical keystore name.
    pub logical_keystore_name: String,
    /// The configured AWS KMS grant tokens.
    pub grant_tokens: Vec<String>,
    /// The KMS configuration for this keystore.
    pub kms_configuration: KmsConfiguration,
}

/// The KMS key configuration for a keystore.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KmsConfiguration {
    /// Single-region KMS Key ARN compatibility. ARN may be MRK or non-MRK.
    KmsKeyArn(String),
    /// MRK ARN compatibility. ARN may be MRK or non-MRK.
    KmsMrKeyArn(String),
    /// Discovery configuration; KMS Key ARN is read from each DDB record.
    Discovery,
    /// MRDiscovery configuration with required region argument.
    MrDiscovery {
        /// The region to use for MRK ARN rewrites.
        region: String,
    },
}

impl KmsConfiguration {
    /// A [`KmsConfiguration::KmsKeyArn`] for `arn`.
    #[must_use]
    pub fn kms_key_arn(arn: impl Into<String>) -> Self {
        Self::KmsKeyArn(arn.into())
    }

    /// A [`KmsConfiguration::KmsMrKeyArn`] for `arn`.
    #[must_use]
    pub fn kms_mr_key_arn(arn: impl Into<String>) -> Self {
        Self::KmsMrKeyArn(arn.into())
    }

    /// A [`KmsConfiguration::MrDiscovery`] for `region`.
    #[must_use]
    pub fn mr_discovery(region: impl Into<String>) -> Self {
        Self::MrDiscovery {
            region: region.into(),
        }
    }
}
