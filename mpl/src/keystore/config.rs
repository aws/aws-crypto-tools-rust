// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for the [`Keystore`](super::Keystore) trait.

/// Configuration for constructing a [`Keystore`](super::Keystore).
#[derive(Debug, Clone)]
pub struct KeyStoreConfig {
    /// The DynamoDB table name backing this keystore.
    pub ddb_table_name: String,
    /// The KMS key configuration governing encryption/decryption.
    pub kms_configuration: KmsConfiguration,
    /// Logical name cryptographically bound to all keys in this table.
    pub logical_keystore_name: String,
    /// Optional keystore identifier.
    pub id: Option<String>,
    /// Optional AWS KMS grant tokens.
    pub grant_tokens: Option<Vec<String>>,
}

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
    pub aws_kms_grant_tokens: Vec<String>,
    /// The KMS configuration for this keystore.
    pub aws_kms_configuration: KmsConfiguration,
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
