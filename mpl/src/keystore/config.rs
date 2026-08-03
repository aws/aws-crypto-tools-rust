// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for the [`Keystore`](super::Keystore) trait.

use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_kms::Client as KmsClient;

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
    /// Optional DynamoDB client used to call Amazon DynamoDB. If `None`, a
    /// default client is created using the Region parsed from the KMS ARN
    /// (see [`BranchKeyStore::new`](super::BranchKeyStore::new)).
    pub ddb_client: Option<DynamoDbClient>,
    /// Optional AWS KMS client used to call AWS KMS. If `None`, a default
    /// client is created using the Region parsed from the KMS ARN.
    pub kms_client: Option<KmsClient>,
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
