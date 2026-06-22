// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for the [`Keystore`](super::Keystore) trait.

//= ../spec/framework/branch-key-store.md#initialization
//= type=implication
//# The following inputs MAY be specified to create a KeyStore:
//
//= ../spec/framework/branch-key-store.md#initialization
//= type=implication
//# The following inputs MUST be specified to create a KeyStore:
//
//= ../spec/framework/branch-key-store.md#getkeystoreinfo
//= type=implication
//# This MUST include:
/// Configuration for constructing a [`Keystore`](super::Keystore).
#[derive(Debug, Clone)]
pub struct KeyStoreConfig {
    /// The DynamoDB table name backing this keystore.
    pub table_name: String,
    /// The KMS key configuration governing encryption/decryption.
    pub kms_configuration: KmsConfiguration,
    /// Logical name cryptographically bound to all keys in this table.
    pub logical_keystore_name: String,
    /// Optional keystore identifier; Phase 4 will default to UUID v4.
    pub keystore_id: Option<String>,
    /// Optional AWS KMS grant tokens.
    pub aws_kms_grant_tokens: Option<Vec<String>>,
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

//= ../spec/framework/branch-key-store.md#aws-kms-configuration
//= type=implication
//# `KMS Key ARN` and `KMS MRKey ARN` MUST take an additional argument
//# that is a KMS ARN.
//
//= ../spec/framework/branch-key-store.md#aws-kms-configuration
//= type=implication
//# To be clear, an KMS ARN for a Multi-Region Key MAY be provided to the `KMS Key ARN` configuration,
//# and a KMS ARN for non Multi-Region Key MAY be provided to the `KMS MRKey ARN` configuration.
//
//= ../spec/framework/branch-key-store.md#aws-kms-configuration
//= type=implication
//# `MRDiscovery` MUST take an additional argument, which is a region.
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
