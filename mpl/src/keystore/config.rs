// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for the [`KeyStore`](super::KeyStore) trait.

/// Configuration for constructing a [`KeyStore`](super::KeyStore).
#[derive(Debug, Clone)]
pub struct KeyStoreConfig {
    /// The DynamoDB table name that backs this Key Store.
    pub ddb_table_name: String,
    /// Configures Key Store's KMS Key ARN restrictions.
    pub kms_configuration: KmsConfiguration,
    /// The logical name for this Key Store, which is cryptographically bound to
    /// the keys it holds. This appears in the Encryption Context of KMS requests
    /// as `tablename`.
    pub logical_key_store_name: String,
    /// An identifier for this Key Store.
    pub id: Option<String>,
    /// The AWS KMS grant tokens that are used when this Key Store calls to AWS KMS.
    pub grant_tokens: Option<Vec<String>>,
}

/// The configuration information for a Key Store, returned by
/// [`KeyStore::get_key_store_info`](super::KeyStore::get_key_store_info).
#[derive(Debug, Clone)]
pub struct KeyStoreInfo {
    /// An identifier for this Key Store.
    pub key_store_id: String,
    /// The DynamoDB table name that backs this Key Store.
    pub key_store_name: String,
    /// The logical name for this Key Store, which is cryptographically bound to
    /// the keys it holds.
    pub logical_key_store_name: String,
    /// The AWS KMS grant tokens that are used when this Key Store calls to AWS KMS.
    pub grant_tokens: Vec<String>,
    /// Configures Key Store's KMS Key ARN restrictions.
    pub kms_configuration: KmsConfiguration,
}

/// Configures Key Store's KMS Key ARN restrictions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KmsConfiguration {
    /// Key Store is restricted to only this KMS Key ARN. If a different KMS Key
    /// ARN is encountered when creating, versioning, or getting a Branch Key or
    /// Beacon Key, KMS is never called and an exception is thrown. While a
    /// Multi-Region Key (MKR) may be provided, the whole ARN, including the
    /// Region, is persisted in Branch Keys and MUST strictly equal this value to
    /// be considered valid.
    KmsKeyArn(String),
    /// If an MRK ARN is provided, and the Key Store table holds an MRK ARN, then
    /// those two ARNs may differ in region, although they must be otherwise
    /// equal. If either ARN is not an MRK ARN, then mrkKmsKeyArn behaves exactly
    /// as kmsKeyArn.
    KmsMrKeyArn(String),
    /// The Key Store can use the KMS Key ARNs already persisted in the Backing
    /// Table. The VersionKey and CreateKey Operations are NOT supported and will
    /// fail with a runtime exception. There is no Multi-Region logic with this
    /// configuration; if a Multi-Region Key is encountered, and the region in the
    /// ARN is not the region of the KMS Client, requests will Fail with KMS
    /// Exceptions.
    Discovery,
    /// The Key Store can use the KMS Key ARNs already persisted in the Backing
    /// Table. The VersionKey and CreateKey Operations are NOT supported and will
    /// fail with a runtime exception. If a Multi-Region Key is encountered, the
    /// region in the ARN is changed to the configured region.
    MrDiscovery {
        /// Any MRK ARN discovered will have its region replaced with this.
        region: String,
    },
}
