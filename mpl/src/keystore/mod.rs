// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The `KeyStore` trait — the abstract contract every key store MUST implement.
//
// # Why `async_trait` and not native AFIT
//
// The same dyn-compatibility rationale recorded in [`crate::keyring`] applies
// here: AFIT traits are not stable-dyn-compatible, the MPL needs `dyn KeyStore`
// and `Box<dyn KeyStore>` for plug-in key store backends (DynamoDB-backed
// branch key store today, potentially other backends later), and `async_trait`
// boxes the future to make `dyn KeyStore` work today.
//

pub mod config;
pub mod error;
pub mod kms_config;

use async_trait::async_trait;

pub use config::{KeyStoreConfig, KeyStoreInfo, KmsConfiguration};
pub use error::{KeyStoreError, KeyStoreErrorKind};

use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Returns the configuration information for a Key Store.
    async fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeyStoreError>;

    /// Create the DynamoDB table that backs this Key Store based on the Key
    /// Store configuration. If a table already exists, validate it is configured
    /// as expected.
    async fn create_key_store(&self) -> Result<String, KeyStoreError>;

    /// Create a new Branch Key in the Key Store. Additionally create a Beacon
    /// Key that is tied to this Branch Key.
    async fn create_key(
        &self,
        branch_key_identifier: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeyStoreError>;

    /// Create a new ACTIVE version of an existing Branch Key in the Key Store,
    /// and set the previously ACTIVE version to DECRYPT_ONLY.
    async fn version_key(&self, branch_key_identifier: String) -> Result<(), KeyStoreError>;

    /// Get the ACTIVE version for a particular Branch Key from the Key Store.
    async fn get_active_branch_key(
        &self,
        branch_key_identifier: String,
    ) -> Result<BranchKeyMaterials, KeyStoreError>;

    /// Get a particular version of a Branch Key from the Key Store.
    async fn get_branch_key_version(
        &self,
        branch_key_identifier: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeyStoreError>;

    /// Get a Beacon Key from the Key Store.
    async fn get_beacon_key(
        &self,
        branch_key_identifier: String,
    ) -> Result<BeaconKeyMaterials, KeyStoreError>;
}
