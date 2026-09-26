// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The `Keystore` trait — the abstract contract every keystore MUST implement.
//
// # Why `async_trait` and not native AFIT
//
// The same dyn-compatibility rationale recorded in [`crate::keyring`] applies
// here: AFIT traits are not stable-dyn-compatible, the MPL needs `dyn Keystore`
// and `Box<dyn Keystore>` for plug-in keystore backends (DynamoDB-backed
// branch key store today, potentially other backends later), and `async_trait`
// boxes the future to make `dyn Keystore` work today.
//

pub mod attributes;
pub mod branch_key_store;
pub mod config;
pub mod encryption_context;
pub mod error;
pub mod kms_config;
pub(crate) mod kms_ops;
pub mod record;

use async_trait::async_trait;

pub use branch_key_store::BranchKeyStore;
pub use config::{KeyStoreConfig, KeyStoreInfo, KmsConfiguration};
pub use error::{KeystoreError, KeystoreErrorKind};

use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

/// The interface every keystore implements.
///
/// To hold a keystore whose concrete type is chosen at runtime, use [`SharedKeystore`].
#[async_trait]
pub trait Keystore: Send + Sync {
    /// Returns the keystore information for this keystore.
    ///
    /// This is the keystore's own configuration, fixed when the keystore was
    /// constructed, so it is synchronous and performs no IO. Callers that
    /// need it on every operation — for example the Hierarchical Keyring's
    /// cache identifiers, which bind the logical keystore name — can
    /// therefore resolve it once at construction.
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError>;

    /// Creates the backing DynamoDB table for this keystore.
    async fn create_key_store(&self) -> Result<String, KeystoreError>;

    /// Creates a new branch key + beacon key pair in this keystore.
    async fn create_key(
        &self,
        branch_key_id: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, KeystoreError>;

    /// Rotates the ACTIVE branch key to a new version.
    async fn version_key(&self, branch_key_id: String) -> Result<(), KeystoreError>;

    /// Returns the ACTIVE branch key materials for the given branch-key-id.
    async fn get_active_branch_key(
        &self,
        branch_key_id: String,
    ) -> Result<BranchKeyMaterials, KeystoreError>;

    /// Returns branch key materials for a specific version.
    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, KeystoreError>;

    /// Returns the active beacon key materials for the given branch-key-id.
    async fn get_beacon_key(
        &self,
        branch_key_id: String,
    ) -> Result<BeaconKeyMaterials, KeystoreError>;
}

crate::shared::shared_handle!(
    /// A keystore whose concrete type is not known at compile time.
    ///
    /// [`Keystore`] is the trait a keystore implements.
    /// `SharedKeystore` holds any value that implements it.
    /// APIs that accept a keystore take `impl Into<SharedKeystore>`,
    /// so callers usually pass the concrete keystore and never name this type.
    SharedKeystore,
    Keystore
);
