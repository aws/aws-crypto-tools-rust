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
pub mod kms_config;
pub(crate) mod kms_ops;
pub mod record;

use crate::Error;
use async_trait::async_trait;

pub use branch_key_store::{BranchKeyStore, BranchKeyStoreBuilder};
pub use config::{Discovery, KeyStoreInfo, KmsConfiguration, MrDiscovery};

use crate::structures::{BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext};

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
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation reads only in-memory
    /// configuration and never returns an error. Other implementations may
    /// return any variant.
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, Error>;

    /// Creates the backing DynamoDB table for this keystore.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`Validation`](crate::Error::Validation): the table exists but does not match the required key store schema.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an Amazon DynamoDB call failed, or returned a success response with no table description or ARN (`Service`); `resource()` is the table.
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request failed.
    ///
    /// Other implementations may return different variants.
    async fn create_key_store(&self) -> Result<String, Error>;

    /// Creates a new branch key + beacon key pair in this keystore.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`Validation`](crate::Error::Validation): the input is invalid, for example a caller-supplied branch key id without an encryption context, a non-single-key KMS configuration, or an invalid encryption context.
    /// - [`Conflict`](crate::Error::Conflict): the branch key id already exists; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no ciphertext (`Service`); `resource()` is the KMS key or the table.
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request or formatting the record timestamp failed.
    ///
    /// Other implementations may return different variants.
    async fn create_key(
        &self,
        branch_key_id: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, Error>;

    /// Rotates the ACTIVE branch key to a new version.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`Validation`](crate::Error::Validation): the KMS configuration is not a single key, or the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the ACTIVE record is missing a required attribute or is malformed; `resource()` is the branch key.
    /// - [`Cryptographic`](crate::Error::Cryptographic): AWS KMS rejected the stored ACTIVE record as tampered with (`InvalidCiphertextException`).
    /// - [`Conflict`](crate::Error::Conflict): the branch key was rotated concurrently; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no ciphertext (`Service`); `resource()` is the KMS key or the table. `ResourceNotFound` also when no ACTIVE record exists for the branch key (`resource()` is the branch key).
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request or formatting the record timestamp failed.
    ///
    /// Other implementations may return different variants.
    async fn version_key(&self, branch_key_id: String) -> Result<(), Error>;

    /// Returns the ACTIVE branch key materials for the given branch-key-id.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keystore record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no plaintext (`Service`); `resource()` is the KMS key or the table. `ResourceNotFound` also when no keystore record exists for the branch key (`resource()` is the branch key).
    ///
    /// Other implementations may return different variants.
    async fn get_active_branch_key(
        &self,
        branch_key_id: String,
    ) -> Result<BranchKeyMaterials, Error>;

    /// Returns branch key materials for a specific version.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keystore record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no plaintext (`Service`); `resource()` is the KMS key or the table. `ResourceNotFound` also when no keystore record exists for the branch key (`resource()` is the branch key).
    ///
    /// Other implementations may return different variants.
    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, Error>;

    /// Returns the active beacon key materials for the given branch-key-id.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the keystore record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed, or AWS KMS returned no plaintext (`Service`); `resource()` is the KMS key or the table. `ResourceNotFound` also when no keystore record exists for the branch key (`resource()` is the branch key).
    ///
    /// Other implementations may return different variants.
    async fn get_beacon_key(&self, branch_key_id: String) -> Result<BeaconKeyMaterials, Error>;
}

crate::shared::shared_handle!(
    /// A keystore whose concrete type is chosen at runtime.
    ///
    /// It implements [`Keystore`], so it can be passed anywhere a keystore is accepted.
    /// Callers that know their keystore's type pass it directly and never need this one.
    SharedKeystore,
    Keystore
);

#[async_trait]
impl Keystore for SharedKeystore {
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, Error> {
        self.0.get_key_store_info()
    }

    async fn create_key_store(&self) -> Result<String, Error> {
        self.0.create_key_store().await
    }

    async fn create_key(
        &self,
        branch_key_id: Option<String>,
        encryption_context: Option<EncryptionContext>,
    ) -> Result<String, Error> {
        self.0.create_key(branch_key_id, encryption_context).await
    }

    async fn version_key(&self, branch_key_id: String) -> Result<(), Error> {
        self.0.version_key(branch_key_id).await
    }

    async fn get_active_branch_key(
        &self,
        branch_key_id: String,
    ) -> Result<BranchKeyMaterials, Error> {
        self.0.get_active_branch_key(branch_key_id).await
    }

    async fn get_branch_key_version(
        &self,
        branch_key_id: String,
        branch_key_version: String,
    ) -> Result<BranchKeyMaterials, Error> {
        self.0
            .get_branch_key_version(branch_key_id, branch_key_version)
            .await
    }

    async fn get_beacon_key(&self, branch_key_id: String) -> Result<BeaconKeyMaterials, Error> {
        self.0.get_beacon_key(branch_key_id).await
    }
}
