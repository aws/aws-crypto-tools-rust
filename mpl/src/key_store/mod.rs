// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`KeyStore`] trait, which every key store implements,
//! and [`KeyStoreClient`], through which callers use one.
//!
//! ```no_run
//! # async fn example() -> Result<(), aws_crypto_mpl::Error> {
//! use aws_crypto_mpl::key_store::{BranchKeyStore, KmsConfiguration};
//!
//! let key_store = BranchKeyStore::builder()
//!     .ddb_table_name("my-table")
//!     .logical_key_store_name("my-table")
//!     .kms_configuration(KmsConfiguration::KmsKeyArn(
//!         "arn:aws:kms:us-west-2:111122223333:key/my-key".to_owned(),
//!     ))
//!     .build()
//!     .await?;
//! let branch_key_id = key_store.create_key().send().await?.into_branch_key_id();
//! key_store.version_key().branch_key_id(&branch_key_id).send().await?;
//! # Ok(())
//! # }
//! ```

mod attributes;
pub mod branch_key_store;
mod client;
pub mod config;
mod encryption_context;
mod kms_config;
mod kms_ops;
mod record;
mod types;

use crate::Error;
use async_trait::async_trait;

pub use branch_key_store::{BranchKeyStore, BranchKeyStoreBuilder};
pub use client::{
    CreateKeyFluentBuilder, CreateKeyStoreFluentBuilder, GetActiveBranchKeyFluentBuilder,
    GetBeaconKeyFluentBuilder, GetBranchKeyVersionFluentBuilder, GetKeyStoreInfoFluentBuilder,
    KeyStoreClient, VersionKeyFluentBuilder,
};
pub use config::{Discovery, KmsConfiguration, MrDiscovery};
pub use types::{
    CreateKeyInput, CreateKeyInputBuilder, CreateKeyOutput, CreateKeyOutputBuilder,
    CreateKeyStoreInput, CreateKeyStoreInputBuilder, CreateKeyStoreOutput,
    CreateKeyStoreOutputBuilder, GetActiveBranchKeyInput, GetActiveBranchKeyInputBuilder,
    GetActiveBranchKeyOutput, GetActiveBranchKeyOutputBuilder, GetBeaconKeyInput,
    GetBeaconKeyInputBuilder, GetBeaconKeyOutput, GetBeaconKeyOutputBuilder,
    GetBranchKeyVersionInput, GetBranchKeyVersionInputBuilder, GetBranchKeyVersionOutput,
    GetBranchKeyVersionOutputBuilder, GetKeyStoreInfoInput, GetKeyStoreInfoInputBuilder,
    GetKeyStoreInfoOutput, GetKeyStoreInfoOutputBuilder, VersionKeyInput, VersionKeyInputBuilder,
    VersionKeyOutput, VersionKeyOutputBuilder,
};

/// A key store: the storage and AWS KMS protection of branch keys and beacon keys.
///
/// Implement this trait, with `#[async_trait]`, to provide a key store.
/// To call one, wrap it in a [`KeyStoreClient`].
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Returns the configuration of this key store.
    ///
    /// The configuration is fixed when the key store is constructed,
    /// so this method is synchronous and performs no IO.
    /// The Hierarchical Keyring reads it once, when the keyring is built.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation does not return an error.
    /// Other implementations may return any variant.
    fn get_key_store_info(
        &self,
        input: GetKeyStoreInfoInput,
    ) -> Result<GetKeyStoreInfoOutput, Error>;

    /// Creates the DynamoDB table that backs this key store, or validates an existing one.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`Validation`](crate::Error::Validation): the table exists but does not have the key store schema.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an Amazon DynamoDB call failed; `resource()` is the table.
    /// - [`Service`](crate::Error::Service): Amazon DynamoDB reported success but returned no table description or ARN.
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request failed.
    ///
    /// Other implementations may return different variants.
    async fn create_key_store(
        &self,
        input: CreateKeyStoreInput,
    ) -> Result<CreateKeyStoreOutput, Error>;

    /// Creates a new branch key and its beacon key.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`Validation`](crate::Error::Validation): the call passes a branch key id but no encryption context, the KMS configuration is not a single KMS key, or the encryption context is invalid.
    /// - [`Conflict`](crate::Error::Conflict): the branch key id already exists; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed; `resource()` is the KMS key or the table.
    /// - [`Service`](crate::Error::Service): AWS KMS returned no ciphertext.
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request or formatting the record timestamp failed.
    ///
    /// Other implementations may return different variants.
    async fn create_key(&self, input: CreateKeyInput) -> Result<CreateKeyOutput, Error>;

    /// Rotates the ACTIVE branch key to a new version.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`Validation`](crate::Error::Validation): the KMS configuration is not a single KMS key, or the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the ACTIVE record is missing a required attribute or is malformed; `resource()` is the branch key.
    /// - [`Cryptographic`](crate::Error::Cryptographic): the stored ACTIVE record fails AWS KMS authentication (`InvalidCiphertextException`).
    /// - [`Conflict`](crate::Error::Conflict): the branch key was rotated concurrently; `resource()` is the branch key.
    /// - [`ResourceNotFound`](crate::Error::ResourceNotFound): the branch key has no ACTIVE record; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed; `resource()` is the KMS key or the table.
    /// - [`Service`](crate::Error::Service): AWS KMS returned no ciphertext.
    /// - [`Internal`](crate::Error::Internal): building a DynamoDB request or formatting the record timestamp failed.
    ///
    /// Other implementations may return different variants.
    async fn version_key(&self, input: VersionKeyInput) -> Result<VersionKeyOutput, Error>;

    /// Returns the ACTIVE branch key materials for a branch key.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the key store record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`ResourceNotFound`](crate::Error::ResourceNotFound): the branch key has no ACTIVE record; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed; `resource()` is the KMS key or the table.
    /// - [`Service`](crate::Error::Service): AWS KMS returned no plaintext.
    ///
    /// Other implementations may return different variants.
    async fn get_active_branch_key(
        &self,
        input: GetActiveBranchKeyInput,
    ) -> Result<GetActiveBranchKeyOutput, Error>;

    /// Returns the branch key materials for a specific version of a branch key.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the key store record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`ResourceNotFound`](crate::Error::ResourceNotFound): the branch key has no record of that version; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed; `resource()` is the KMS key or the table.
    /// - [`Service`](crate::Error::Service): AWS KMS returned no plaintext.
    ///
    /// Other implementations may return different variants.
    async fn get_branch_key_version(
        &self,
        input: GetBranchKeyVersionInput,
    ) -> Result<GetBranchKeyVersionOutput, Error>;

    /// Returns the beacon key materials for a branch key.
    ///
    /// # Errors
    ///
    /// The built-in [`BranchKeyStore`] implementation returns:
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the key store record is malformed or missing a required attribute; `resource()` is the branch key.
    /// - [`Validation`](crate::Error::Validation): the record's `kms-arn` is not compatible with the configured KMS key.
    /// - [`ResourceNotFound`](crate::Error::ResourceNotFound): the branch key has no beacon key record; `resource()` is the branch key.
    /// - [`AccessDenied`](crate::Error::AccessDenied), [`ResourceNotFound`](crate::Error::ResourceNotFound), [`Throttling`](crate::Error::Throttling), [`Service`](crate::Error::Service), [`Dispatch`](crate::Error::Dispatch): an AWS KMS or Amazon DynamoDB call failed; `resource()` is the KMS key or the table.
    /// - [`Service`](crate::Error::Service): AWS KMS returned no plaintext.
    ///
    /// Other implementations may return different variants.
    async fn get_beacon_key(&self, input: GetBeaconKeyInput) -> Result<GetBeaconKeyOutput, Error>;
}

/// Internals that the crate's own integration tests reach.
/// Not part of the public API and may change in any release.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod __test_internals {
    pub mod attributes {
        pub use crate::key_store::attributes::*;
    }
    pub mod encryption_context {
        pub use crate::key_store::encryption_context::*;
    }
    pub mod kms_config {
        pub use crate::key_store::kms_config::*;
    }
    pub mod record {
        pub use crate::key_store::record::*;
    }
}
