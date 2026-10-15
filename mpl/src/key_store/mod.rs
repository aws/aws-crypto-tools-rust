// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`KeyStore`] trait, which every key store implements,
//! and [`Client`], through which callers use one.
//!
//! ```no_run
//! # async fn example() -> Result<(), aws_crypto_mpl::Error> {
//! use aws_crypto_mpl::key_store;
//! use aws_crypto_mpl::key_store::types::KmsConfiguration;
//!
//! let key_store = key_store::Client::builder()
//!     .ddb_table_name("my-table")
//!     .logical_key_store_name("my-table")
//!     .kms_configuration(KmsConfiguration::KmsKeyArn(
//!         "arn:aws:kms:us-west-2:111122223333:key/my-key".into(),
//!     ))
//!     .build()
//!     .await?;
//! let branch_key_id = key_store.create_key().send().await?.into_branch_key_id();
//! key_store.version_key().branch_key_id(&branch_key_id).send().await?;
//! # Ok(())
//! # }
//! ```

// The DynamoDB key store needs both SDK clients.
// The modules it builds on are gated only on what they use themselves.
// It is their only caller today, so without it they are unused.
#[cfg_attr(not(all(feature = "kms", feature = "ddb")), allow(dead_code))]
mod attributes;
#[cfg(all(feature = "kms", feature = "ddb"))]
mod branch_key_store;
mod client_impl;
mod config;
#[cfg_attr(not(all(feature = "kms", feature = "ddb")), allow(dead_code))]
mod encryption_context;
mod kms_config;
#[cfg(feature = "kms")]
#[cfg_attr(not(all(feature = "kms", feature = "ddb")), allow(dead_code))]
mod kms_ops;
#[cfg_attr(not(all(feature = "kms", feature = "ddb")), allow(dead_code))]
mod record;
mod shapes;

use crate::Error;
use async_trait::async_trait;

pub use client_impl::Client;

pub mod client {
    //! The key store [`Client`] and its [`Builder`].

    #[cfg(all(feature = "kms", feature = "ddb"))]
    pub use super::branch_key_store::Builder;
    pub use super::client_impl::Client;
}

pub mod types {
    //! The types a key store's configuration takes.

    pub use super::config::{Discovery, KmsConfiguration, MrDiscovery};

    pub mod builders {
        //! Builders for the types in [`key_store::types`](crate::key_store::types).

        pub use crate::key_store::config::{DiscoveryBuilder, MrDiscoveryBuilder};
    }
}
pub(crate) use shapes::*;

/// Each [`Client`] operation's input, output, and builders, laid out as in an AWS SDK for Rust crate.
pub mod operation {
    pub mod get_key_store_info {
        //! The [`get_key_store_info`](crate::key_store::KeyStore::get_key_store_info) operation.

        pub use crate::key_store::shapes::{GetKeyStoreInfoInput, GetKeyStoreInfoOutput};

        pub mod builders {
            //! The builders for the [`get_key_store_info`](crate::key_store::KeyStore::get_key_store_info) operation.

            pub use crate::key_store::client_impl::GetKeyStoreInfoFluentBuilder;
            pub use crate::key_store::shapes::{
                GetKeyStoreInfoInputBuilder, GetKeyStoreInfoOutputBuilder,
            };
        }
    }

    pub mod create_key_store {
        //! The [`create_key_store`](crate::key_store::KeyStore::create_key_store) operation.

        pub use crate::key_store::shapes::{CreateKeyStoreInput, CreateKeyStoreOutput};

        pub mod builders {
            //! The builders for the [`create_key_store`](crate::key_store::KeyStore::create_key_store) operation.

            pub use crate::key_store::client_impl::CreateKeyStoreFluentBuilder;
            pub use crate::key_store::shapes::{
                CreateKeyStoreInputBuilder, CreateKeyStoreOutputBuilder,
            };
        }
    }

    pub mod create_key {
        //! The [`create_key`](crate::key_store::KeyStore::create_key) operation.

        pub use crate::key_store::shapes::{CreateKeyInput, CreateKeyOutput};

        pub mod builders {
            //! The builders for the [`create_key`](crate::key_store::KeyStore::create_key) operation.

            pub use crate::key_store::client_impl::CreateKeyFluentBuilder;
            pub use crate::key_store::shapes::{CreateKeyInputBuilder, CreateKeyOutputBuilder};
        }
    }

    pub mod version_key {
        //! The [`version_key`](crate::key_store::KeyStore::version_key) operation.

        pub use crate::key_store::shapes::{VersionKeyInput, VersionKeyOutput};

        pub mod builders {
            //! The builders for the [`version_key`](crate::key_store::KeyStore::version_key) operation.

            pub use crate::key_store::client_impl::VersionKeyFluentBuilder;
            pub use crate::key_store::shapes::{VersionKeyInputBuilder, VersionKeyOutputBuilder};
        }
    }

    pub mod get_active_branch_key {
        //! The [`get_active_branch_key`](crate::key_store::KeyStore::get_active_branch_key) operation.

        pub use crate::key_store::shapes::{GetActiveBranchKeyInput, GetActiveBranchKeyOutput};

        pub mod builders {
            //! The builders for the [`get_active_branch_key`](crate::key_store::KeyStore::get_active_branch_key) operation.

            pub use crate::key_store::client_impl::GetActiveBranchKeyFluentBuilder;
            pub use crate::key_store::shapes::{
                GetActiveBranchKeyInputBuilder, GetActiveBranchKeyOutputBuilder,
            };
        }
    }

    pub mod get_branch_key_version {
        //! The [`get_branch_key_version`](crate::key_store::KeyStore::get_branch_key_version) operation.

        pub use crate::key_store::shapes::{GetBranchKeyVersionInput, GetBranchKeyVersionOutput};

        pub mod builders {
            //! The builders for the [`get_branch_key_version`](crate::key_store::KeyStore::get_branch_key_version) operation.

            pub use crate::key_store::client_impl::GetBranchKeyVersionFluentBuilder;
            pub use crate::key_store::shapes::{
                GetBranchKeyVersionInputBuilder, GetBranchKeyVersionOutputBuilder,
            };
        }
    }

    pub mod get_beacon_key {
        //! The [`get_beacon_key`](crate::key_store::KeyStore::get_beacon_key) operation.

        pub use crate::key_store::shapes::{GetBeaconKeyInput, GetBeaconKeyOutput};

        pub mod builders {
            //! The builders for the [`get_beacon_key`](crate::key_store::KeyStore::get_beacon_key) operation.

            pub use crate::key_store::client_impl::GetBeaconKeyFluentBuilder;
            pub use crate::key_store::shapes::{
                GetBeaconKeyInputBuilder, GetBeaconKeyOutputBuilder,
            };
        }
    }
}

/// A key store: the storage and AWS KMS protection of branch keys and beacon keys.
///
/// Implement this trait, with [`#[async_trait]`](macro@crate::async_trait), to provide a key store.
/// To call one, wrap it in a [`Client`].
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Returns the configuration of this key store.
    ///
    /// The Hierarchical Keyring reads it once, when the keyring is built.
    ///
    /// # Errors
    ///
    /// The key store [`Client::builder`] builds does not return an error.
    /// Other implementations may return any variant.
    async fn get_key_store_info(
        &self,
        input: GetKeyStoreInfoInput,
    ) -> Result<GetKeyStoreInfoOutput, Error>;

    /// Creates the DynamoDB table that backs this key store, or validates an existing one.
    ///
    /// # Errors
    ///
    /// The key store [`Client::builder`] builds returns:
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
    /// The key store [`Client::builder`] builds returns:
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
    /// The key store [`Client::builder`] builds returns:
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
    /// The key store [`Client::builder`] builds returns:
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
    /// The key store [`Client::builder`] builds returns:
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
    /// The key store [`Client::builder`] builds returns:
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
    pub mod branch_key_store {
        pub use crate::key_store::branch_key_store::__test_internals::*;
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
