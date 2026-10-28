// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    unused_qualifications,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs
)]

//! The AWS Database Encryption SDK for DynamoDB: client-side encryption and signing of DynamoDB items.
//!
//! Configure each table with a [`TableConfig`]: which attributes to encrypt, which to sign,
//! and the keyring or CMM that protects each item's data key.
//! An [`ItemEncryptor`] encrypts and decrypts items of one table with no call to DynamoDB.
//!
//! Every item is signed. Its encrypted attributes become binary, and two attributes are added:
//! `aws_dbe_head`, the header with the encrypted data keys,
//! and `aws_dbe_foot`, the footer with the signatures.
//!
//! The keyrings, CMMs, caches, and key store come from the AWS Cryptographic Material Providers
//! Library, re-exported here as [`keyring`], [`cmm`], [`cmc`], [`key_store`], and [`mpl`].

mod branch_key_supplier;
mod ddb;
mod edk_description;
pub mod error;
mod item_encryptor;
#[doc(hidden)]
pub mod structured;
mod table_config;
pub mod types;

pub use edk_description::{
    EncryptedDataKeyDescription, describe_encrypted_data_keys, describe_header_encrypted_data_keys,
};
pub use error::generated::Error;
pub use item_encryptor::{
    DecryptItemFluentBuilder, DecryptItemOutput, EncryptItemFluentBuilder, EncryptItemOutput,
    ItemEncryptor, ItemEncryptorBuilder, ParsedHeader,
};
pub use table_config::{TableConfig, TableConfigBuilder};

/// The AWS Cryptographic Material Providers Library this crate is built on.
pub use aws_crypto_mpl as mpl;
pub use aws_crypto_mpl::{cmc, cmm, key_store};

/// Keyrings: the Material Providers Library's, plus [`ItemKeySupplier`](keyring::ItemKeySupplier),
/// which picks a [`HierarchicalKeyring`](keyring::HierarchicalKeyring)'s branch key from each
/// item's primary key.
pub mod keyring {
    pub use crate::branch_key_supplier::{
        GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdFromItemKeyInputBuilder,
        ItemKeyBranchKeySupplier, ItemKeySupplier,
    };
    pub use aws_crypto_mpl::keyring::*;
}

/// Put `#[async_trait]` on an `impl` of a [`Keyring`](keyring::Keyring) or [`Cmm`](cmm::Cmm).
pub use aws_crypto_mpl::async_trait;

#[cfg(feature = "default-aws-sdk-clients")]
pub use aws_crypto_mpl::aws_config;
pub use aws_crypto_mpl::aws_sdk_dynamodb;
#[cfg(feature = "kms")]
pub use aws_crypto_mpl::aws_sdk_kms;
