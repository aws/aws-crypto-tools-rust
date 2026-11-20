// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
// Lint definitions:
// https://doc.rust-lang.org/rustc/lints/listing/index.html
// https://rust-lang.github.io/rust-clippy/master/index.html
#![warn(
    // Forward compatibility: idioms that future editions break.
    deprecated_in_future,
    keyword_idents,
    keyword_idents_2024,
    rust_2018_idioms,           // sub-lints like elided_lifetimes_in_paths still fire on edition 2024

    // Public API hygiene.
    missing_debug_implementations,
    missing_copy_implementations,
    missing_docs,
    unreachable_pub,

    // Constructs that are usually mistakes.
    let_underscore_drop,        // `let _ = guard;` drops the guard immediately
    noop_method_call,           // .clone()/.borrow() that does nothing
    trivial_casts,              // `x as T` where T is x's type
    trivial_numeric_casts,      // numeric `as` cast that is a no-op
    unit_bindings,              // `let x = ();` is almost always a bug

    // Cleanup and explicitness.
    absolute_paths_not_starting_with_crate,
    explicit_outlives_requirements,
    impl_trait_redundant_captures,
    macro_use_extern_crate,
    non_ascii_idents,
    redundant_imports,
    redundant_lifetimes,
    single_use_lifetimes,
    unused_extern_crates,
    unused_lifetimes,
    unused_qualifications,

    // Safety review.
    unsafe_op_in_unsafe_fn,     // warn by default on edition 2024; listed so that the whole policy is in one place

    // Clippy lint groups.
    clippy::style,
    clippy::pedantic,
    clippy::nursery,            // unstable: expect new warnings after a toolchain upgrade
    clippy::cargo,

    // Selected clippy::restriction lints.
    clippy::create_dir,                       // require create_dir_all
    clippy::exhaustive_enums,                 // public enums must be #[non_exhaustive]
    clippy::exhaustive_structs,               // public structs must be #[non_exhaustive]
    clippy::little_endian_bytes,              // the spec's wire format is big-endian
    clippy::missing_asserts_for_indexing,     // catch panic-prone indexing
    clippy::mixed_read_write_in_expression,   // avoid order-of-eval surprises
    clippy::partial_pub_fields,               // all-or-nothing field visibility
    clippy::redundant_type_annotations,
    clippy::renamed_function_params,          // trait impls keep parameter names
    clippy::rest_pat_in_fully_bound_structs,  // explicit `..` only when needed
    clippy::same_name_method,                 // avoid inherent vs trait shadowing
    clippy::string_add,                       // prefer push_str over `s + s`
    clippy::string_lit_chars_any,             // prefer matches! over .chars().any()
    clippy::tests_outside_test_module,
    clippy::unneeded_field_pattern,

    // Not enabled:
    //   clippy::panic -- catch-all arms on #[non_exhaustive] MPL enums need panic!()
    //   clippy::indexing_slicing -- too noisy in serialization code
    //   clippy::wildcard_enum_match_arm -- allowed below
    //   clippy::restriction -- most of its lints are situational
    //   non_exhaustive_omitted_patterns -- unstable
    //   rust_2021_incompatible_closure_captures, rust_2021_incompatible_or_patterns,
    //   rust_2021_prefixes_incompatible_syntax, rust_2021_prelude_collisions --
    //     migration lints for edition 2021; they do not fire on edition 2024
)]
// Lints from the groups above that this crate allows:
#![allow(clippy::wildcard_enum_match_arm)] // too noisy against #[non_exhaustive] MPL enums
#![allow(clippy::multiple_crate_versions)] // transitively unavoidable
#![allow(clippy::option_if_let_else)] // disagree: `if let` is often clearer
#![allow(clippy::redundant_pub_crate)] // false positive: conflicts with unreachable_pub
#![allow(clippy::too_many_lines)] // disagree: arbitrary line-count threshold
#![allow(clippy::missing_const_for_fn)] // getters and setters stay non-const, so they can change without breaking callers
#![allow(unused_crate_dependencies)] // false positives across workspace dev-deps

//! # AWS Database Encryption SDK for DynamoDB in Rust
//!
//! Client-side encryption and signing of DynamoDB items.
//!
//! Configure each table with a [`TableConfig`]:
//! which attributes to encrypt, which to sign, and the keyring or CMM that protects each item's data key.
//! A [`Client`] has the operations of the AWS SDK's DynamoDB client.
//! It encrypts items before writing them, and verifies and decrypts them after reading them.
//! An [`ItemEncryptor`] encrypts and decrypts items of one table without calling DynamoDB.
//!
//! The SDK signs every item.
//! It turns each encrypted attribute into a binary attribute, and adds two attributes:
//! - `aws_dbe_head`: the header, which holds the encrypted data keys
//! - `aws_dbe_foot`: the footer, which holds the signatures
//!
//! ## Getting started
//!
//! Add the SDK and an async runtime to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! aws-db-esdk = "0.1"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! Then configure a table, and encrypt and decrypt an item:
//!
//! ```
//! use std::collections::HashMap;
//!
//! use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
//! use aws_db_esdk::keyring::RawAesKeyring;
//! use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
//! use aws_db_esdk::{ItemEncryptor, TableConfig};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // For demonstration only: load your wrapping key from a secure store.
//! let keyring = RawAesKeyring::builder()
//!     .key_namespace("my-key-namespace")
//!     .key_name("my-key-name")
//!     .wrapping_key(vec![0x2A; 32])
//!     .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
//!     .build()?;
//!
//! let table = TableConfig::builder()
//!     .partition_key_name("id")
//!     .attribute_actions_on_encrypt("id", CryptoAction::SignOnly)
//!     .attribute_actions_on_encrypt("secret", CryptoAction::EncryptAndSign)
//!     .keyring(keyring)
//!     .build()?;
//! let encryptor = ItemEncryptor::builder().table("my-table", table).build()?;
//!
//! let item = HashMap::from([
//!     ("id".to_string(), AttributeValue::S("1".into())),
//!     ("secret".to_string(), AttributeValue::S("Hello World".into())),
//! ]);
//! let encrypted = encryptor.encrypt_item().plaintext_item(item.clone()).send().await?;
//! assert!(encrypted.encrypted_item()["secret"].is_b());
//!
//! let decrypted = encryptor
//!     .decrypt_item()
//!     .encrypted_item(encrypted.into_encrypted_item())
//!     .send()
//!     .await?;
//! assert_eq!(decrypted.plaintext_item(), &item);
//! # Ok(())
//! # }
//! ```
//!
//! To read and write a table, give the same `TableConfig` to a [`Client`],
//! along with the `aws_sdk_dynamodb::Client` that it sends requests through.
//! Then use it as you would an `aws_sdk_dynamodb::Client`.
//! The [`Client`] docs show how.
//!
//! Every operation fails with an [`Error`].
//! The [`error`] module shows how to handle each kind.
//!
//! ## Crate organization
//!
//! - The crate root holds [`Client`], [`TableConfig`], [`ItemEncryptor`], and [`Error`],
//!   plus [`describe_encrypted_data_keys`], which lists the keys that protect an item.
//! - [`client`] holds the fluent builder of each [`Client`] operation.
//! - [`types`] holds the types that the configuration takes:
//!   [`CryptoAction`](types::CryptoAction), [`AlgorithmSuiteId`](types::AlgorithmSuiteId),
//!   and [`EncryptionContext`](types::EncryptionContext).
//! - [`search`] holds the searchable encryption configuration: beacons, and the key store that protects them.
//! - [`error`] holds [`Error`] and the details that each error carries.
//! - [`keyring`], [`cmm`], [`cmc`], and [`key_store`] are the Material Providers Library's resources:
//!   keyrings, cryptographic materials managers, caches, and the branch key store.
//!   [`keyring`] also holds [`ItemKeySupplier`](keyring::ItemKeySupplier),
//!   which picks a hierarchical keyring's branch key from each item's primary key.
//! - [`aws_config`], [`aws_sdk_kms`], and [`aws_sdk_dynamodb`] are the AWS SDK crates that those resources take clients from.
//! - [`mpl`] is the whole Material Providers Library.
//!   Code that implements a keyring or CMM uses its [`Error`](mpl::Error) and [`types`](mpl::types).

mod branch_key_supplier;
pub mod client;
mod ddb;
mod edk_description;
pub mod error;
mod item_encryptor;
pub mod search;
#[doc(hidden)]
pub mod structured;
mod table_config;
#[doc(hidden)]
pub mod transforms;
pub mod types;

pub use client::Client;
pub use edk_description::{
    EncryptedDataKeyDescription, describe_encrypted_data_keys, describe_header_encrypted_data_keys,
};
pub use error::generated::Error;
pub use item_encryptor::{
    DecryptItemFluentBuilder, DecryptItemOutput, EncryptItemFluentBuilder, EncryptItemOutput,
    ItemEncryptor, ItemEncryptorBuilder, ParsedHeader,
};
pub use table_config::{TableConfig, TableConfigBuilder};

/// The AWS Cryptographic Material Providers Library that this crate is built on.
pub use aws_crypto_mpl as mpl;
pub use aws_crypto_mpl::{cmc, cmm, key_store};

/// The Material Providers Library's keyrings, plus [`ItemKeySupplier`](keyring::ItemKeySupplier).
///
/// An `ItemKeySupplier` picks a [`HierarchicalKeyring`](keyring::HierarchicalKeyring)'s branch key
/// from each item's primary key.
pub mod keyring {
    //= spec/dynamodb-encryption-client/ddb-encryption-branch-key-id-supplier.md#operation
    //= type=implication
    //= reason=ItemKeyBranchKeySupplier::new is the operation, exported next to ItemEncryptor
    //# The `CreateDynamoDbEncryptionBranchKeyIdSupplier` is an operation that MUST be vended alongside the DynamoDb Item Encryptor.
    pub use crate::branch_key_supplier::{
        GetBranchKeyIdFromItemKeyInput, GetBranchKeyIdFromItemKeyInputBuilder,
        ItemKeyBranchKeySupplier, ItemKeySupplier,
    };
    pub use aws_crypto_mpl::keyring::*;
}

/// Put `#[async_trait]` on an `impl` of a [`Keyring`](keyring::Keyring), [`Cmm`](cmm::Cmm),
/// or [`ItemKeySupplier`](keyring::ItemKeySupplier).
pub use aws_crypto_mpl::async_trait;

#[cfg(feature = "default-aws-sdk-clients")]
pub use aws_crypto_mpl::aws_config;
pub use aws_crypto_mpl::aws_sdk_dynamodb;
#[cfg(feature = "kms")]
pub use aws_crypto_mpl::aws_sdk_kms;
