// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
// Project lint policy. We opt in to several rustc/clippy lint groups plus
// individually-selected clippy::restriction lints. Lint definitions live at
// https://doc.rust-lang.org/rustc/lints/listing/index.html and
// https://rust-lang.github.io/rust-clippy/master/index.html.
#![warn(
    // --- Forward-compatibility (catch idioms that future editions will break) ---
    deprecated_in_future,
    keyword_idents,
    keyword_idents_2024,
    rust_2018_idioms,           // sub-lints like elided_lifetimes_in_paths still fire on edition 2024

    // --- Public API hygiene ---
    missing_debug_implementations,
    missing_copy_implementations,
    missing_docs,
    unreachable_pub,

    // --- Bug prevention (constructs that are usually mistakes) ---
    let_underscore_drop,        // `let _ = guard;` drops the guard immediately
    noop_method_call,           // .clone()/.borrow() that does nothing
    trivial_casts,              // `x as T` where T is x's type
    trivial_numeric_casts,      // numeric `as` cast that is a no-op
    unit_bindings,              // `let x = ();` is almost always a bug

    // --- Cleanup / explicitness ---
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

    // --- Safety review ---
    unsafe_op_in_unsafe_fn,     // edition 2024 makes this warn-by-default; listed for explicit project policy

    // --- Clippy lint groups ---
    clippy::style,
    clippy::pedantic,
    clippy::nursery,            // unstable; review surprise warnings on toolchain bumps
    clippy::cargo,

    // --- Selected clippy::restriction lints. We do NOT enable
    // clippy::restriction wholesale; most of its lints are situational. ---
    clippy::create_dir,                       // require create_dir_all
    clippy::exhaustive_enums,                 // public enums must be #[non_exhaustive]
    clippy::exhaustive_structs,               // public structs must be #[non_exhaustive]
    clippy::little_endian_bytes,              // big-endian preferred (matches spec wire format)
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

    // Intentionally not enabled (with rationale):
    //   clippy::panic                  — MPL enums are #[non_exhaustive], forcing panic!()
    //   clippy::indexing_slicing       — too noisy in serialization code
    //   clippy::wildcard_enum_match_arm — see allow(...) below
    //   clippy::restriction            — opt in to selected lints individually
    //   non_exhaustive_omitted_patterns — unstable
    //   rust_2021_incompatible_closure_captures
    //   rust_2021_incompatible_or_patterns
    //   rust_2021_prefixes_incompatible_syntax
    //   rust_2021_prelude_collisions  — all four are silent on edition 2024 (the things
    //                                   they warn about are compile errors here, not lintable)
)]
// Project disagreements with the warn set above:
#![allow(clippy::wildcard_enum_match_arm)] // too noisy against #[non_exhaustive] MPL enums
#![allow(clippy::multiple_crate_versions)] // transitively unavoidable
#![allow(clippy::option_if_let_else)] // disagree: `if let` is often clearer
#![allow(clippy::redundant_pub_crate)] // false positive: conflicts with unreachable_pub
#![allow(clippy::too_many_lines)] // disagree: arbitrary line-count threshold
#![allow(unused_crate_dependencies)] // false positives across workspace dev-deps

//! The AWS Database Encryption SDK for DynamoDB: client-side encryption and signing of DynamoDB items.
//!
//! Configure each table with a [`TableConfig`]: which attributes to encrypt, which to sign,
//! and the keyring or CMM that protects each item's data key.
//! A [`Client`] has the operations of the AWS SDK's DynamoDB client: it encrypts items before
//! writing them, and verifies and decrypts them after reading them.
//! An [`ItemEncryptor`] encrypts and decrypts items of one table with no call to DynamoDB.
//!
//! Every item is signed. Its encrypted attributes become binary, and two attributes are added:
//! `aws_dbe_head`, the header with the encrypted data keys,
//! and `aws_dbe_foot`, the footer with the signatures.
//!
//! The keyrings, CMMs, caches, and key store come from the AWS Cryptographic Material Providers
//! Library, re-exported here as [`keyring`], [`cmm`], [`cmc`], [`key_store`], and [`mpl`].

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
