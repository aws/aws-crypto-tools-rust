// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! # AWS Encryption SDK for Rust
//!
//! The AWS Encryption SDK is a client-side encryption library.
//! It encrypts data with a unique data key per message,
//! and protects that data key with one or more wrapping keys you control, through a keyring.
//! The result is an encrypted message that holds the encrypted data keys, the encryption context and the ciphertext.
//!
//! ## Getting started
//!
//! Add the SDK and an async runtime to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! aws-esdk = "2"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! Then create a [`Client`], and encrypt and decrypt with a keyring:
//!
//! ```
//! use aws_esdk::keyring::RawAesKeyring;
//! use aws_esdk::types::{AesWrappingAlg, EncryptionContext};
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
//! let mut encryption_context = EncryptionContext::new();
//! encryption_context.insert("purpose", "example");
//!
//! let esdk = aws_esdk::Client::default();
//! let encrypted = esdk
//!     .encrypt()
//!     .plaintext(b"Hello World")
//!     .encryption_context(encryption_context.clone())
//!     .keyring(keyring.clone())
//!     .send()
//!     .await?;
//! let decrypted = esdk
//!     .decrypt()
//!     .ciphertext(encrypted.ciphertext())
//!     .encryption_context(encryption_context)
//!     .keyring(keyring)
//!     .send()
//!     .await?;
//! assert_eq!(decrypted.plaintext(), b"Hello World");
//! # Ok(())
//! # }
//! ```
//!
//! ## Using the SDK
//!
//! [`Client`] is the client. Configure settings that apply to every call, such as the commitment policy,
//! with [`Client::builder`]. Each operation is a method on the client that returns a fluent builder:
//! set its members, then call `send`.
//!
//! To keep settings separate from the client, as `aws_sdk_kms::Client::from_conf` does, build a
//! [`Config`] and pass it to [`Client::from_conf`]:
//!
//! ```
//! use aws_esdk::types::CommitmentPolicy;
//!
//! # fn main() -> Result<(), aws_esdk::Error> {
//! let config = aws_esdk::Config::builder()
//!     .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
//!     .build()?;
//! let esdk = aws_esdk::Client::from_conf(config);
//! # Ok(())
//! # }
//! ```
//!
//! | Operation | Fluent builder | Output |
//! |---|---|---|
//! | [`Client::encrypt`] | [`EncryptFluentBuilder`](operation::encrypt::builders::EncryptFluentBuilder) | [`EncryptOutput`](operation::encrypt::EncryptOutput) |
//! | [`Client::decrypt`] | [`DecryptFluentBuilder`](operation::decrypt::builders::DecryptFluentBuilder) | [`DecryptOutput`](operation::decrypt::DecryptOutput) |
//! | [`Client::encrypt_stream`] | [`EncryptStreamFluentBuilder`](operation::encrypt_stream::builders::EncryptStreamFluentBuilder) | [`EncryptStreamOutput`](operation::encrypt_stream::EncryptStreamOutput) |
//! | [`Client::decrypt_stream`] | [`DecryptStreamFluentBuilder`](operation::decrypt_stream::builders::DecryptStreamFluentBuilder) | [`DecryptStreamOutput`](operation::decrypt_stream::DecryptStreamOutput) |
//!
//! Keyrings and cryptographic materials managers (CMMs) are in [`keyring`] and [`cmm`].
//! To write your own, implement [`Keyring`](keyring::Keyring) or [`Cmm`](cmm::Cmm).
//!
//! Every operation fails with an [`Error`]; see the [`error`] module for how to handle each kind.
//!
//! ## Crate organization
//!
//! The layout follows the AWS SDK for Rust:
//!
//! - The crate root holds [`Client`], [`Config`], and [`Error`].
//! - [`config`] holds [`Config`] and its [`Builder`](config::Builder).
//! - [`operation`] has a module per operation, holding its output and, under `builders`, its fluent builder.
//! - [`types`] holds the types the operations take:
//!   [`EncryptionContext`](types::EncryptionContext), [`AlgorithmSuiteId`](types::AlgorithmSuiteId),
//!   [`CommitmentPolicy`](types::CommitmentPolicy), and [`AesWrappingAlg`](types::AesWrappingAlg).
//! - [`error`] holds [`Error`] and the details each error carries.
//! - [`keyring`], [`cmm`], [`cmc`], and [`key_store`] are the Material Providers Library's resources:
//!   keyrings, cryptographic materials managers, caches, and the branch key store.
//! - [`aws_config`], [`aws_sdk_kms`], and [`aws_sdk_dynamodb`] are the AWS SDK crates those resources take clients from.
//! - [`mpl`] is the whole Material Providers Library.
//!   Code that implements a keyring, CMM, cache, or key store uses its [`Error`](mpl::Error) and [`types`](mpl::types).
//!
//! The SDK reads and writes framed and nonframed message bodies, and message format versions 1 and 2
//! (version 2 adds key commitment).
//!
#![cfg_attr(docsrs, feature(doc_cfg))]
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

mod builder;
pub mod client;
pub mod config;
mod decrypt;
mod encrypt;
pub mod error;
pub mod operation;
mod shapes;
mod suites;
pub mod types;

pub use client::Client;
pub use config::Config;
pub use error::generated::Error;
pub use shapes::async_trait;

/// The Material Providers Library, which this crate is built on.
/// Its resource modules and AWS SDK clients are also re-exported below,
/// so most code never names it.
pub use aws_crypto_mpl as mpl;
#[cfg(feature = "default-aws-sdk-clients")]
pub use aws_crypto_mpl::aws_config;
#[cfg(feature = "ddb")]
pub use aws_crypto_mpl::aws_sdk_dynamodb;
#[cfg(feature = "kms")]
pub use aws_crypto_mpl::aws_sdk_kms;
pub use aws_crypto_mpl::{cmc, cmm, key_store, keyring};

pub(crate) mod key_derivation;
pub(crate) mod materials;
pub(crate) mod message;

/// Internal items exposed solely so integration tests under `tests/` can
/// construct and assert on exact byte outputs of non-public serialization
/// helpers. Not part of the public API. Do not use.
///
/// Everything in this module is exempt from semantic versioning and may be
/// changed, renamed, or removed at any time.
#[doc(hidden)]
pub mod __test_internals {
    pub use crate::key_derivation::{ExpandedKeyMaterial, derive_key_v2, derive_keys};
    pub use crate::message::DigestWriter;
    pub use crate::message::body::body_aad::{BodyAADContent, body_aad};
    pub use crate::message::header::{HeaderInfo, generate_message_id, read_header_body};
    pub use crate::message::header_auth::read_header_auth_tag;
    pub use crate::message::header_types::HeaderBody;
    pub use crate::shapes::{Sink, Source, Tee};
    pub use crate::suites::{
        algorithm_suite_from_bytes, algorithm_suite_id_from_bytes, get_ecdsa_alg,
        get_esdk_algorithm_suite_id,
    };
}
