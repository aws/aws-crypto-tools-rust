// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Keyring` trait — the abstract contract every keyring MUST implement.
//!
//! Uses #[async_trait] so that the CMM can hold any runtime defined
//! keyring. The macro makes this work by rewriting each `async fn`
//! to return a boxed future.
//!
//! # Errors for keyring and CMM authors
//!
//! The AWS Encryption SDK passes the [`Error`] variant your [`Keyring`] or [`Cmm`](crate::Cmm) returns
//! on to its caller, so pick the variant that tells the caller what to do:
//!
//! - **[`NoMatchingDataKey`](Error::NoMatchingDataKey)** when no encrypted data key belongs to this keyring.
//!   Decide this from each key's provider ID and provider info, before trying to decrypt.
//!   Pass the encrypted data keys to [`with_encrypted_data_keys`](Error::with_encrypted_data_keys)
//!   so the caller can see which key providers the message has.
//! - **[`Cryptographic`](Error::Cryptographic)** when an encrypted data key belongs to this keyring
//!   but does not decrypt.
//! - **[`InvalidMaterials`](Error::InvalidMaterials)** when the materials are inconsistent,
//!   for example they already hold a plaintext data key.
//! - **[`Validation`](Error::Validation)** when the keyring's own configuration is invalid.
//!
//! Each variant above has a constructor of the same name, such as [`Error::cryptographic`].
//! Attach the underlying error with [`with_source`](Error::with_source):
//!
//! ```
//! use aws_crypto_mpl::Error;
//!
//! # let io_error = std::io::Error::other("connection reset");
//! let err = Error::cryptographic("encrypted data key 0 did not decrypt").with_source(io_error);
//! assert!(err.is_cryptographic());
//!
//! # let encrypted_data_keys: Vec<aws_crypto_mpl::structures::EncryptedDataKey> = Vec::new();
//! use aws_crypto_mpl::error::DataKeyInfo;
//!
//! let err = Error::no_matching_data_key("no encrypted data key belongs to this keyring")
//!     .with_encrypted_data_keys(encrypted_data_keys.iter().map(DataKeyInfo::from));
//! assert!(err.is_no_matching_data_key());
//! ```
//!
//! To report several failures as one error:
//!
//! - [`Error::all_failed`] when you tried several encrypted data keys and each failed.
//!   Any one succeeding would have been enough, so the result is retryable if any attempt is.
//! - [`Error::any_failed`] when several steps your keyring needed failed.
//!   One permanent failure makes the result not retryable.
//!
//! Both pick the variant and keep the details every failure shares.
//! Given a single failure, both return it unchanged.
//!
//! Implement [`name`](Keyring::name): errors about your keyring show it.
//! You do not need to set `resource()` to your keyring.
//! When your error is `InvalidMaterials` or `NoMatchingDataKey` and names no resource,
//! the AWS Encryption SDK sets `resource()` to [`Resource::Keyring`](crate::error::Resource::Keyring)
//! or [`Resource::Cmm`](crate::error::Resource::Cmm) with your name.

use crate::Error;
use std::borrow::Cow;

use async_trait::async_trait;

pub mod raw_aes_keyring;
mod types;

pub use raw_aes_keyring::{RawAesKeyring, RawAesKeyringBuilder};
pub use types::{
    OnDecryptInput, OnDecryptInputBuilder, OnDecryptOutput, OnDecryptOutputBuilder, OnEncryptInput,
    OnEncryptInputBuilder, OnEncryptOutput, OnEncryptOutputBuilder,
};

/// To hold a keyring whose concrete type is chosen at runtime, use [`SharedKeyring`].
#[async_trait]
pub trait Keyring: Send + Sync {
    /// A short name for this keyring, which errors show.
    ///
    /// When the ESDK attributes an error to this keyring, it sets `resource()` to
    /// [`Resource::Keyring`](crate::error::Resource::Keyring) with this name.
    /// Keep it stable and short, and never put secrets in it.
    /// Return `Cow::Owned` for a name built at runtime.
    /// The default is the type's name.
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(std::any::type_name::<Self>())
    }

    /// Add a data key to the input's encryption materials and return them.
    /// When the materials have no plaintext data key, generate one.
    /// See the [OnEncrypt](../../../spec/framework/keyring-interface.md#onencrypt)
    /// section of the keyring interface specification.
    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error>;

    /// Decrypt one of the input's encrypted data keys,
    /// add its plaintext data key to the input's decryption materials,
    /// and return them.
    /// See the [OnDecrypt](../../../spec/framework/keyring-interface.md#ondecrypt)
    /// section of the keyring interface specification.
    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error>;
}

crate::shared::shared_handle!(
    /// A keyring whose concrete type is chosen at runtime.
    ///
    /// It implements [`Keyring`], so it can be passed anywhere a keyring is accepted.
    /// Callers that know their keyring's type pass it directly and never need this one.
    SharedKeyring,
    Keyring
);

#[async_trait]
impl Keyring for SharedKeyring {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        self.0.on_encrypt(input).await
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        self.0.on_decrypt(input).await
    }
}

/// A keyring behind an `Arc` is a keyring, so one instance can be shared without being `Clone`.
#[async_trait]
impl<T: Keyring + ?Sized> Keyring for std::sync::Arc<T> {
    fn name(&self) -> Cow<'_, str> {
        (**self).name()
    }

    async fn on_encrypt(&self, input: OnEncryptInput) -> Result<OnEncryptOutput, Error> {
        (**self).on_encrypt(input).await
    }

    async fn on_decrypt(&self, input: OnDecryptInput) -> Result<OnDecryptOutput, Error> {
        (**self).on_decrypt(input).await
    }
}
