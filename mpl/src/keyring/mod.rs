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
//! A custom [`Keyring`] or [`Cmm`](crate::Cmm) returns [`Error`],
//! and the AWS Encryption SDK passes the variant on to its caller,
//! so pick the variant that tells the caller what to do:
//!
//! - **[`NoMatchingDataKey`](Error::NoMatchingDataKey)** when no encrypted data key belongs to
//!   this keyring, judged by its key provider ID and key provider info, before trying to decrypt.
//! - **[`Cryptographic`](Error::Cryptographic)** when an encrypted data key belongs to this keyring
//!   but does not decrypt.
//! - **[`InvalidMaterials`](Error::InvalidMaterials)** when the materials are inconsistent,
//!   for example they already hold a plaintext data key.
//! - **[`Validation`](Error::Validation)** when the keyring's own configuration is invalid.
//!
//! Construct them with the short constructors, and keep the underlying error with
//! [`with_source`](Error::with_source):
//!
//! ```
//! use aws_crypto_mpl::Error;
//!
//! # let io_error = std::io::Error::other("connection reset");
//! let err = Error::cryptographic("encrypted data key 0 did not decrypt").with_source(io_error);
//! assert!(err.is_cryptographic());
//! ```
//!
//! When you try several encrypted data keys and each fails, return them together with
//! [`Error::all_failed`]: any one succeeding would have been enough,
//! so it is retryable if any attempt is.
//! When several steps your keyring needed fail, return them with [`Error::any_failed`]:
//! one permanent failure makes the whole operation not retryable.
//! Both pick the variant and keep the details every failure shares,
//! and with one failure return that failure.
//!
//! Implement [`name`](Keyring::name): errors about your keyring show it.
//! You do not need to set `resource()` to your keyring:
//! the AWS Encryption SDK sets it to [`Resource::Keyring`](crate::error::Resource::Keyring)
//! or [`Resource::Cmm`](crate::error::Resource::Cmm) and your name
//! when your materials are rejected or no data key matched.

use crate::Error;
use async_trait::async_trait;

pub mod raw_aes_keyring;

pub use raw_aes_keyring::{RawAesKeyring, RawAesKeyringBuilder};

use crate::structures::{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials};

/// To hold a keyring whose concrete type is chosen at runtime, use [`SharedKeyring`].
#[async_trait]
pub trait Keyring: Send + Sync {
    /// A short name for this keyring, which errors show.
    ///
    /// The ESDK reports a failure of a caller's keyring with
    /// `resource()` set to [`Resource::Keyring`](crate::error::Resource::Keyring) and this name.
    /// It should be stable and short, and must not contain secrets.
    /// The default is the type's name.
    fn name(&self) -> &str {
        std::any::type_name::<Self>()
    }

    /// Modify the supplied [`EncryptionMaterials`] by generating and/or
    /// encrypting a data key. See the
    /// [OnEncrypt](../../../spec/framework/keyring-interface.md#onencrypt)
    /// section of the keyring interface specification.
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, Error>;

    /// Modify the supplied [`DecryptionMaterials`] by deriving the plaintext
    /// data key from one of the supplied encrypted data keys. See the
    /// [OnDecrypt](../../../spec/framework/keyring-interface.md#ondecrypt)
    /// section of the keyring interface specification.
    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, Error>;
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
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, Error> {
        self.0.on_encrypt(materials).await
    }

    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, Error> {
        self.0.on_decrypt(materials, encrypted_data_keys).await
    }
}
