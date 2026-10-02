// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Keyring` trait — the abstract contract every keyring MUST implement.
//!
//! Uses #[async_trait] so that the CMM can hold any runtime defined
//! keyring. The macro makes this work by rewriting each `async fn`
//! to return a boxed future.

use crate::Error;
use async_trait::async_trait;

pub mod raw_aes_keyring;

pub use raw_aes_keyring::RawAesKeyring;

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
