// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fluent builders for the [`SharedKeyring`] operations.

use super::{
    Keyring, OnDecryptInput, OnDecryptInputBuilder, OnDecryptOutput, OnEncryptInput,
    OnEncryptInputBuilder, OnEncryptOutput, SharedKeyring,
};
use crate::Error;
use crate::error::KeyringResource;
use crate::structures::materials_checks;
use crate::structures::{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials};

impl SharedKeyring {
    /// Start a [`Keyring::on_encrypt`] call.
    pub fn on_encrypt(&self) -> OnEncryptFluentBuilder {
        OnEncryptFluentBuilder {
            handle: self.clone(),
            inner: OnEncryptInput::builder(),
        }
    }

    /// Start a [`Keyring::on_decrypt`] call.
    pub fn on_decrypt(&self) -> OnDecryptFluentBuilder {
        OnDecryptFluentBuilder {
            handle: self.clone(),
            inner: OnDecryptInput::builder(),
        }
    }
}

/// Fluent builder for [`SharedKeyring::on_encrypt`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct OnEncryptFluentBuilder {
    handle: SharedKeyring,
    inner: OnEncryptInputBuilder,
}

impl OnEncryptFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub fn as_input(&self) -> &OnEncryptInputBuilder {
        &self.inner
    }

    /// Set the encryption materials to add a data key to.
    /// Required.
    pub fn materials(mut self, materials: impl Into<EncryptionMaterials>) -> Self {
        self.inner = self.inner.materials(materials);
        self
    }

    /// Set or clear the materials from an `Option`.
    /// To set a value, use [`Self::materials`].
    pub fn set_materials(mut self, materials: Option<EncryptionMaterials>) -> Self {
        self.inner = self.inner.set_materials(materials);
        self
    }

    /// The materials, if set.
    #[must_use]
    pub fn get_materials(&self) -> &Option<EncryptionMaterials> {
        self.inner.get_materials()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `materials` is unset.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the input or returned materials are invalid,
    ///   the returned materials have no plaintext data key,
    ///   or the keyring changed anything other than adding a plaintext data key and encrypted data keys.
    ///
    /// Otherwise, the errors [`Keyring::on_encrypt`] documents.
    pub async fn send(self) -> Result<OnEncryptOutput, Error> {
        let input = self.inner.build()?;
        let before = input.materials().clone();
        let output = Keyring::on_encrypt(&*self.handle.0, input).await?;
        materials_checks::check_encryption_transition(&before, output.materials())
            .map_err(|e| e.with_resource(KeyringResource::new(self.handle.name())))?;
        Ok(output)
    }
}

/// Fluent builder for [`SharedKeyring::on_decrypt`].
#[derive(Debug, Clone)]
#[must_use = "does nothing until `send` is called"]
pub struct OnDecryptFluentBuilder {
    handle: SharedKeyring,
    inner: OnDecryptInputBuilder,
}

impl OnDecryptFluentBuilder {
    /// The input set so far.
    #[must_use]
    pub fn as_input(&self) -> &OnDecryptInputBuilder {
        &self.inner
    }

    /// Set the decryption materials to add the plaintext data key to.
    /// Required.
    pub fn materials(mut self, materials: impl Into<DecryptionMaterials>) -> Self {
        self.inner = self.inner.materials(materials);
        self
    }

    /// Set or clear the materials from an `Option`.
    /// To set a value, use [`Self::materials`].
    pub fn set_materials(mut self, materials: Option<DecryptionMaterials>) -> Self {
        self.inner = self.inner.set_materials(materials);
        self
    }

    /// The materials, if set.
    #[must_use]
    pub fn get_materials(&self) -> &Option<DecryptionMaterials> {
        self.inner.get_materials()
    }

    /// Appends an item to the encrypted data keys to try.
    ///
    /// To override the contents of this collection use [`set_encrypted_data_keys`](Self::set_encrypted_data_keys).
    /// Required.
    pub fn encrypted_data_keys(mut self, input: EncryptedDataKey) -> Self {
        self.inner = self.inner.encrypted_data_keys(input);
        self
    }

    /// Set or clear the encrypted data keys from an `Option`.
    /// To add one entry, use [`Self::encrypted_data_keys`].
    pub fn set_encrypted_data_keys(
        mut self,
        encrypted_data_keys: Option<Vec<EncryptedDataKey>>,
    ) -> Self {
        self.inner = self.inner.set_encrypted_data_keys(encrypted_data_keys);
        self
    }

    /// The encrypted data keys, if set.
    #[must_use]
    pub fn get_encrypted_data_keys(&self) -> &Option<Vec<EncryptedDataKey>> {
        self.inner.get_encrypted_data_keys()
    }

    /// Send the request.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `materials` or `encrypted_data_keys` is unset.
    /// - [`InvalidMaterials`](crate::Error::InvalidMaterials): the input or returned materials are invalid,
    ///   the input materials already have a plaintext data key,
    ///   the returned materials have no plaintext data key,
    ///   or the keyring changed anything other than adding a plaintext data key.
    ///
    /// Otherwise, the errors [`Keyring::on_decrypt`] documents.
    pub async fn send(self) -> Result<OnDecryptOutput, Error> {
        let input = self.inner.build()?;
        let before = input.materials().clone();
        let output = Keyring::on_decrypt(&*self.handle.0, input).await?;
        materials_checks::check_decryption_transition(&before, output.materials())
            .map_err(|e| e.with_resource(KeyringResource::new(self.handle.name())))?;
        Ok(output)
    }
}

/// Add the [`SharedKeyring`] fluent calls to a built-in keyring.
macro_rules! fluent_keyring {
    ($($ty:ty),+) => {$(
        impl $ty {
            /// Start a [`Keyring::on_encrypt`] call.
            pub fn on_encrypt(&self) -> OnEncryptFluentBuilder {
                SharedKeyring::new(crate::shared::Builtin(self.clone())).on_encrypt()
            }

            /// Start a [`Keyring::on_decrypt`] call.
            pub fn on_decrypt(&self) -> OnDecryptFluentBuilder {
                SharedKeyring::new(crate::shared::Builtin(self.clone())).on_decrypt()
            }
        }

        impl crate::shared::FromUnshared<$ty> for SharedKeyring {
            fn from_unshared(value: $ty) -> Self {
                SharedKeyring::new(crate::shared::Builtin(value))
            }
        }
    )+};
}

fluent_keyring!(
    super::RawAesKeyring,
    crate::aws_kms::hierarchical_keyring::HierarchicalKeyring
);

#[cfg(feature = "kms")]
fluent_keyring!(crate::aws_kms::aws_kms_keyring::AwsKmsKeyring);
