// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Inputs and outputs of the [`Keyring`](super::Keyring) operations.

use crate::Error;
use crate::builder::required;
use crate::structures::{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials};

/// Input for [`Keyring::on_encrypt`](super::Keyring::on_encrypt).
#[derive(Debug)]
#[non_exhaustive]
pub struct OnEncryptInput {
    pub(crate) materials: EncryptionMaterials,
}

impl OnEncryptInput {
    /// Start a builder for `OnEncryptInput`.
    #[must_use]
    pub fn builder() -> OnEncryptInputBuilder {
        OnEncryptInputBuilder::default()
    }

    /// The encryption materials to add a data key to.
    #[must_use]
    pub const fn materials(&self) -> &EncryptionMaterials {
        &self.materials
    }

    /// The materials, consuming the input.
    #[must_use]
    pub fn into_materials(self) -> EncryptionMaterials {
        self.materials
    }
}

/// Builder for [`OnEncryptInput`].
#[derive(Debug, Default)]
pub struct OnEncryptInputBuilder {
    materials: Option<EncryptionMaterials>,
}

impl OnEncryptInputBuilder {
    /// Set the encryption materials to add a data key to.
    /// Required.
    #[must_use]
    pub fn materials(mut self, materials: impl Into<EncryptionMaterials>) -> Self {
        self.materials = Some(materials.into());
        self
    }

    /// Set or clear the materials from an `Option`.
    /// To set a value, use [`Self::materials`].
    #[must_use]
    pub fn set_materials(mut self, materials: Option<EncryptionMaterials>) -> Self {
        self.materials = materials;
        self
    }

    /// Build the `OnEncryptInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `materials` is unset.
    pub fn build(self) -> Result<OnEncryptInput, Error> {
        Ok(OnEncryptInput {
            materials: required(self.materials, "materials")?,
        })
    }
}

/// Output of [`Keyring::on_encrypt`](super::Keyring::on_encrypt).
#[derive(Debug)]
#[non_exhaustive]
pub struct OnEncryptOutput {
    pub(crate) materials: EncryptionMaterials,
}

impl OnEncryptOutput {
    /// Start a builder for `OnEncryptOutput`.
    #[must_use]
    pub fn builder() -> OnEncryptOutputBuilder {
        OnEncryptOutputBuilder::default()
    }

    /// The encryption materials with the keyring's data key added.
    #[must_use]
    pub const fn materials(&self) -> &EncryptionMaterials {
        &self.materials
    }

    /// The materials, consuming the output.
    #[must_use]
    pub fn into_materials(self) -> EncryptionMaterials {
        self.materials
    }
}

/// Builder for [`OnEncryptOutput`].
#[derive(Debug, Default)]
pub struct OnEncryptOutputBuilder {
    materials: Option<EncryptionMaterials>,
}

impl OnEncryptOutputBuilder {
    /// Set the encryption materials with the keyring's data key added.
    /// Required.
    #[must_use]
    pub fn materials(mut self, materials: impl Into<EncryptionMaterials>) -> Self {
        self.materials = Some(materials.into());
        self
    }

    /// Set or clear the materials from an `Option`.
    /// To set a value, use [`Self::materials`].
    #[must_use]
    pub fn set_materials(mut self, materials: Option<EncryptionMaterials>) -> Self {
        self.materials = materials;
        self
    }

    /// Build the `OnEncryptOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `materials` is unset.
    pub fn build(self) -> Result<OnEncryptOutput, Error> {
        Ok(OnEncryptOutput {
            materials: required(self.materials, "materials")?,
        })
    }
}

/// Input for [`Keyring::on_decrypt`](super::Keyring::on_decrypt).
#[derive(Debug)]
#[non_exhaustive]
pub struct OnDecryptInput {
    pub(crate) materials: DecryptionMaterials,
    pub(crate) encrypted_data_keys: Vec<EncryptedDataKey>,
}

impl OnDecryptInput {
    /// Start a builder for `OnDecryptInput`.
    #[must_use]
    pub fn builder() -> OnDecryptInputBuilder {
        OnDecryptInputBuilder::default()
    }

    /// The decryption materials to add the plaintext data key to.
    #[must_use]
    pub const fn materials(&self) -> &DecryptionMaterials {
        &self.materials
    }

    /// The encrypted data keys to try.
    #[must_use]
    pub fn encrypted_data_keys(&self) -> &[EncryptedDataKey] {
        &self.encrypted_data_keys
    }

    /// The materials, consuming the input.
    #[must_use]
    pub fn into_materials(self) -> DecryptionMaterials {
        self.materials
    }

    /// The materials and the encrypted data keys, consuming the input.
    #[must_use]
    pub fn into_parts(self) -> (DecryptionMaterials, Vec<EncryptedDataKey>) {
        (self.materials, self.encrypted_data_keys)
    }
}

/// Builder for [`OnDecryptInput`].
#[derive(Debug, Default)]
pub struct OnDecryptInputBuilder {
    materials: Option<DecryptionMaterials>,
    encrypted_data_keys: Option<Vec<EncryptedDataKey>>,
}

impl OnDecryptInputBuilder {
    /// Set the decryption materials to add the plaintext data key to.
    /// Required.
    #[must_use]
    pub fn materials(mut self, materials: impl Into<DecryptionMaterials>) -> Self {
        self.materials = Some(materials.into());
        self
    }

    /// Set or clear the materials from an `Option`.
    /// To set a value, use [`Self::materials`].
    #[must_use]
    pub fn set_materials(mut self, materials: Option<DecryptionMaterials>) -> Self {
        self.materials = materials;
        self
    }

    /// Set the encrypted data keys to try.
    /// Required.
    #[must_use]
    pub fn encrypted_data_keys(
        mut self,
        encrypted_data_keys: impl Into<Vec<EncryptedDataKey>>,
    ) -> Self {
        self.encrypted_data_keys = Some(encrypted_data_keys.into());
        self
    }

    /// Set or clear the encrypted data keys from an `Option`.
    /// To set a value, use [`Self::encrypted_data_keys`].
    #[must_use]
    pub fn set_encrypted_data_keys(
        mut self,
        encrypted_data_keys: Option<Vec<EncryptedDataKey>>,
    ) -> Self {
        self.encrypted_data_keys = encrypted_data_keys;
        self
    }

    /// Build the `OnDecryptInput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `materials` or `encrypted_data_keys` is unset.
    pub fn build(self) -> Result<OnDecryptInput, Error> {
        Ok(OnDecryptInput {
            materials: required(self.materials, "materials")?,
            encrypted_data_keys: required(self.encrypted_data_keys, "encrypted_data_keys")?,
        })
    }
}

/// Output of [`Keyring::on_decrypt`](super::Keyring::on_decrypt).
#[derive(Debug)]
#[non_exhaustive]
pub struct OnDecryptOutput {
    pub(crate) materials: DecryptionMaterials,
}

impl OnDecryptOutput {
    /// Start a builder for `OnDecryptOutput`.
    #[must_use]
    pub fn builder() -> OnDecryptOutputBuilder {
        OnDecryptOutputBuilder::default()
    }

    /// The decryption materials with the plaintext data key added.
    #[must_use]
    pub const fn materials(&self) -> &DecryptionMaterials {
        &self.materials
    }

    /// The materials, consuming the output.
    #[must_use]
    pub fn into_materials(self) -> DecryptionMaterials {
        self.materials
    }
}

/// Builder for [`OnDecryptOutput`].
#[derive(Debug, Default)]
pub struct OnDecryptOutputBuilder {
    materials: Option<DecryptionMaterials>,
}

impl OnDecryptOutputBuilder {
    /// Set the decryption materials with the plaintext data key added.
    /// Required.
    #[must_use]
    pub fn materials(mut self, materials: impl Into<DecryptionMaterials>) -> Self {
        self.materials = Some(materials.into());
        self
    }

    /// Set or clear the materials from an `Option`.
    /// To set a value, use [`Self::materials`].
    #[must_use]
    pub fn set_materials(mut self, materials: Option<DecryptionMaterials>) -> Self {
        self.materials = materials;
        self
    }

    /// Build the `OnDecryptOutput`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): `materials` is unset.
    pub fn build(self) -> Result<OnDecryptOutput, Error> {
        Ok(OnDecryptOutput {
            materials: required(self.materials, "materials")?,
        })
    }
}

impl From<EncryptionMaterials> for OnEncryptOutput {
    fn from(materials: EncryptionMaterials) -> Self {
        Self { materials }
    }
}

impl From<DecryptionMaterials> for OnDecryptOutput {
    fn from(materials: DecryptionMaterials) -> Self {
        Self { materials }
    }
}
