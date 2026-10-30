// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypted data key structure.

use crate::Error;
use crate::builder::required;

/// An encrypted data key comprised of provider ID, provider info, and ciphertext.
///
/// Construct with [`EncryptedDataKey::builder`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncryptedDataKey {
    /// The MUST-be-binary half of the spec citation below is satisfied by
    /// construction — Rust's `String` is a UTF-8 byte sequence. The
    /// SHOULD-equal-namespace half is concrete-keyring scope (each concrete
    /// keyring chooses the value when constructing the EDK).
    key_provider_id: String,
    /// The MUST-be-binary half of the spec citation below is satisfied by
    /// construction — `Vec<u8>` is a binary byte sequence. The
    /// SHOULD-equal-name half is concrete-keyring scope (each concrete
    /// keyring chooses the value when constructing the EDK).
    key_provider_info: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptedDataKey {
    /// Start a builder for `EncryptedDataKey`.
    /// Every field is required.
    #[must_use]
    pub fn builder() -> EncryptedDataKeyBuilder {
        EncryptedDataKeyBuilder::default()
    }

    /// UTF-8 key provider identifier.
    #[must_use]
    pub fn key_provider_id(&self) -> &str {
        &self.key_provider_id
    }

    /// Opaque key provider information bytes.
    #[must_use]
    pub fn key_provider_info(&self) -> &[u8] {
        &self.key_provider_info
    }

    /// Opaque ciphertext bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Builder for [`EncryptedDataKey`].
#[derive(Debug, Clone, Default)]
pub struct EncryptedDataKeyBuilder {
    key_provider_id: Option<String>,
    key_provider_info: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
}

impl EncryptedDataKeyBuilder {
    /// Set the key provider identifier.
    /// Required.
    #[must_use]
    pub fn key_provider_id(mut self, key_provider_id: impl Into<String>) -> Self {
        self.key_provider_id = Some(key_provider_id.into());
        self
    }

    /// Set or clear the key provider identifier from an `Option`.
    /// To set a value, use [`Self::key_provider_id`].
    #[must_use]
    pub fn set_key_provider_id(mut self, key_provider_id: Option<String>) -> Self {
        self.key_provider_id = key_provider_id;
        self
    }

    /// The key provider ID, if set.
    #[must_use]
    pub const fn get_key_provider_id(&self) -> &Option<String> {
        &self.key_provider_id
    }

    /// Set the key provider information.
    /// Required.
    #[must_use]
    pub fn key_provider_info(mut self, key_provider_info: impl Into<Vec<u8>>) -> Self {
        self.key_provider_info = Some(key_provider_info.into());
        self
    }

    /// Set or clear the key provider information from an `Option`.
    /// To set a value, use [`Self::key_provider_info`].
    #[must_use]
    pub fn set_key_provider_info(mut self, key_provider_info: Option<Vec<u8>>) -> Self {
        self.key_provider_info = key_provider_info;
        self
    }

    /// The key provider info, if set.
    #[must_use]
    pub const fn get_key_provider_info(&self) -> &Option<Vec<u8>> {
        &self.key_provider_info
    }

    /// Set the ciphertext.
    /// Required.
    #[must_use]
    pub fn ciphertext(mut self, ciphertext: impl Into<Vec<u8>>) -> Self {
        self.ciphertext = Some(ciphertext.into());
        self
    }

    /// Set or clear the ciphertext from an `Option`.
    /// To set a value, use [`Self::ciphertext`].
    #[must_use]
    pub fn set_ciphertext(mut self, ciphertext: Option<Vec<u8>>) -> Self {
        self.ciphertext = ciphertext;
        self
    }

    /// The ciphertext, if set.
    #[must_use]
    pub const fn get_ciphertext(&self) -> &Option<Vec<u8>> {
        &self.ciphertext
    }

    /// Build the `EncryptedDataKey`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a field is unset.
    pub fn build(self) -> Result<EncryptedDataKey, Error> {
        let key_provider_id = required(self.key_provider_id, "key_provider_id")?;
        let key_provider_info = required(self.key_provider_info, "key_provider_info")?;
        let ciphertext = required(self.ciphertext, "ciphertext")?;
        Ok(EncryptedDataKey {
            key_provider_id,
            key_provider_info,
            ciphertext,
        })
    }
}

impl From<&EncryptedDataKey> for crate::error::DataKeyInfo {
    /// The key's provider ID and info, without its ciphertext.
    fn from(edk: &EncryptedDataKey) -> Self {
        Self::new(edk.key_provider_id.clone(), edk.key_provider_info.clone())
    }
}
