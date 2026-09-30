// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypted data key structure.

use super::error::MaterialsError;

/// An encrypted data key comprised of provider ID, provider info, and ciphertext.
///
/// Construct with [`EncryptedDataKey::builder`].
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Start a builder for `EncryptedDataKey`. Every field is required.
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
    /// Set the key provider identifier. Required.
    #[must_use]
    pub fn key_provider_id(mut self, key_provider_id: impl Into<String>) -> Self {
        self.key_provider_id = Some(key_provider_id.into());
        self
    }

    /// Set the key provider information. Required.
    #[must_use]
    pub fn key_provider_info(mut self, key_provider_info: impl Into<Vec<u8>>) -> Self {
        self.key_provider_info = Some(key_provider_info.into());
        self
    }

    /// Set the ciphertext. Required.
    #[must_use]
    pub fn ciphertext(mut self, ciphertext: impl Into<Vec<u8>>) -> Self {
        self.ciphertext = Some(ciphertext.into());
        self
    }

    /// Build the `EncryptedDataKey`.
    ///
    /// # Errors
    ///
    /// Returns a [`MaterialsErrorKind::Validation`](super::MaterialsErrorKind::Validation)
    /// error if any field is unset.
    pub fn build(self) -> Result<EncryptedDataKey, MaterialsError> {
        let Some(key_provider_id) = self.key_provider_id else {
            return Err(MaterialsError::new(
                "EncryptedDataKey: a key provider ID is required",
            ));
        };
        let Some(key_provider_info) = self.key_provider_info else {
            return Err(MaterialsError::new(
                "EncryptedDataKey: key provider information is required",
            ));
        };
        let Some(ciphertext) = self.ciphertext else {
            return Err(MaterialsError::new(
                "EncryptedDataKey: a ciphertext is required",
            ));
        };
        Ok(EncryptedDataKey {
            key_provider_id,
            key_provider_info,
            ciphertext,
        })
    }
}
