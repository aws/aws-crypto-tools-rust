// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Branch key materials structure.

use super::encryption_context::EncryptionContext;
use crate::Error;
use crate::builder::required;

/// Materials for establishing a key hierarchy to reuse a data key that wraps other data keys.
///
/// Construct with [`BranchKeyMaterials::builder`].
#[derive(Clone)]
#[non_exhaustive]
pub struct BranchKeyMaterials {
    branch_key: [u8; 32],
    branch_key_id: String,
    branch_key_version: String,
    encryption_context: EncryptionContext,
}

impl BranchKeyMaterials {
    /// Start a builder for `BranchKeyMaterials`.
    #[must_use]
    pub fn builder() -> BranchKeyMaterialsBuilder {
        BranchKeyMaterialsBuilder::default()
    }

    /// The plaintext branch key.
    #[must_use]
    pub const fn branch_key(&self) -> &[u8; 32] {
        &self.branch_key
    }

    /// The branch key identifier.
    #[must_use]
    pub fn branch_key_id(&self) -> &str {
        &self.branch_key_id
    }

    /// The branch key version.
    #[must_use]
    pub fn branch_key_version(&self) -> &str {
        &self.branch_key_version
    }

    /// The custom encryption context of the branch key.
    #[must_use]
    pub const fn encryption_context(&self) -> &EncryptionContext {
        &self.encryption_context
    }
}

impl std::fmt::Debug for BranchKeyMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranchKeyMaterials")
            .field("branch_key", &"[REDACTED; 32 bytes]")
            .field("branch_key_id", &self.branch_key_id)
            .field("branch_key_version", &self.branch_key_version)
            .field("encryption_context", &self.encryption_context)
            .finish()
    }
}

/// Builder for [`BranchKeyMaterials`].
#[derive(Clone, Default)]
pub struct BranchKeyMaterialsBuilder {
    branch_key: Option<[u8; 32]>,
    branch_key_id: Option<String>,
    branch_key_version: Option<String>,
    encryption_context: Option<EncryptionContext>,
}

impl BranchKeyMaterialsBuilder {
    /// Set the plaintext branch key.
    /// Required.
    #[must_use]
    pub fn branch_key(mut self, branch_key: impl Into<[u8; 32]>) -> Self {
        self.branch_key = Some(branch_key.into());
        self
    }

    /// Set or clear the branch key from an `Option`.
    /// To set a value, use [`Self::branch_key`].
    #[must_use]
    pub const fn set_branch_key(mut self, branch_key: Option<[u8; 32]>) -> Self {
        self.branch_key = branch_key;
        self
    }

    /// The branch key, if set.
    #[must_use]
    pub const fn get_branch_key(&self) -> &Option<[u8; 32]> {
        &self.branch_key
    }

    /// Set the branch key identifier.
    /// Required, and must not be empty.
    #[must_use]
    pub fn branch_key_id(mut self, branch_key_id: impl Into<String>) -> Self {
        self.branch_key_id = Some(branch_key_id.into());
        self
    }

    /// Set or clear the branch key identifier from an `Option`.
    /// To set a value, use [`Self::branch_key_id`].
    #[must_use]
    pub fn set_branch_key_id(mut self, branch_key_id: Option<String>) -> Self {
        self.branch_key_id = branch_key_id;
        self
    }

    /// The branch key ID, if set.
    #[must_use]
    pub const fn get_branch_key_id(&self) -> &Option<String> {
        &self.branch_key_id
    }

    /// Set the branch key version.
    /// Required, and must not be empty.
    #[must_use]
    pub fn branch_key_version(mut self, branch_key_version: impl Into<String>) -> Self {
        self.branch_key_version = Some(branch_key_version.into());
        self
    }

    /// Set or clear the branch key version from an `Option`.
    /// To set a value, use [`Self::branch_key_version`].
    #[must_use]
    pub fn set_branch_key_version(mut self, branch_key_version: Option<String>) -> Self {
        self.branch_key_version = branch_key_version;
        self
    }

    /// The branch key version, if set.
    #[must_use]
    pub const fn get_branch_key_version(&self) -> &Option<String> {
        &self.branch_key_version
    }

    /// Set the custom encryption context of the branch key.
    /// Required.
    #[must_use]
    pub fn encryption_context(mut self, encryption_context: impl Into<EncryptionContext>) -> Self {
        self.encryption_context = Some(encryption_context.into());
        self
    }

    /// Set or clear the encryption context from an `Option`.
    /// To set a value, use [`Self::encryption_context`].
    #[must_use]
    pub fn set_encryption_context(mut self, encryption_context: Option<EncryptionContext>) -> Self {
        self.encryption_context = encryption_context;
        self
    }

    /// The encryption context, if set.
    #[must_use]
    pub const fn get_encryption_context(&self) -> &Option<EncryptionContext> {
        &self.encryption_context
    }

    /// Build the `BranchKeyMaterials`.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a field is unset, or `branch_key_id` or `branch_key_version` is empty.
    pub fn build(self) -> Result<BranchKeyMaterials, Error> {
        let branch_key_id = required(self.branch_key_id, "branch_key_id")?;
        if branch_key_id.is_empty() {
            return Err(Error::validation("branch_key_id must not be empty"));
        }
        let branch_key_version = required(self.branch_key_version, "branch_key_version")?;
        if branch_key_version.is_empty() {
            return Err(Error::validation("branch_key_version must not be empty"));
        }
        Ok(BranchKeyMaterials {
            branch_key: required(self.branch_key, "branch_key")?,
            branch_key_id,
            branch_key_version,
            encryption_context: required(self.encryption_context, "encryption_context")?,
        })
    }
}

impl std::fmt::Debug for BranchKeyMaterialsBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranchKeyMaterialsBuilder")
            .field(
                "branch_key",
                &self.branch_key.map(|_| "[REDACTED; 32 bytes]"),
            )
            .field("branch_key_id", &self.branch_key_id)
            .field("branch_key_version", &self.branch_key_version)
            .field("encryption_context", &self.encryption_context)
            .finish()
    }
}
