// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Branch key materials structure.

use super::encryption_context::EncryptionContext;
use super::error::MaterialsError;

/// Materials for establishing a key hierarchy to reuse a data key that wraps other data keys.
///
//= spec/framework/structures.md#structure-3
//= type=implication
//# This structure MUST include all of the following fields:
#[derive(Clone)]
pub struct BranchKeyMaterials {
    //= spec/framework/structures.md#branch-key
    //= type=implication
    //# This key MUST be 32 bytes long.
    branch_key: [u8; 32],
    branch_key_id: String,
    branch_key_version: String,
    encryption_context: EncryptionContext,
}

impl BranchKeyMaterials {
    /// Construct branch key materials. Callers are responsible for supplying
    /// a well-formed `branch_key_version` string (a canonical hyphenated
    /// UUIDv4 produced by the `uuid` crate at generation time in the branch-
    /// key-store slice, or converted from raw bytes via
    /// `uuid::Uuid::from_bytes(...).hyphenated().to_string()` on decrypt);
    /// this constructor does not re-validate.
    pub fn new(
        branch_key: [u8; 32],
        branch_key_id: String,
        branch_key_version: String,
        encryption_context: EncryptionContext,
    ) -> Result<Self, MaterialsError> {
        Ok(Self {
            branch_key,
            branch_key_id,
            branch_key_version,
            encryption_context,
        })
    }

    pub fn branch_key(&self) -> &[u8; 32] {
        &self.branch_key
    }

    pub fn branch_key_id(&self) -> &str {
        &self.branch_key_id
    }

    pub fn branch_key_version(&self) -> &str {
        &self.branch_key_version
    }

    pub fn encryption_context(&self) -> &EncryptionContext {
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
