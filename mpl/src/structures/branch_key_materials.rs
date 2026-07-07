// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Branch key materials structure.

use super::encryption_context::EncryptionContext;
use super::error::MaterialsError;

/// Materials for establishing a key hierarchy to reuse a data key that wraps other data keys.
///
pub struct BranchKeyMaterials {
    branch_key: [u8; 32],
    branch_key_id: String,
    branch_key_version: String,
    encryption_context: EncryptionContext,
}

impl BranchKeyMaterials {
    /// Construct branch key materials. Validates that `branch_key_version` is a valid UUIDv4.
    pub fn new(
        branch_key: [u8; 32],
        branch_key_id: String,
        branch_key_version: String,
        encryption_context: EncryptionContext,
    ) -> Result<Self, MaterialsError> {
        if !is_valid_uuid_v4(&branch_key_version) {
            return Err(MaterialsError::new(format!(
                "Branch key version is not a valid UUIDv4: {}",
                branch_key_version
            )));
        }

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

/// Validate that a string is a valid version 4 UUID in the canonical 8-4-4-4-12 hex format.
fn is_valid_uuid_v4(s: &str) -> bool {
    // Only accept the canonical hyphenated form (36 chars). The uuid crate's
    // parser also accepts simple (32), braced (38), and urn (45) forms;
    // this length check keeps the accepted surface narrow to the wire form
    // the keystore emits.
    if s.len() != 36 {
        return false;
    }
    let Ok(u) = uuid::Uuid::parse_str(s) else {
        return false;
    };
    // A well-formed v4 UUID has both the version=4 nibble AND the RFC 4122
    // variant (`10xx` high bits, hex digit ∈ {8, 9, a, b}). Uuid::parse_str
    // does not enforce the variant, so check it explicitly.
    u.get_version() == Some(uuid::Version::Random) && u.get_variant() == uuid::Variant::RFC4122
}
