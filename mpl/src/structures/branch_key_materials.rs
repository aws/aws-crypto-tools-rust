// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Branch key materials structure.

use super::encryption_context::EncryptionContext;
use super::error::MaterialsError;

/// Materials for establishing a key hierarchy to reuse a data key that wraps other data keys.
///
//= ../spec/framework/structures.md#structure-3
//= type=implication
//# This structure MUST include all of the following fields:
pub struct BranchKeyMaterials {
    //= ../spec/framework/structures.md#branch-key
    //= type=implication
    //# This key MUST be 32 bytes long.
    branch_key: [u8; 32],
    branch_key_id: String,
    branch_key_version: String,
    encryption_context: EncryptionContext,
}

impl BranchKeyMaterials {
    /// Construct branch key materials. Validates that `branch_key_version` is a valid UUIDv4.
    //= ../spec/framework/structures.md#branch-key
    //= type=exception
    //= reason=Origin requirement; enforced at the keystore layer (branch-key-store.md), not at this type.
    //# This data key MUST only be generated through
    //# AWS KMS using the [`GenerateDataKeyWithoutPlaintext`](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html) API.
    pub fn new(
        branch_key: [u8; 32],
        branch_key_id: String,
        branch_key_version: String,
        encryption_context: EncryptionContext,
    ) -> Result<Self, MaterialsError> {
        //= ../spec/framework/structures.md#branch-key-version
        //# This value MUST be a version 4 [UUID](https://www.ietf.org/rfc/rfc4122.txt).
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
    let bytes = s.as_bytes();
    // Must be exactly 36 characters: 8-4-4-4-12
    if bytes.len() != 36 {
        return false;
    }
    // Check hyphens at positions 8, 13, 18, 23
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    // Check version nibble: position 14 must be '4'
    if bytes[14] != b'4' {
        return false;
    }
    // Check variant nibble: position 19 must be '8', '9', 'a', 'b', 'A', or 'B'
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B') {
        return false;
    }
    // Check all other positions are hex digits
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue; // hyphens already checked
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}
