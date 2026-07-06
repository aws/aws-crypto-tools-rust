// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Record format parsing and materials reconstruction for the branch key store.

use std::collections::BTreeMap;

use crate::keystore::error::{KeystoreError, KeystoreErrorKind};
use crate::structures::{BranchKeyMaterials, EncryptionContext};

/// Field name constants from the keystore record format spec.
pub const FIELD_BRANCH_KEY_ID: &str = "branch-key-id";
pub const FIELD_TYPE: &str = "type";
pub const FIELD_VERSION: &str = "version";
pub const FIELD_ENC: &str = "enc";
pub const FIELD_KMS_ARN: &str = "kms-arn";
pub const FIELD_CREATE_TIME: &str = "create-time";
pub const FIELD_HIERARCHY_VERSION: &str = "hierarchy-version";

pub const TYPE_BRANCH_ACTIVE: &str = "branch:ACTIVE";
pub const TYPE_BEACON_ACTIVE: &str = "beacon:ACTIVE";
pub const TYPE_BRANCH_VERSION_PREFIX: &str = "branch:version:";
pub const CUSTOM_EC_PREFIX: &str = "aws-crypto-ec:";

/// A DDB record at the string-keyed abstraction level.
#[derive(Debug, Clone)]
pub struct EncryptedRecord {
    pub attributes: BTreeMap<String, String>,
    pub enc: Vec<u8>,
}

/// Reconstructs the custom [`EncryptionContext`] portion from an authenticated
/// encryption context by extracting entries prefixed with `aws-crypto-ec:`.
pub fn custom_encryption_context_from_authenticated_encryption_context(
    authenticated_ec: &BTreeMap<String, String>,
) -> Result<EncryptionContext, KeystoreError> {
    let mut ec = EncryptionContext::new();

    for (key, value) in authenticated_ec {
        if let Some(stripped) = key.strip_prefix(CUSTOM_EC_PREFIX) {
            let ec_key = stripped.as_bytes().to_vec();

            let ec_value = value.as_bytes().to_vec();

            ec.insert(ec_key, ec_value);
        }
    }

    Ok(ec)
}

/// Reconstructs [`BranchKeyMaterials`] from an authenticated encryption context
/// plus decrypted plaintext branch key bytes.
pub fn branch_key_materials_from_authenticated_encryption_context(
    authenticated_ec: &BTreeMap<String, String>,
    plaintext_branch_key: Vec<u8>,
) -> Result<BranchKeyMaterials, KeystoreError> {
    let type_attr = authenticated_ec.get(FIELD_TYPE).ok_or_else(|| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            "Missing 'type' attribute in authenticated encryption context",
        )
    })?;

    if type_attr != TYPE_BRANCH_ACTIVE && !type_attr.starts_with(TYPE_BRANCH_VERSION_PREFIX) {
        return Err(KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!(
                "Invalid type attribute: '{}'. Must be '{}' or start with '{}'",
                type_attr, TYPE_BRANCH_ACTIVE, TYPE_BRANCH_VERSION_PREFIX
            ),
        ));
    }

    // Resolve version string based on type attribute value.
    let version_string = if type_attr == TYPE_BRANCH_ACTIVE {
        authenticated_ec
            .get(FIELD_VERSION)
            .ok_or_else(|| {
                KeystoreError::new(
                    KeystoreErrorKind::RecordMalformed,
                    "type is 'branch:ACTIVE' but 'version' attribute is missing",
                )
            })?
            .clone()
    } else {
        type_attr.clone()
    };

    if !version_string.starts_with(TYPE_BRANCH_VERSION_PREFIX) {
        return Err(KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!(
                "Version string '{}' does not start with '{}'",
                version_string, TYPE_BRANCH_VERSION_PREFIX
            ),
        ));
    }

    let branch_key_version = version_string[TYPE_BRANCH_VERSION_PREFIX.len()..].to_string();

    let branch_key_id = authenticated_ec
        .get(FIELD_BRANCH_KEY_ID)
        .ok_or_else(|| {
            KeystoreError::new(
                KeystoreErrorKind::RecordMalformed,
                "Missing 'branch-key-id' attribute in authenticated encryption context",
            )
        })?
        .clone();

    let encryption_context =
        custom_encryption_context_from_authenticated_encryption_context(authenticated_ec)?;

    let branch_key: [u8; 32] = plaintext_branch_key.try_into().map_err(|v: Vec<u8>| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Branch key must be 32 bytes, got {}", v.len()),
        )
    })?;

    BranchKeyMaterials::new(
        branch_key,
        branch_key_id,
        branch_key_version,
        encryption_context,
    )
    .map_err(|e| {
        KeystoreError::new(
            KeystoreErrorKind::RecordMalformed,
            format!("Failed to construct BranchKeyMaterials: {}", e),
        )
    })
}
