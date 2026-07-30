// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encryption context construction for branch key store operations.

use std::collections::BTreeMap;

use super::error::{KeystoreError, KeystoreErrorKind};
use crate::structures::EncryptionContext;

/// Key for the branch-key-id attribute.
pub const KEY_BRANCH_KEY_ID: &str = "branch-key-id";
/// Key for the type attribute.
pub const KEY_TYPE: &str = "type";
/// Key for the create-time attribute.
pub const KEY_CREATE_TIME: &str = "create-time";
/// Key for the tablename attribute (stores logicalKeyStoreName).
pub const KEY_TABLENAME: &str = "tablename";
/// Key for the kms-arn attribute.
pub const KEY_KMS_ARN: &str = "kms-arn";
/// Key for the hierarchy-version attribute.
pub const KEY_HIERARCHY_VERSION: &str = "hierarchy-version";
/// Key for the version attribute (ACTIVE only).
pub const KEY_VERSION: &str = "version";
/// Key for the enc attribute (MUST NOT be present in constructed EC).
pub const KEY_ENC: &str = "enc";

/// Type value for ACTIVE branch keys.
pub const TYPE_BRANCH_ACTIVE: &str = "branch:ACTIVE";
/// Type value for ACTIVE beacon keys.
pub const TYPE_BEACON_ACTIVE: &str = "beacon:ACTIVE";
/// Prefix for branch key version strings.
pub const TYPE_BRANCH_VERSION_PREFIX: &str = "branch:version:";

/// Prefix added to custom encryption context keys for namespace isolation.
pub const CUSTOM_EC_PREFIX: &str = "aws-crypto-ec:";

/// Inputs required to construct any flavor of keystore encryption context.
#[derive(Debug, Clone)]
pub struct EncryptionContextInput<'a> {
    /// The branch key identifier.
    pub branch_key_id: &'a str,
    /// ISO 8601 creation timestamp.
    pub create_time: &'a str,
    /// Logical keystore name (becomes `tablename` value per spec).
    pub logical_keystore_name: &'a str,
    /// KMS key ARN.
    pub kms_arn: &'a str,
    /// Hierarchy version (becomes string representation).
    pub hierarchy_version: u32,
    /// Optional custom encryption context.
    pub custom_ec: Option<&'a EncryptionContext>,
}

/// Builds the base encryption context shared by all flavors.
fn build_base(
    input: &EncryptionContextInput<'_>,
    type_value: &str,
) -> Result<BTreeMap<String, String>, KeystoreError> {
    if input.branch_key_id.is_empty() {
        return Err(KeystoreError::new(
            KeystoreErrorKind::Configuration,
            "branch-key-id MUST not be an empty string",
        ));
    }

    if type_value.is_empty() {
        return Err(KeystoreError::new(
            KeystoreErrorKind::Configuration,
            "type field MUST not be an empty string",
        ));
    }

    let mut ec = BTreeMap::new();

    ec.insert(
        KEY_BRANCH_KEY_ID.to_string(),
        input.branch_key_id.to_string(),
    );

    ec.insert(KEY_TYPE.to_string(), type_value.to_string());

    ec.insert(KEY_CREATE_TIME.to_string(), input.create_time.to_string());

    ec.insert(
        KEY_TABLENAME.to_string(),
        input.logical_keystore_name.to_string(),
    );

    ec.insert(KEY_KMS_ARN.to_string(), input.kms_arn.to_string());

    ec.insert(
        KEY_HIERARCHY_VERSION.to_string(),
        input.hierarchy_version.to_string(),
    );

    debug_assert!(
        !ec.contains_key(KEY_ENC),
        "constructed encryption context must not contain 'enc'"
    );

    // Custom encryption context
    if let Some(custom) = input.custom_ec {
        for (k, v) in custom.iter() {
            // The custom encryption context becomes part of the authenticated
            // AWS KMS encryption context, so a byte sequence that is not valid
            // UTF-8 cannot be represented and MUST be rejected. Decoding it
            // lossily would substitute U+FFFD, producing an encryption context
            // that other implementations cannot reproduce.
            let Ok(key_str) = str::from_utf8(k) else {
                return Err(KeystoreError::new(
                    KeystoreErrorKind::Configuration,
                    "custom encryption context key MUST be valid UTF-8",
                ));
            };

            let Ok(val_str) = str::from_utf8(v) else {
                return Err(KeystoreError::new(
                    KeystoreErrorKind::Configuration,
                    format!(
                        "custom encryption context value for key '{key_str}' MUST be valid UTF-8"
                    ),
                ));
            };

            // A custom key that already carries the prefix, or a duplicate
            // after prefixing, would otherwise overwrite a previous entry.
            if ec
                .insert(format!("{CUSTOM_EC_PREFIX}{key_str}"), val_str.to_string())
                .is_some()
            {
                return Err(KeystoreError::new(
                    KeystoreErrorKind::Configuration,
                    format!(
                        "custom encryption context key '{key_str}' collides with an existing \
                         encryption context entry after prefixing with '{CUSTOM_EC_PREFIX}'"
                    ),
                ));
            }
        }
    }

    // NOTE: Additional DDB attributes beyond the standard keys are handled
    // by the caller (record-format module) which passes them via custom_ec.
    // This function constructs the base; the caller is responsible for
    // merging any extra DDB attributes before calling KMS.

    Ok(ec)
}

/// Builds the ACTIVE branch-key encryption context.
///
/// `version` MUST be the branch key version (without the "branch:version:" prefix).
pub fn active_encryption_context(
    input: &EncryptionContextInput<'_>,
    version: &str,
) -> Result<BTreeMap<String, String>, KeystoreError> {
    let mut ec = build_base(input, TYPE_BRANCH_ACTIVE)?;

    //
    ec.insert(
        KEY_VERSION.to_string(),
        format!("{TYPE_BRANCH_VERSION_PREFIX}{version}"),
    );

    Ok(ec)
}

/// Builds the DECRYPT_ONLY branch-key encryption context.
///
/// `version` MUST be the branch key version (without the "branch:version:" prefix).
pub fn decrypt_only_encryption_context(
    input: &EncryptionContextInput<'_>,
    version: &str,
) -> Result<BTreeMap<String, String>, KeystoreError> {
    let type_value = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    let ec = build_base(input, &type_value)?;

    debug_assert!(
        !ec.contains_key(KEY_VERSION),
        "DECRYPT_ONLY encryption context must not have a version attribute"
    );

    Ok(ec)
}

/// Builds the beacon-key encryption context.
pub fn beacon_key_encryption_context(
    input: &EncryptionContextInput<'_>,
) -> Result<BTreeMap<String, String>, KeystoreError> {
    let ec = build_base(input, TYPE_BEACON_ACTIVE)?;

    debug_assert!(
        !ec.contains_key(KEY_VERSION),
        "Beacon key encryption context must not have a version attribute"
    );

    Ok(ec)
}
