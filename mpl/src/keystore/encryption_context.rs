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
        //= ../spec/framework/branch-key-store.md#encryption-context
        //# - The `branch-key-id` field MUST not be an empty string
        return Err(KeystoreError::new(
            KeystoreErrorKind::Configuration,
            "branch-key-id MUST not be an empty string",
        ));
    }

    if type_value.is_empty() {
        //= ../spec/framework/branch-key-store.md#encryption-context
        //# - The `type` field MUST not be an empty string
        return Err(KeystoreError::new(
            KeystoreErrorKind::Configuration,
            "type field MUST not be an empty string",
        ));
    }

    let mut ec = BTreeMap::new();

    //= ../spec/framework/branch-key-store.md#encryption-context
    //# - MUST have a `branch-key-id` attribute
    ec.insert(
        KEY_BRANCH_KEY_ID.to_string(),
        input.branch_key_id.to_string(),
    );

    //= ../spec/framework/branch-key-store.md#encryption-context
    //# - MUST have a `type` attribute
    ec.insert(KEY_TYPE.to_string(), type_value.to_string());

    //= ../spec/framework/branch-key-store.md#encryption-context
    //# - MUST have a `create-time` attribute
    ec.insert(KEY_CREATE_TIME.to_string(), input.create_time.to_string());

    //= ../spec/framework/branch-key-store.md#encryption-context
    //# - MUST have a `tablename` attribute to store the logicalKeyStoreName
    ec.insert(
        KEY_TABLENAME.to_string(),
        input.logical_keystore_name.to_string(),
    );

    //= ../spec/framework/branch-key-store.md#encryption-context
    //# - MUST have a `kms-arn` attribute
    ec.insert(KEY_KMS_ARN.to_string(), input.kms_arn.to_string());

    //= ../spec/framework/branch-key-store.md#encryption-context
    //# - MUST have a `hierarchy-version`
    ec.insert(
        KEY_HIERARCHY_VERSION.to_string(),
        input.hierarchy_version.to_string(),
    );

    //= ../spec/framework/branch-key-store.md#encryption-context
    //# - MUST NOT have a `enc` attribute
    debug_assert!(
        !ec.contains_key(KEY_ENC),
        "constructed encryption context must not contain 'enc'"
    );

    // Custom encryption context
    //= ../spec/framework/branch-key-store.md#encryption-context
    //# Any additionally attributes on the DynamoDB item
    //# MUST be added to the encryption context.
    if let Some(custom) = input.custom_ec {
        //= ../spec/framework/branch-key-store.md#custom-encryption-context
        //# If custom [encryption context](./structures.md#encryption-context-3)
        //# is associated with the branch key these values MUST be added to the AWS KMS encryption context.
        for (k, v) in custom.iter() {
            let key_str = String::from_utf8_lossy(k);
            let val_str = String::from_utf8_lossy(v);
            //= ../spec/framework/branch-key-store.md#custom-encryption-context
            //# To avoid name collisions each added attribute from the custom [encryption context](./structures.md#encryption-context-3)
            //# MUST be prefixed with `aws-crypto-ec:`.
            ec.insert(format!("{CUSTOM_EC_PREFIX}{key_str}"), val_str.into_owned());
        }
    }

    // NOTE: Additional DDB attributes beyond the standard keys are handled
    // by the caller (record-format module) which passes them via custom_ec.
    // This function constructs the base; the caller is responsible for
    // merging any extra DDB attributes before calling KMS.

    //= ../spec/framework/branch-key-store.md#custom-encryption-context
    //= type=exception
    //= reason=Per master plan Phase 9 (slug keystore-version-key), this exception will be replaced with type=implementation on the version_key impl that compares the active EC against the new version's EC and type=test on the contract test that proves it.
    //# Across all versions of a Branch Key, the custom encryption context MUST be equal.

    Ok(ec)
}

/// Builds the ACTIVE branch-key encryption context.
///
/// `version` MUST be the branch key version (without the "branch:version:" prefix).
pub fn active_encryption_context(
    input: &EncryptionContextInput<'_>,
    version: &str,
) -> Result<BTreeMap<String, String>, KeystoreError> {
    //= ../spec/framework/branch-key-store.md#active-encryption-context
    //# The ACTIVE encryption context value of the `type` attribute MUST equal to `"branch:ACTIVE"`.
    let mut ec = build_base(input, TYPE_BRANCH_ACTIVE)?;

    //= ../spec/framework/branch-key-store.md#active-encryption-context
    //# The ACTIVE encryption context MUST have a `version` attribute.
    //
    //= ../spec/framework/branch-key-store.md#active-encryption-context
    //# The `version` attribute MUST store the branch key version formatted like `"branch:version:"` + `version`.
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
    //= ../spec/framework/branch-key-store.md#decrypt-only-encryption-context
    //# The `type` attribute MUST stores the branch key version formatted like `"branch:version:"` + `version`.
    let type_value = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    let ec = build_base(input, &type_value)?;

    //= ../spec/framework/branch-key-store.md#decrypt-only-encryption-context
    //# The DECRYPT_ONLY encryption context MUST NOT have a `version` attribute.
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
    //= ../spec/framework/branch-key-store.md#beacon-key-encryption-context
    //# The Beacon key encryption context value of the `type` attribute MUST equal to `"beacon:ACTIVE"`.
    let ec = build_base(input, TYPE_BEACON_ACTIVE)?;

    //= ../spec/framework/branch-key-store.md#beacon-key-encryption-context
    //# The Beacon key encryption context MUST NOT have a `version` attribute.
    debug_assert!(
        !ec.contains_key(KEY_VERSION),
        "Beacon key encryption context must not have a version attribute"
    );

    Ok(ec)
}
