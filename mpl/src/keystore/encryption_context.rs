// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encryption context construction for branch key store operations.

use crate::{Error, ErrorKind};
use std::collections::BTreeMap;

use super::attributes::{
    ATTR_BRANCH_KEY_ID, ATTR_CREATE_TIME, ATTR_ENC, ATTR_HIERARCHY_VERSION, ATTR_KMS_ARN,
    ATTR_TABLENAME, ATTR_TYPE, ATTR_VERSION, CUSTOM_EC_PREFIX, TYPE_BEACON_ACTIVE,
    TYPE_BRANCH_ACTIVE, TYPE_BRANCH_VERSION_PREFIX,
};
use crate::structures::EncryptionContext;

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
    /// Custom encryption context supplied by the user, if any. Each key is
    /// added to the context prefixed with `aws-crypto-ec:`, so callers pass
    /// keys unprefixed. This is only for user-supplied custom encryption
    /// context; attributes already present on a stored DynamoDB item are a
    /// read-path concern (see [`super::record::encryption_context_from_item`])
    /// and are not passed here.
    pub custom_ec: Option<&'a EncryptionContext>,
}

/// Builds the base encryption context shared by all flavors.
fn build_base(
    input: &EncryptionContextInput<'_>,
    type_value: &str,
) -> Result<BTreeMap<String, String>, Error> {
    if input.branch_key_id.is_empty() {
        return Err(Error::new(
            ErrorKind::Validation,
            "branch-key-id MUST not be an empty string",
        ));
    }

    if type_value.is_empty() {
        return Err(Error::new(
            ErrorKind::Validation,
            "type field MUST not be an empty string",
        ));
    }

    let mut ec = BTreeMap::new();

    ec.insert(
        ATTR_BRANCH_KEY_ID.to_string(),
        input.branch_key_id.to_string(),
    );

    ec.insert(ATTR_TYPE.to_string(), type_value.to_string());

    ec.insert(ATTR_CREATE_TIME.to_string(), input.create_time.to_string());

    ec.insert(
        ATTR_TABLENAME.to_string(),
        input.logical_keystore_name.to_string(),
    );

    ec.insert(ATTR_KMS_ARN.to_string(), input.kms_arn.to_string());

    ec.insert(
        ATTR_HIERARCHY_VERSION.to_string(),
        input.hierarchy_version.to_string(),
    );

    debug_assert!(
        !ec.contains_key(ATTR_ENC),
        "constructed encryption context must not contain 'enc'"
    );

    // Custom encryption context
    if let Some(custom) = input.custom_ec {
        for (key_str, val_str) in custom.iter() {
            // A custom key that already carries the prefix, or a duplicate
            // after prefixing, would otherwise overwrite a previous entry.
            if ec
                .insert(format!("{CUSTOM_EC_PREFIX}{key_str}"), val_str.to_string())
                .is_some()
            {
                return Err(Error::new(
                    ErrorKind::Validation,
                    format!(
                        "custom encryption context key '{key_str}' collides with an existing \
                         encryption context entry after prefixing with '{CUSTOM_EC_PREFIX}'"
                    ),
                ));
            }
        }
    }

    Ok(ec)
}

/// Builds the ACTIVE branch-key encryption context.
///
/// `version` MUST be the branch key version (without the "branch:version:" prefix).
///
/// The ACTIVE context is the DECRYPT_ONLY context with the `type` attribute
/// set to "branch:ACTIVE" and the branch key version moved into the `version`
/// attribute, so it is derived from [`decrypt_only_encryption_context`] rather
/// than built independently.
pub fn active_encryption_context(
    input: &EncryptionContextInput<'_>,
    version: &str,
) -> Result<BTreeMap<String, String>, Error> {
    let mut ec = decrypt_only_encryption_context(input, version)?;

    // In DECRYPT_ONLY the branch key version lives in `type`; ACTIVE moves it
    // to `version` and sets `type` to "branch:ACTIVE".
    ec.insert(ATTR_TYPE.to_string(), TYPE_BRANCH_ACTIVE.to_string());
    ec.insert(
        ATTR_VERSION.to_string(),
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
) -> Result<BTreeMap<String, String>, Error> {
    if version.is_empty() {
        return Err(Error::new(
            ErrorKind::Validation,
            "branch key version MUST not be an empty string",
        ));
    }

    let type_value = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    let ec = build_base(input, &type_value)?;

    debug_assert!(
        !ec.contains_key(ATTR_VERSION),
        "DECRYPT_ONLY encryption context must not have a version attribute"
    );

    Ok(ec)
}

/// Builds the beacon-key encryption context.
pub fn beacon_key_encryption_context(
    input: &EncryptionContextInput<'_>,
) -> Result<BTreeMap<String, String>, Error> {
    let ec = build_base(input, TYPE_BEACON_ACTIVE)?;

    debug_assert!(
        !ec.contains_key(ATTR_VERSION),
        "Beacon key encryption context must not have a version attribute"
    );

    Ok(ec)
}
