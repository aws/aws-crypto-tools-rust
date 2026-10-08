// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Record format parsing and materials reconstruction for the branch key store.

use crate::Error;
use crate::error::{BranchKey, Kind, Resource, Service};
use std::collections::BTreeMap;

use crate::keystore::attributes::{
    ATTR_BRANCH_KEY_ID, ATTR_ENC, ATTR_TABLENAME, ATTR_TYPE, ATTR_VERSION, CUSTOM_EC_PREFIX,
    TYPE_BRANCH_ACTIVE, TYPE_BRANCH_VERSION_PREFIX,
};
use crate::structures::{BranchKeyMaterials, EncryptionContext};

/// A DDB record at the string-keyed abstraction level.
#[derive(Debug, Clone)]
pub struct EncryptedRecord {
    pub attributes: BTreeMap<String, String>,
    pub enc: Vec<u8>,
}

/// Projects an [`EncryptedRecord`] into the authenticated encryption context,
/// mirroring the Dafny `ToBranchKeyContext`: every stored attribute except
/// `enc`, plus a `tablename` attribute holding the logical keystore name.
///
/// Attributes present on the item beyond the standard record fields are
/// carried through verbatim — the spec requires every item attribute (except
/// `enc`) to be authenticated, and any custom encryption context pairs are
/// already stored with the `aws-crypto-ec:` prefix, so no prefixing happens
/// here. `enc` is held separately on [`EncryptedRecord`] and is never part of
/// the encryption context; an `enc` key appearing among `attributes` is
/// dropped defensively.
pub fn encryption_context_from_item(
    record: &EncryptedRecord,
    logical_keystore_name: &str,
) -> BTreeMap<String, String> {
    let mut ec: BTreeMap<String, String> = record
        .attributes
        .iter()
        .filter(|(k, _)| k.as_str() != ATTR_ENC)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    ec.insert(
        ATTR_TABLENAME.to_string(),
        logical_keystore_name.to_string(),
    );

    ec
}

/// Inverse of [`encryption_context_from_item`], mirroring the Dafny
/// `ToAttributeMap`: the stored attributes are the encryption context minus
/// `tablename` (which exists only in the context), and the wrapped branch key
/// becomes the separate `enc` value.
pub fn to_attribute_map(
    encryption_context: &BTreeMap<String, String>,
    encrypted_key: Vec<u8>,
) -> EncryptedRecord {
    let attributes = encryption_context
        .iter()
        .filter(|(k, _)| k.as_str() != ATTR_TABLENAME)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    EncryptedRecord {
        attributes,
        enc: encrypted_key,
    }
}

/// Reconstructs the custom [`EncryptionContext`] portion from an authenticated
/// encryption context by extracting entries prefixed with `aws-crypto-ec:`.
pub fn custom_encryption_context_from_authenticated_encryption_context(
    authenticated_ec: &BTreeMap<String, String>,
) -> Result<EncryptionContext, Error> {
    let mut ec = EncryptionContext::new();

    for (key, value) in authenticated_ec {
        if let Some(stripped) = key.strip_prefix(CUSTOM_EC_PREFIX) {
            ec.insert(stripped, value.as_str());
        }
    }

    Ok(ec)
}

/// Reconstructs [`BranchKeyMaterials`] from an authenticated encryption context
/// plus decrypted plaintext branch key bytes.
pub fn branch_key_materials_from_authenticated_encryption_context(
    authenticated_ec: &BTreeMap<String, String>,
    plaintext_branch_key: Vec<u8>,
) -> Result<BranchKeyMaterials, Error> {
    let type_attr = authenticated_ec.get(ATTR_TYPE).ok_or_else(|| {
        malformed(
            authenticated_ec,
            "missing 'type' attribute in authenticated encryption context",
        )
    })?;

    if type_attr != TYPE_BRANCH_ACTIVE && !type_attr.starts_with(TYPE_BRANCH_VERSION_PREFIX) {
        return Err(malformed(
            authenticated_ec,
            format!(
                "invalid type attribute: '{}', must be '{}' or start with '{}'",
                type_attr, TYPE_BRANCH_ACTIVE, TYPE_BRANCH_VERSION_PREFIX
            ),
        ));
    }

    // Resolve version string based on type attribute value.
    let version_string = if type_attr == TYPE_BRANCH_ACTIVE {
        authenticated_ec
            .get(ATTR_VERSION)
            .ok_or_else(|| {
                malformed(
                    authenticated_ec,
                    "type is 'branch:ACTIVE' but 'version' attribute is missing",
                )
            })?
            .clone()
    } else {
        type_attr.clone()
    };

    // The version string MUST be "branch:version:" followed by a non-empty
    // version. The Dafny reference uses a strict prefix (`prefix < value`), so
    // the bare prefix with no version is rejected rather than yielding an empty
    // branch key version.
    let branch_key_version = version_string
        .strip_prefix(TYPE_BRANCH_VERSION_PREFIX)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            malformed(
                authenticated_ec,
                format!(
                    "version string '{version_string}' MUST be '{TYPE_BRANCH_VERSION_PREFIX}' \
                     followed by a non-empty version"
                ),
            )
        })?
        .to_string();

    let branch_key_id = authenticated_ec
        .get(ATTR_BRANCH_KEY_ID)
        .ok_or_else(|| {
            malformed(
                authenticated_ec,
                "missing 'branch-key-id' attribute in authenticated encryption context",
            )
        })?
        .clone();

    let encryption_context =
        custom_encryption_context_from_authenticated_encryption_context(authenticated_ec)?;

    let branch_key: [u8; 32] = plaintext_branch_key.try_into().map_err(|v: Vec<u8>| {
        malformed(
            authenticated_ec,
            format!("branch key must be 32 bytes, got {}", v.len()),
        )
    })?;

    BranchKeyMaterials::new(
        branch_key,
        branch_key_id,
        branch_key_version,
        encryption_context,
    )
    .map_err(|e| {
        malformed(authenticated_ec, "failed to construct branch key materials").with_source(e)
    })
}

/// An `InvalidMaterials` error for a malformed branch key record.
/// It names the branch key and its version when the record has them.
fn malformed(authenticated_ec: &BTreeMap<String, String>, message: impl Into<String>) -> Error {
    let version = authenticated_ec
        .get(ATTR_TYPE)
        .filter(|t| *t != TYPE_BRANCH_ACTIVE)
        .or_else(|| authenticated_ec.get(ATTR_VERSION))
        .and_then(|v| v.strip_prefix(TYPE_BRANCH_VERSION_PREFIX))
        .filter(|v| !v.is_empty());
    Error::new(Kind::InvalidMaterials, message).about(
        Some(Service::DynamoDb),
        authenticated_ec.get(ATTR_BRANCH_KEY_ID).map(|id| {
            let branch_key = BranchKey::new(id.clone());
            Resource::BranchKey(match version {
                Some(version) => branch_key.with_version(version),
                None => branch_key,
            })
        }),
    )
}
