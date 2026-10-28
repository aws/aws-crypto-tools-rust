// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Describe the encrypted data keys in an item's header, without decrypting it.

use std::collections::HashMap;
use std::fmt::Write as _;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;
use aws_crypto_mpl::types::{AlgorithmSuiteId as MplAlgorithmSuiteId, EdkWrapping};

use crate::error::{Error, ser_err, val_err};
use crate::structured::util::HEADER_FIELD;
use crate::structured::{DBE_ALGORITHM_FAMILY, PartialHeader};

/// The hierarchical keyring's key provider id.
const HIERARCHY_PROVIDER_ID: &str = "aws-kms-hierarchy";
/// Every AWS KMS keyring's key provider id starts with this.
const AWS_KMS_PROVIDER_PREFIX: &str = "aws-kms";
/// A hierarchical EDK's wrapped material: salt, IV, then the branch key version.
const SALT_LENGTH: usize = 16;
const IV_LENGTH: usize = 12;
const VERSION_LENGTH: usize = 16;

/// What one encrypted data key in a header says about the key that protects it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncryptedDataKeyDescription {
    key_provider_id: String,
    key_provider_info: Option<String>,
    branch_key_id: Option<String>,
    branch_key_version: Option<String>,
}

impl EncryptedDataKeyDescription {
    /// The key provider id, such as `aws-kms`, `aws-kms-hierarchy`, or a raw keyring's namespace.
    #[must_use]
    pub fn key_provider_id(&self) -> &str {
        &self.key_provider_id
    }

    /// The key provider info of an AWS KMS key: its key ARN, or a hierarchical keyring's
    /// branch key id. `None` for every other keyring.
    #[must_use]
    pub fn key_provider_info(&self) -> Option<&str> {
        self.key_provider_info.as_deref()
    }

    /// The branch key id. Set for every AWS KMS key, where it equals
    /// [`key_provider_info`](Self::key_provider_info); `None` for every other keyring.
    #[must_use]
    pub fn branch_key_id(&self) -> Option<&str> {
        self.branch_key_id.as_deref()
    }

    /// The branch key version, as a UUID. Set only for a hierarchical keyring.
    #[must_use]
    pub fn branch_key_version(&self) -> Option<&str> {
        self.branch_key_version.as_deref()
    }
}

/// Describe each encrypted data key of an encrypted item, in header order.
///
/// Reads only the item's `aws_dbe_head` attribute: it needs no keyring and makes no AWS call.
///
/// # Errors
///
/// A [`Validation`](Error::Validation) error when the item has no binary `aws_dbe_head`,
/// and a [`Serialization`](Error::Serialization) error when the header is malformed.
pub fn describe_encrypted_data_keys(
    item: &HashMap<String, AttributeValue>,
) -> Result<Vec<EncryptedDataKeyDescription>, Error> {
    match item.get(HEADER_FIELD) {
        Some(AttributeValue::B(header)) => describe_header_encrypted_data_keys(header.as_ref()),
        _ => Err(val_err("Header not found in the DynamoDB item.")),
    }
}

/// Describe each encrypted data key of a serialized header (an item's `aws_dbe_head` value),
/// in header order.
///
/// # Errors
///
/// A [`Serialization`](Error::Serialization) error when the header is malformed.
pub fn describe_header_encrypted_data_keys(
    header: &[u8],
) -> Result<Vec<EncryptedDataKeyDescription>, Error> {
    let header = PartialHeader::deserialize(header)?;
    header
        .data_keys
        .iter()
        .map(|edk| {
            let key_provider_id = edk.key_provider_id().to_owned();
            if !key_provider_id.starts_with(AWS_KMS_PROVIDER_PREFIX) {
                return Ok(EncryptedDataKeyDescription {
                    key_provider_id,
                    key_provider_info: None,
                    branch_key_id: None,
                    branch_key_version: None,
                });
            }
            let info = std::str::from_utf8(edk.key_provider_info())
                .map_err(|_| ser_err("Invalid UTF-8 in key provider info."))?
                .to_owned();
            let branch_key_version = if key_provider_id == HIERARCHY_PROVIDER_ID {
                Some(branch_key_version(edk.ciphertext(), header.flavor)?)
            } else {
                None
            };
            Ok(EncryptedDataKeyDescription {
                key_provider_id,
                key_provider_info: Some(info.clone()),
                branch_key_id: Some(info),
                branch_key_version,
            })
        })
        .collect()
}

/// The branch key version stored in a hierarchical EDK's ciphertext.
fn branch_key_version(ciphertext: &[u8], flavor: u8) -> Result<String, Error> {
    // The header flavor is the second byte of the DBE suite id.
    let suite = MplAlgorithmSuiteId::from_id_bytes([DBE_ALGORITHM_FAMILY, flavor])
        .ok_or_else(|| ser_err("Invalid format flavor."))?
        .specification();
    // With intermediate key wrapping, the encrypted plaintext data key comes first,
    // and the material the branch key wrapped follows it.
    let provider_wrapped = match suite.edk_wrapping() {
        EdkWrapping::IntermediateKeyWrapping(_) => ciphertext
            .get(suite.encryption_key_length() + suite.authentication_tag_length()..)
            .ok_or_else(|| ser_err("Unable to deserialize Intermediate Key Wrapped material."))?,
        _ => ciphertext,
    };
    let start = SALT_LENGTH + IV_LENGTH;
    let version: &[u8; VERSION_LENGTH] = provider_wrapped
        .get(start..start + VERSION_LENGTH)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ser_err("Incorrect ciphertext structure length."))?;
    Ok(uuid_string(version))
}

/// A UUID in its lowercase hyphenated form.
fn uuid_string(bytes: &[u8; VERSION_LENGTH]) -> String {
    let mut out = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        // Writing to a String never fails.
        let _ = write!(out, "{b:02x}");
    }
    out
}
