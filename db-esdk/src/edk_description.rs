// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Describe the encrypted data keys in an item's header, without decrypting it.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::BuildHasher;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;
use aws_crypto_mpl::types::{AlgorithmSuiteId as MplAlgorithmSuiteId, EdkWrapping};

use crate::error::{Error, ser_err, val_err};
use crate::structured::util::HEADER_FIELD;
use crate::structured::{DBE_ALGORITHM_FAMILY, PartialHeader};

/// The hierarchical keyring's key provider id.
const HIERARCHY_PROVIDER_ID: &str = "aws-kms-hierarchy";
/// Every AWS KMS keyring's key provider id starts with this.
const AWS_KMS_PROVIDER_PREFIX: &str = "aws-kms";
// The material that the branch key wraps in a hierarchical EDK: a salt, an IV, then the branch key version.
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

    /// The key provider info of an AWS KMS keyring's data key:
    /// the KMS key ARN, or the branch key id for a hierarchical keyring.
    /// `None` for every other keyring.
    #[must_use]
    pub fn key_provider_info(&self) -> Option<&str> {
        self.key_provider_info.as_deref()
    }

    /// The branch key id.
    /// For every AWS KMS keyring, it equals [`key_provider_info`](Self::key_provider_info).
    /// `None` for every other keyring.
    #[must_use]
    pub fn branch_key_id(&self) -> Option<&str> {
        self.branch_key_id.as_deref()
    }

    /// The branch key version, as a UUID.
    /// Set only for a hierarchical keyring.
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
/// - [`Validation`](Error::Validation): the item has no binary `aws_dbe_head` attribute.
/// - [`Serialization`](Error::Serialization): the header is malformed.
pub fn describe_encrypted_data_keys<S: BuildHasher>(
    item: &HashMap<String, AttributeValue, S>,
) -> Result<Vec<EncryptedDataKeyDescription>, Error> {
    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //# - If the input is an encrypted DynamoDB item, it MUST attempt to extract "aws_dbe_head" attribute from the DynamoDB item to get the binary header.
    match item.get(HEADER_FIELD) {
        //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#input
        //# This operation MUST take in either of the following:
        Some(AttributeValue::B(header)) => describe_header_encrypted_data_keys(header.as_ref()),
        _ => Err(val_err("the item has no binary aws_dbe_head attribute")),
    }
}

/// Describe each encrypted data key of a serialized header (an item's `aws_dbe_head` value),
/// in header order.
///
/// # Errors
///
/// - [`Serialization`](Error::Serialization): the header is malformed.
//= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
//= type=implication
//= reason=takes no keyring, CMM, or materials, so it cannot decrypt a data key
//# - The operation MUST NEVER DECRYPT the Data Keys.
//
//= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
//= type=implication
//= reason=a sync fn taking only bytes; no client, keyring, or I/O handle
//# - The operation MUST NOT access the network in any way.
pub fn describe_header_encrypted_data_keys(
    header: &[u8],
) -> Result<Vec<EncryptedDataKeyDescription>, Error> {
    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //# - This operation MUST deserialize the header bytes according to the header format.
    let header = PartialHeader::deserialize(header)?;

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //# - This operation MUST extract the dataKeys from the deserialize header.
    let data_keys = &header.data_keys;

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //# - For every Data Key in Data Keys, the operation MUST attempt to extract a description of the Data Key.
    data_keys
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
                .map_err(|_| ser_err("an encrypted data key's key provider info is not UTF-8"))?
                .to_owned();
            let branch_key_version = if key_provider_id == HIERARCHY_PROVIDER_ID {
                //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
                //# - This operation MUST extract the Format Flavor from the deserialize header.
                Some(branch_key_version(edk.ciphertext(), header.flavor)?)
            } else {
                None
            };

            //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#output
            //# This operation MUST return the following:
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
        .ok_or_else(|| {
            ser_err("the item's header (aws_dbe_head) names an unknown algorithm suite")
        })?
        .specification();
    // With intermediate key wrapping, the ciphertext starts with the encrypted data key.
    // The material that the branch key wrapped follows it.
    let provider_wrapped = match suite.edk_wrapping() {
        EdkWrapping::IntermediateKeyWrapping(_) => ciphertext
            .get(suite.encryption_key_length() + suite.authentication_tag_length()..)
            .ok_or_else(|| ser_err("a hierarchical keyring's encrypted data key is too short"))?,
        _ => ciphertext,
    };
    let start = SALT_LENGTH + IV_LENGTH;

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //# - This description SHOULD be as detailed as possible, parsing but NOT decrypting the cipher-text field of the Data Key for embedded fields such as the Hierarchical Keyring’s branchKeyVersion.
    let version: &[u8; VERSION_LENGTH] = provider_wrapped
        .get(start..start + VERSION_LENGTH)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ser_err("a hierarchical keyring's encrypted data key is too short"))?;
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

#[cfg(test)]
mod tests {
    //! Ported from `DynamoDbGetEncryptedDataKeyDescriptionTest.dfy`.

    use super::*;
    use aws_crypto_mpl::aws_sdk_dynamodb::primitives::Blob;
    use aws_crypto_mpl::types::{EncryptedDataKey, EncryptionContext};

    const MSG_ID: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    /// The Dafny `testAwsKmsHDataKey` ciphertext.
    const HIERARCHY_CIPHERTEXT: [u8; 140] = [
        64, 92, 115, 7, 85, 121, 112, 79, 69, 12, 82, 25, 67, 34, 11, 66, 93, 45, 40, 23, 90, 61,
        16, 28, 59, 114, 52, 122, 50, 23, 11, 101, 48, 53, 30, 120, 51, 74, 77, 53, 57, 99, 53, 13,
        30, 21, 109, 85, 15, 86, 47, 84, 91, 85, 87, 60, 4, 56, 67, 74, 29, 87, 85, 106, 8, 82, 63,
        114, 100, 110, 68, 58, 83, 24, 111, 41, 21, 91, 122, 61, 118, 37, 72, 38, 67, 2, 17, 61,
        17, 121, 7, 90, 117, 49, 30, 20, 89, 68, 33, 111, 107, 5, 120, 20, 95, 78, 70, 2, 49, 84,
        39, 50, 40, 40, 115, 114, 76, 18, 103, 84, 34, 123, 1, 125, 61, 33, 13, 18, 81, 24, 53, 53,
        26, 60, 52, 85, 81, 96, 85, 72,
    ];

    fn edk(id: &str, info: &[u8], ciphertext: &[u8]) -> EncryptedDataKey {
        EncryptedDataKey::builder()
            .key_provider_id(id)
            .key_provider_info(info)
            .ciphertext(ciphertext)
            .build()
            .unwrap()
    }

    fn aws_kms() -> EncryptedDataKey {
        edk("aws-kms", b"keyproviderInfo", &[1, 2, 3, 4, 5])
    }

    fn aws_kms_hierarchy() -> EncryptedDataKey {
        edk(
            "aws-kms-hierarchy",
            b"keyproviderInfo",
            &HIERARCHY_CIPHERTEXT,
        )
    }

    fn raw_rsa() -> EncryptedDataKey {
        edk("raw-rsa", &[1, 2, 3, 4, 5], &[6, 7, 8, 9])
    }

    fn aws_kms_rsa() -> EncryptedDataKey {
        edk("aws-kms-rsa", b"keyproviderInfo", &[1, 2, 3, 4, 5])
    }

    /// The Dafny test's `CreatePartialHeader(...).serialize() + msgID`.
    /// The message id stands in for the commitment.
    fn header(flavor: u8, data_keys: Vec<EncryptedDataKey>) -> Vec<u8> {
        let header = PartialHeader {
            version: 1,
            flavor,
            msg_id: MSG_ID,
            legend: vec![0x65, 0x73],
            enc_context: EncryptionContext::from([("abc", "def")]),
            data_keys,
        };
        let mut bytes = header.serialize();
        bytes.extend_from_slice(&MSG_ID);
        bytes
    }

    fn item(header: Vec<u8>) -> HashMap<String, AttributeValue> {
        HashMap::from([(
            HEADER_FIELD.to_owned(),
            AttributeValue::B(Blob::new(header)),
        )])
    }

    fn kms_description(id: &str) -> EncryptedDataKeyDescription {
        EncryptedDataKeyDescription {
            key_provider_id: id.to_owned(),
            key_provider_info: Some("keyproviderInfo".to_owned()),
            branch_key_id: Some("keyproviderInfo".to_owned()),
            branch_key_version: None,
        }
    }

    fn hierarchy_description() -> EncryptedDataKeyDescription {
        EncryptedDataKeyDescription {
            branch_key_version: Some("155b7a3d-7625-4826-4302-113d1179075a".to_owned()),
            ..kms_description("aws-kms-hierarchy")
        }
    }

    fn raw_rsa_description() -> EncryptedDataKeyDescription {
        EncryptedDataKeyDescription {
            key_provider_id: "raw-rsa".to_owned(),
            key_provider_info: None,
            branch_key_id: None,
            branch_key_version: None,
        }
    }

    /// Both entry points give `expected` for a header with `data_keys`.
    fn assert_described(
        flavor: u8,
        data_keys: Vec<EncryptedDataKey>,
        expected: &[EncryptedDataKeyDescription],
    ) {
        let bytes = header(flavor, data_keys);
        assert_eq!(
            describe_header_encrypted_data_keys(&bytes).unwrap(),
            expected
        );
        assert_eq!(
            describe_encrypted_data_keys(&item(bytes)).unwrap(),
            expected
        );
    }

    #[test]
    fn aws_kms_data_key() {
        assert_described(1, vec![aws_kms()], &[kms_description("aws-kms")]);
    }

    #[test]
    fn aws_kms_hierarchy_data_key_has_branch_key_version() {
        // Both DBE suites use intermediate key wrapping, so the version is at the same offset.
        assert_described(1, vec![aws_kms_hierarchy()], &[hierarchy_description()]);
        assert_described(0, vec![aws_kms_hierarchy()], &[hierarchy_description()]);
    }

    #[test]
    fn raw_rsa_data_key_has_only_its_provider_id() {
        assert_described(1, vec![raw_rsa()], &[raw_rsa_description()]);
    }

    #[test]
    fn aws_kms_rsa_data_key() {
        assert_described(1, vec![aws_kms_rsa()], &[kms_description("aws-kms-rsa")]);
    }

    #[test]
    fn every_data_key_is_described_in_order() {
        assert_described(
            1,
            vec![aws_kms(), aws_kms_rsa()],
            &[kms_description("aws-kms"), kms_description("aws-kms-rsa")],
        );
    }

    #[test]
    fn accessors() {
        let d = hierarchy_description();
        assert_eq!(d.key_provider_id(), "aws-kms-hierarchy");
        assert_eq!(d.key_provider_info(), Some("keyproviderInfo"));
        assert_eq!(d.branch_key_id(), Some("keyproviderInfo"));
        assert_eq!(
            d.branch_key_version(),
            Some("155b7a3d-7625-4826-4302-113d1179075a")
        );
        let d = raw_rsa_description();
        assert_eq!(d.key_provider_info(), None);
        assert_eq!(d.branch_key_id(), None);
        assert_eq!(d.branch_key_version(), None);
    }

    #[test]
    fn item_without_binary_header_fails() {
        let bytes = header(1, vec![aws_kms()]);
        let wrong_name = HashMap::from([(
            "wrong_header_attribute".to_owned(),
            AttributeValue::B(Blob::new(bytes)),
        )]);
        let not_binary =
            HashMap::from([(HEADER_FIELD.to_owned(), AttributeValue::S("x".to_owned()))]);
        for item in [wrong_name, not_binary] {
            match describe_encrypted_data_keys(&item) {
                Err(Error::Validation(e)) => {
                    assert_eq!(e.message(), "the item has no binary aws_dbe_head attribute");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    fn serialization_message(result: Result<Vec<EncryptedDataKeyDescription>, Error>) -> String {
        match result {
            Err(Error::Serialization(e)) => e.message().to_owned(),
            other => panic!("expected a Serialization error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_header_fails() {
        assert_eq!(
            serialization_message(describe_header_encrypted_data_keys(&[1, 1])),
            "the item's header (aws_dbe_head) is too short"
        );
    }

    #[test]
    fn invalid_utf8_key_provider_info_fails() {
        let bytes = header(1, vec![edk("aws-kms", &[0xFF], &[1])]);
        assert_eq!(
            serialization_message(describe_header_encrypted_data_keys(&bytes)),
            "an encrypted data key's key provider info is not UTF-8"
        );
    }

    #[test]
    fn short_hierarchy_ciphertext_fails() {
        // Too short for the encrypted data key.
        let bytes = header(1, vec![edk("aws-kms-hierarchy", b"id", &[0; 47])]);
        assert_eq!(
            serialization_message(describe_header_encrypted_data_keys(&bytes)),
            "a hierarchical keyring's encrypted data key is too short"
        );
        // Long enough for the data key, too short for the branch key version.
        let bytes = header(1, vec![edk("aws-kms-hierarchy", b"id", &[0; 48 + 43])]);
        assert_eq!(
            serialization_message(describe_header_encrypted_data_keys(&bytes)),
            "a hierarchical keyring's encrypted data key is too short"
        );
        let bytes = header(1, vec![edk("aws-kms-hierarchy", b"id", &[0; 48 + 44])]);
        assert_eq!(
            describe_header_encrypted_data_keys(&bytes).unwrap()[0].branch_key_version(),
            Some("00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn unknown_flavor_has_no_suite() {
        assert_eq!(
            branch_key_version(&HIERARCHY_CIPHERTEXT, 2)
                .unwrap_err()
                .message(),
            "the item's header (aws_dbe_head) names an unknown algorithm suite"
        );
    }
}
