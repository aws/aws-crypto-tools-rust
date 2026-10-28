// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `describe_encrypted_data_keys` and `describe_header_encrypted_data_keys`, on headers built
//! byte by byte.

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::{
    EncryptedDataKeyDescription, Error, describe_encrypted_data_keys,
    describe_header_encrypted_data_keys,
};

/// The Dafny `testAwsKmsHDataKey` ciphertext; it holds branch key version
/// `155b7a3d-7625-4826-4302-113d1179075a`.
const HIERARCHY_CIPHERTEXT: [u8; 140] = [
    64, 92, 115, 7, 85, 121, 112, 79, 69, 12, 82, 25, 67, 34, 11, 66, 93, 45, 40, 23, 90, 61, 16,
    28, 59, 114, 52, 122, 50, 23, 11, 101, 48, 53, 30, 120, 51, 74, 77, 53, 57, 99, 53, 13, 30, 21,
    109, 85, 15, 86, 47, 84, 91, 85, 87, 60, 4, 56, 67, 74, 29, 87, 85, 106, 8, 82, 63, 114, 100,
    110, 68, 58, 83, 24, 111, 41, 21, 91, 122, 61, 118, 37, 72, 38, 67, 2, 17, 61, 17, 121, 7, 90,
    117, 49, 30, 20, 89, 68, 33, 111, 107, 5, 120, 20, 95, 78, 70, 2, 49, 84, 39, 50, 40, 40, 115,
    114, 76, 18, 103, 84, 34, 123, 1, 125, 61, 33, 13, 18, 81, 24, 53, 53, 26, 60, 52, 85, 81, 96,
    85, 72,
];
const HIERARCHY_VERSION: &str = "155b7a3d-7625-4826-4302-113d1179075a";

const HIERARCHY_EDK: (&str, &[u8], &[u8]) = (
    "aws-kms-hierarchy",
    b"keyproviderInfo",
    &HIERARCHY_CIPHERTEXT,
);
const KMS_EDK: (&str, &[u8], &[u8]) = ("aws-kms", b"keyproviderInfo", &[1, 2, 3, 4, 5]);
const RAW_RSA_EDK: (&str, &[u8], &[u8]) = ("raw-rsa", &[1, 2, 3, 4, 5], &[6, 7, 8, 9]);

fn push_u16_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("test field fits a u16 length prefix");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A version-1 header; see [`versioned_header`].
fn header(flavor: u8, edks: &[(&str, &[u8], &[u8])]) -> Vec<u8> {
    versioned_header(1, flavor, edks)
}

/// A header with `version`, `flavor` and `edks` (provider id, provider info, ciphertext), a
/// two-attribute legend, the encryption context `{abc: def}`, and an arbitrary commitment.
fn versioned_header(version: u8, flavor: u8, edks: &[(&str, &[u8], &[u8])]) -> Vec<u8> {
    let mut out = vec![version, flavor];
    out.extend_from_slice(&[7; 32]);
    push_u16_prefixed(&mut out, b"es");
    out.extend_from_slice(&1u16.to_be_bytes());
    push_u16_prefixed(&mut out, b"abc");
    push_u16_prefixed(&mut out, b"def");
    out.push(u8::try_from(edks.len()).expect("test header has fewer than 256 EDKs"));
    for (id, info, ciphertext) in edks {
        push_u16_prefixed(&mut out, id.as_bytes());
        push_u16_prefixed(&mut out, info);
        push_u16_prefixed(&mut out, ciphertext);
    }
    // Describe never checks the commitment.
    out.extend_from_slice(&[9; 32]);
    out
}

fn item_with(header: Vec<u8>) -> HashMap<String, AttributeValue> {
    HashMap::from([(
        "aws_dbe_head".to_owned(),
        AttributeValue::B(Blob::new(header)),
    )])
}

fn serialization_message(result: Result<Vec<EncryptedDataKeyDescription>, Error>) -> String {
    match result {
        Err(Error::Serialization(e)) => e.message().to_owned(),
        other => panic!("expected a Serialization error, got {other:?}"),
    }
}

#[test]
fn accepts_a_binary_header_or_an_encrypted_item() {
    let bytes = header(1, &[KMS_EDK, HIERARCHY_EDK]);
    let from_header = describe_header_encrypted_data_keys(&bytes).unwrap();
    let from_item = describe_encrypted_data_keys(&item_with(bytes)).unwrap();

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#input
    //= type=test
    //= reason=a binary header and an item holding it are both accepted and give the same descriptions
    //# This operation MUST take in either of the following:
    assert_eq!(from_header, from_item);
    assert_eq!(from_header.len(), 2);
    // A version-2 header is described the same way.
    let v2 = versioned_header(2, 1, &[KMS_EDK, HIERARCHY_EDK]);
    assert_eq!(
        describe_header_encrypted_data_keys(&v2).unwrap(),
        from_header
    );
}

#[test]
fn output_has_provider_id_info_branch_key_id_and_version() {
    let descriptions = describe_header_encrypted_data_keys(&header(1, &[HIERARCHY_EDK])).unwrap();
    let [d] = descriptions.as_slice() else {
        panic!("expected one description, got {descriptions:?}");
    };

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#output
    //= type=test
    //# This operation MUST return the following:
    assert_eq!(d.key_provider_id(), "aws-kms-hierarchy");
    assert_eq!(d.key_provider_info(), Some("keyproviderInfo"));
    assert_eq!(d.branch_key_id(), Some("keyproviderInfo"));
    assert_eq!(d.branch_key_version(), Some(HIERARCHY_VERSION));
}

#[test]
fn item_header_is_read_only_from_binary_aws_dbe_head() {
    let bytes = header(1, &[KMS_EDK, RAW_RSA_EDK]);
    let mut item = item_with(bytes.clone());
    item.insert(
        "partition_key".to_owned(),
        AttributeValue::S("id-1".to_owned()),
    );
    // A binary attribute with another name must not be taken for the header.
    item.insert(
        "aws_dbe_foot".to_owned(),
        AttributeValue::B(Blob::new(header(1, &[HIERARCHY_EDK]))),
    );

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //= type=test
    //# - If the input is an encrypted DynamoDB item, it MUST attempt to extract "aws_dbe_head" attribute from the DynamoDB item to get the binary header.
    assert_eq!(
        describe_encrypted_data_keys(&item).unwrap(),
        describe_header_encrypted_data_keys(&bytes).unwrap()
    );

    // An item with no binary aws_dbe_head is rejected.
    let missing = HashMap::from([(
        "partition_key".to_owned(),
        AttributeValue::S("id".to_owned()),
    )]);
    let wrong_name = HashMap::from([(
        "wrong_header_attribute".to_owned(),
        AttributeValue::B(Blob::new(bytes)),
    )]);
    let not_binary =
        HashMap::from([("aws_dbe_head".to_owned(), AttributeValue::S("x".to_owned()))]);
    for item in [missing, wrong_name, not_binary] {
        match describe_encrypted_data_keys(&item) {
            Err(Error::Validation(e)) => {
                assert_eq!(e.message(), "the item has no binary aws_dbe_head attribute");
            }
            other => panic!("expected a Validation error, got {other:?}"),
        }
    }
}

#[test]
fn malformed_header_fails_to_deserialize() {
    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //= type=test
    //# - This operation MUST deserialize the header bytes according to the header format.
    assert_eq!(
        serialization_message(describe_header_encrypted_data_keys(&[1, 1])),
        "the item's header (aws_dbe_head) is too short"
    );
    let good = header(1, &[KMS_EDK]);
    let no_commitment = &good[..good.len() - 32];
    assert_eq!(
        serialization_message(describe_header_encrypted_data_keys(no_commitment)),
        "the item's header (aws_dbe_head) ends early"
    );
    let mut extra = good.clone();
    extra.push(0);
    assert_eq!(
        serialization_message(describe_header_encrypted_data_keys(&extra)),
        "the item's header (aws_dbe_head) has extra bytes at the end"
    );
    assert_eq!(describe_header_encrypted_data_keys(&good).unwrap().len(), 1);
}

#[test]
fn hierarchy_version_is_found_for_both_format_flavors() {
    for flavor in [0, 1] {
        let descriptions =
            describe_header_encrypted_data_keys(&header(flavor, &[HIERARCHY_EDK])).unwrap();

        //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
        //= type=test
        //= reason=flavors 0 and 1 both yield the version; both suites place it at offset 76, so they are not told apart
        //# - This operation MUST extract the Format Flavor from the deserialize header.
        assert_eq!(
            descriptions[0].branch_key_version(),
            Some(HIERARCHY_VERSION),
            "flavor {flavor}"
        );
    }
}

#[test]
fn every_data_key_in_the_header_is_described() {
    let descriptions =
        describe_header_encrypted_data_keys(&header(1, &[KMS_EDK, RAW_RSA_EDK, HIERARCHY_EDK]))
            .unwrap();

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //= type=test
    //# - This operation MUST extract the dataKeys from the deserialize header.
    assert_eq!(descriptions.len(), 3);

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //= type=test
    //# - For every Data Key in Data Keys, the operation MUST attempt to extract a description of the Data Key.
    assert_eq!(descriptions[0].key_provider_id(), "aws-kms");
    assert_eq!(descriptions[0].key_provider_info(), Some("keyproviderInfo"));
    assert_eq!(descriptions[0].branch_key_version(), None);
    assert_eq!(descriptions[1].key_provider_id(), "raw-rsa");
    assert_eq!(descriptions[1].key_provider_info(), None);
    assert_eq!(descriptions[1].branch_key_id(), None);
    assert_eq!(descriptions[1].branch_key_version(), None);
    assert_eq!(descriptions[2].key_provider_id(), "aws-kms-hierarchy");
    assert_eq!(
        descriptions[2].branch_key_version(),
        Some(HIERARCHY_VERSION)
    );
}

#[test]
fn hierarchy_branch_key_version_is_parsed_from_ciphertext() {
    let descriptions = describe_header_encrypted_data_keys(&header(1, &[HIERARCHY_EDK])).unwrap();

    //= spec/dynamodb-encryption-client/ddb-get-encrypted-data-key-description.md#behavior
    //= type=test
    //# - This description SHOULD be as detailed as possible, parsing but NOT decrypting the cipher-text field of the Data Key for embedded fields such as the Hierarchical Keyring’s branchKeyVersion.
    assert_eq!(
        descriptions[0].branch_key_version(),
        Some(HIERARCHY_VERSION)
    );

    // The version is bytes 76..92 of the ciphertext: after the 48-byte wrapped data key, the
    // 16-byte salt, and the 12-byte IV.
    let mut ciphertext = [0u8; 48 + 44];
    ciphertext[76..92].copy_from_slice(&[0xab; 16]);
    let edk = ("aws-kms-hierarchy", b"id".as_slice(), ciphertext.as_slice());
    let descriptions = describe_header_encrypted_data_keys(&header(1, &[edk])).unwrap();
    assert_eq!(
        descriptions[0].branch_key_version(),
        Some("abababab-abab-abab-abab-abababababab")
    );

    // A ciphertext too short for the wrapped data key, or for the version, is a
    // Serialization error rather than a panic or a garbage version.
    for len in [40, 48 + 28 + 8] {
        let ciphertext = vec![0u8; len];
        let edk = ("aws-kms-hierarchy", b"id".as_slice(), ciphertext.as_slice());
        assert_eq!(
            serialization_message(describe_header_encrypted_data_keys(&header(1, &[edk]))),
            "a hierarchical keyring's encrypted data key is too short",
            "ciphertext length {len}"
        );
    }
}
