// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `key_store::record` module.

use std::collections::BTreeMap;

use aws_crypto_mpl::error::{BranchKey, Resource, Service};

use aws_crypto_mpl::key_store::attributes::{
    ATTR_BRANCH_KEY_ID, ATTR_CREATE_TIME, ATTR_ENC, ATTR_HIERARCHY_VERSION, ATTR_KMS_ARN,
    ATTR_TABLENAME, ATTR_TYPE, ATTR_VERSION, CUSTOM_EC_PREFIX, TYPE_BRANCH_ACTIVE,
    TYPE_BRANCH_VERSION_PREFIX,
};
use aws_crypto_mpl::key_store::record::{
    EncryptedRecord, branch_key_materials_from_authenticated_encryption_context,
    custom_encryption_context_from_authenticated_encryption_context, encryption_context_from_item,
    to_attribute_map,
};

/// Build a minimal authenticated EC that satisfies all record-format required fields.
fn make_authenticated_ec(
    type_val: &str,
    branch_key_id: &str,
    version: Option<&str>,
) -> BTreeMap<String, String> {
    let mut ec = BTreeMap::new();
    ec.insert(ATTR_BRANCH_KEY_ID.to_string(), branch_key_id.to_string());
    ec.insert(ATTR_TYPE.to_string(), type_val.to_string());
    ec.insert(
        ATTR_KMS_ARN.to_string(),
        "arn:aws:kms:us-east-1:123456789012:key/test-key-id".to_string(),
    );
    ec.insert(
        ATTR_CREATE_TIME.to_string(),
        "2024-01-01T00:00:00.000000Z".to_string(),
    );
    ec.insert(ATTR_HIERARCHY_VERSION.to_string(), "1".to_string());
    if let Some(v) = version {
        ec.insert(ATTR_VERSION.to_string(), v.to_string());
    }
    ec
}

/// A valid 32-byte branch key for testing.
fn test_branch_key() -> Vec<u8> {
    vec![0x42; 32]
}

/// A valid UUID v4 for use as a branch key version.
const TEST_VERSION_UUID: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

#[test]
fn record_format_struct_has_all_required_fields() {
    let mut attributes = BTreeMap::new();
    attributes.insert(ATTR_BRANCH_KEY_ID.to_string(), "test-id".to_string());
    attributes.insert(ATTR_TYPE.to_string(), TYPE_BRANCH_ACTIVE.to_string());
    attributes.insert(
        ATTR_VERSION.to_string(),
        format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID),
    );
    attributes.insert(
        ATTR_KMS_ARN.to_string(),
        "arn:aws:kms:us-east-1:123456789012:key/k".to_string(),
    );
    attributes.insert(
        ATTR_CREATE_TIME.to_string(),
        "2024-01-01T00:00:00.000000Z".to_string(),
    );
    attributes.insert(ATTR_HIERARCHY_VERSION.to_string(), "1".to_string());

    let record = EncryptedRecord {
        attributes,
        enc: vec![0xAA; 64],
    };

    assert_eq!(
        record.attributes.get(ATTR_BRANCH_KEY_ID).unwrap(),
        "test-id"
    );
    assert_eq!(
        record.attributes.get(ATTR_TYPE).unwrap(),
        TYPE_BRANCH_ACTIVE
    );
    assert!(!record.enc.is_empty());
}

#[test]
fn record_format_optional_custom_ec_round_trips() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let mut ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    ec.insert(
        format!("{}tenant", CUSTOM_EC_PREFIX),
        "acme-corp".to_string(),
    );
    ec.insert(
        format!("{}department", CUSTOM_EC_PREFIX),
        "finance".to_string(),
    );

    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key()).unwrap();
    assert_eq!(result.encryption_context().len(), 2);
    assert_eq!(
        result.encryption_context().get("tenant").unwrap(),
        "acme-corp"
    );
    assert_eq!(
        result.encryption_context().get("department").unwrap(),
        "finance"
    );
}

#[test]
fn materials_reconstruction_rejects_invalid_type_value() {
    let ec = make_authenticated_ec("invalid:type", "test-id", None);
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key())
        .expect_err("should reject invalid type");
    assert_malformed(&err);
}

#[test]
fn materials_reconstruction_rejects_beacon_type() {
    let ec = make_authenticated_ec("beacon:ACTIVE", "test-id", None);
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key())
        .expect_err("beacon:ACTIVE is not valid for branch key materials");
    assert_malformed(&err);
}

#[test]
fn materials_reconstruction_branch_active_uses_version_attribute() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key()).unwrap();
    assert_eq!(result.branch_key_version(), TEST_VERSION_UUID);
}

#[test]
fn materials_reconstruction_branch_active_rejects_missing_version() {
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", None);
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key())
        .expect_err("should reject missing version");
    assert_malformed(&err);
}

#[test]
fn materials_reconstruction_branch_version_uses_type_value() {
    let type_val = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let ec = make_authenticated_ec(&type_val, "test-id", None);
    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key()).unwrap();
    assert_eq!(result.branch_key_version(), TEST_VERSION_UUID);
}

#[test]
fn materials_branch_key_matches_input_plaintext() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    let key_bytes = vec![0x99; 32];
    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, key_bytes.clone()).unwrap();
    assert_eq!(result.branch_key(), &[0x99; 32]);
}

#[test]
fn materials_branch_key_rejects_wrong_length() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, vec![0x01; 16])
        .expect_err("should reject non-32-byte key");
    assert_malformed(&err);
}

#[test]
fn materials_branch_key_id_matches_record() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "my-branch-key-123", Some(&version_str));
    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key()).unwrap();
    assert_eq!(result.branch_key_id(), "my-branch-key-123");
}

#[test]
fn materials_version_string_starts_with_branch_version_prefix() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key()).unwrap();
    // The version string used internally starts with the prefix; the extracted version is the UUID part.
    assert_eq!(result.branch_key_version(), TEST_VERSION_UUID);
}

#[test]
fn materials_version_rejects_invalid_prefix() {
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some("invalid:prefix:uuid"));
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key())
        .expect_err("should reject invalid version prefix");
    assert_malformed(&err);
}

#[test]
fn materials_version_bytes_are_utf8_of_remainder() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key()).unwrap();
    // The remaining string after prefix is the UUID, which when UTF-8 encoded equals the version.
    assert_eq!(
        result.branch_key_version().as_bytes(),
        TEST_VERSION_UUID.as_bytes()
    );
}

#[test]
fn materials_encryption_context_constructed_by_custom_ec() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let mut ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    ec.insert(format!("{}org", CUSTOM_EC_PREFIX), "amazon".to_string());

    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key()).unwrap();
    assert_eq!(result.encryption_context().len(), 1);
    assert_eq!(result.encryption_context().get("org").unwrap(), "amazon");
}

#[test]
fn materials_encryption_context_excludes_non_custom_attributes() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    // No custom EC entries — only system attributes.
    let result =
        branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key()).unwrap();
    assert!(result.encryption_context().is_empty());
}

#[test]
fn custom_ec_extraction_strips_prefix() {
    let mut auth_ec = BTreeMap::new();
    auth_ec.insert(format!("{}mykey", CUSTOM_EC_PREFIX), "myval".to_string());
    auth_ec.insert("branch-key-id".to_string(), "id".to_string());

    let result = custom_encryption_context_from_authenticated_encryption_context(&auth_ec).unwrap();
    assert!(result.contains_key("mykey"));
    assert!(!result.contains_key(&format!("{}mykey", CUSTOM_EC_PREFIX)));
}

#[test]
fn custom_ec_extraction_preserves_values() {
    let mut auth_ec = BTreeMap::new();
    auth_ec.insert(format!("{}color", CUSTOM_EC_PREFIX), "blue".to_string());
    auth_ec.insert(format!("{}size", CUSTOM_EC_PREFIX), "large".to_string());

    let result = custom_encryption_context_from_authenticated_encryption_context(&auth_ec).unwrap();
    assert_eq!(result.get("color").unwrap(), "blue");
    assert_eq!(result.get("size").unwrap(), "large");
}

#[test]
fn custom_ec_extraction_ignores_non_prefixed_keys() {
    let mut auth_ec = BTreeMap::new();
    auth_ec.insert("branch-key-id".to_string(), "id".to_string());
    auth_ec.insert("type".to_string(), "branch:ACTIVE".to_string());
    auth_ec.insert("kms-arn".to_string(), "arn:...".to_string());
    auth_ec.insert(format!("{}included", CUSTOM_EC_PREFIX), "yes".to_string());

    let result = custom_encryption_context_from_authenticated_encryption_context(&auth_ec).unwrap();
    assert_eq!(result.len(), 1);
    assert!(result.contains_key("included"));
}

#[test]
fn materials_reconstruction_rejects_bare_version_prefix_type() {
    // `type` is exactly "branch:version:" with no version following it.
    let ec = make_authenticated_ec(TYPE_BRANCH_VERSION_PREFIX, "test-id", None);
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key())
        .expect_err("bare 'branch:version:' with no version must be rejected");
    assert_malformed(&err);
}

#[test]
fn materials_reconstruction_rejects_active_with_bare_version_attribute() {
    let ec = make_authenticated_ec(
        TYPE_BRANCH_ACTIVE,
        "test-id",
        Some(TYPE_BRANCH_VERSION_PREFIX),
    );
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key())
        .expect_err("ACTIVE with bare 'branch:version:' version must be rejected");
    assert_malformed(&err);
}

// to_attribute_map and encryption_context_from_item are inverses: projecting a
// constructed encryption context to a stored item and back reproduces the
// context exactly (the property the Dafny reference proves via
// `ToBranchKeyContext(ToAttributeMap(ec), ec[tablename]) == ec`).
#[test]
fn item_encryption_context_round_trips() {
    let version_str = format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID);
    let mut ec = make_authenticated_ec(TYPE_BRANCH_ACTIVE, "test-id", Some(&version_str));
    ec.insert(ATTR_TABLENAME.to_string(), "logical-name".to_string());
    ec.insert(format!("{}dept", CUSTOM_EC_PREFIX), "eng".to_string());

    let logical = ec[ATTR_TABLENAME].clone();
    let record = to_attribute_map(&ec, vec![0xAB; 48]);
    let recovered = encryption_context_from_item(&record, &logical);

    assert_eq!(recovered, ec);
    // `enc` is carried separately, never in the stored string attributes.
    assert!(!record.attributes.contains_key(ATTR_ENC));
    assert_eq!(record.enc, vec![0xAB; 48]);
    // `tablename` exists only in the context, not among the stored attributes.
    assert!(!record.attributes.contains_key(ATTR_TABLENAME));
}

#[test]
fn encryption_context_from_item_adds_tablename_and_ignores_enc_attribute() {
    let mut attributes = BTreeMap::new();
    attributes.insert(ATTR_BRANCH_KEY_ID.to_string(), "id".to_string());
    attributes.insert(ATTR_TYPE.to_string(), TYPE_BRANCH_ACTIVE.to_string());
    // A stray `enc` among the string attributes must not leak into the context.
    attributes.insert(ATTR_ENC.to_string(), "should-be-dropped".to_string());

    let record = EncryptedRecord {
        attributes,
        enc: vec![0x01; 32],
    };
    let ec = encryption_context_from_item(&record, "logical-name");

    assert_eq!(ec[ATTR_TABLENAME], "logical-name");
    assert!(!ec.contains_key(ATTR_ENC));
}

// Attributes the SDK did not write are authenticated verbatim, and custom
// encryption context entries already stored with the prefix are not prefixed
// a second time.
#[test]
fn additional_item_attributes_are_carried_verbatim() {
    let mut attributes = BTreeMap::new();
    attributes.insert(ATTR_BRANCH_KEY_ID.to_string(), "id".to_string());
    attributes.insert(ATTR_TYPE.to_string(), TYPE_BRANCH_ACTIVE.to_string());
    attributes.insert("custom-column".to_string(), "value".to_string());
    attributes.insert(format!("{}dept", CUSTOM_EC_PREFIX), "eng".to_string());

    let record = EncryptedRecord {
        attributes,
        enc: Vec::new(),
    };
    let ec = encryption_context_from_item(&record, "logical-name");

    assert_eq!(ec["custom-column"], "value");
    assert_eq!(ec[&format!("{}dept", CUSTOM_EC_PREFIX)], "eng");
    assert!(!ec.contains_key(&format!("{0}{0}dept", CUSTOM_EC_PREFIX)));
}

/// A malformed record is `InvalidMaterials` about the branch key, from DynamoDB.
#[track_caller]
fn assert_malformed(err: &aws_crypto_mpl::Error) {
    let aws_crypto_mpl::Error::InvalidMaterials(e) = err else {
        panic!("expected InvalidMaterials, got {err:?}");
    };
    assert_eq!(e.service(), Some(Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BranchKey::new("test-id")))
    );
    assert_eq!(e.code(), None);
}
