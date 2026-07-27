// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `keystore::record` module.

use std::collections::BTreeMap;

use aws_crypto_mpl::keystore::error::KeystoreErrorKind;
use aws_crypto_mpl::keystore::record::{
    CUSTOM_EC_PREFIX, EncryptedRecord, FIELD_BRANCH_KEY_ID, FIELD_CREATE_TIME,
    FIELD_HIERARCHY_VERSION, FIELD_KMS_ARN, FIELD_TYPE, FIELD_VERSION, TYPE_BRANCH_ACTIVE,
    TYPE_BRANCH_VERSION_PREFIX, branch_key_materials_from_authenticated_encryption_context,
    custom_encryption_context_from_authenticated_encryption_context,
};

/// Build a minimal authenticated EC that satisfies all record-format required fields.
fn make_authenticated_ec(
    type_val: &str,
    branch_key_id: &str,
    version: Option<&str>,
) -> BTreeMap<String, String> {
    let mut ec = BTreeMap::new();
    ec.insert(FIELD_BRANCH_KEY_ID.to_string(), branch_key_id.to_string());
    ec.insert(FIELD_TYPE.to_string(), type_val.to_string());
    ec.insert(
        FIELD_KMS_ARN.to_string(),
        "arn:aws:kms:us-east-1:123456789012:key/test-key-id".to_string(),
    );
    ec.insert(
        FIELD_CREATE_TIME.to_string(),
        "2024-01-01T00:00:00.000000Z".to_string(),
    );
    ec.insert(FIELD_HIERARCHY_VERSION.to_string(), "1".to_string());
    if let Some(v) = version {
        ec.insert(FIELD_VERSION.to_string(), v.to_string());
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
    attributes.insert(FIELD_BRANCH_KEY_ID.to_string(), "test-id".to_string());
    attributes.insert(FIELD_TYPE.to_string(), TYPE_BRANCH_ACTIVE.to_string());
    attributes.insert(
        FIELD_VERSION.to_string(),
        format!("{}{}", TYPE_BRANCH_VERSION_PREFIX, TEST_VERSION_UUID),
    );
    attributes.insert(
        FIELD_KMS_ARN.to_string(),
        "arn:aws:kms:us-east-1:123456789012:key/k".to_string(),
    );
    attributes.insert(
        FIELD_CREATE_TIME.to_string(),
        "2024-01-01T00:00:00.000000Z".to_string(),
    );
    attributes.insert(FIELD_HIERARCHY_VERSION.to_string(), "1".to_string());

    let record = EncryptedRecord {
        attributes,
        enc: vec![0xAA; 64],
    };

    assert_eq!(
        record.attributes.get(FIELD_BRANCH_KEY_ID).unwrap(),
        "test-id"
    );
    assert_eq!(
        record.attributes.get(FIELD_TYPE).unwrap(),
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
        result.encryption_context().get(b"tenant".as_ref()).unwrap(),
        b"acme-corp"
    );
    assert_eq!(
        result
            .encryption_context()
            .get(b"department".as_ref())
            .unwrap(),
        b"finance"
    );
}

#[test]
fn materials_reconstruction_rejects_invalid_type_value() {
    let ec = make_authenticated_ec("invalid:type", "test-id", None);
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key())
        .expect_err("should reject invalid type");
    assert_eq!(err.kind, KeystoreErrorKind::RecordMalformed);
    assert!(err.message.contains("Invalid type attribute"));
}

#[test]
fn materials_reconstruction_rejects_beacon_type() {
    let ec = make_authenticated_ec("beacon:ACTIVE", "test-id", None);
    let err = branch_key_materials_from_authenticated_encryption_context(&ec, test_branch_key())
        .expect_err("beacon:ACTIVE is not valid for branch key materials");
    assert_eq!(err.kind, KeystoreErrorKind::RecordMalformed);
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
    assert_eq!(err.kind, KeystoreErrorKind::RecordMalformed);
    assert!(err.message.contains("version"));
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
    assert_eq!(err.kind, KeystoreErrorKind::RecordMalformed);
    assert!(err.message.contains("32 bytes"));
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
    assert_eq!(err.kind, KeystoreErrorKind::RecordMalformed);
    assert!(err.message.contains("does not start with"));
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
    assert_eq!(
        result.encryption_context().get(b"org".as_ref()).unwrap(),
        b"amazon"
    );
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
    assert!(result.contains_key(b"mykey"));
    assert!(!result.contains_key(format!("{}mykey", CUSTOM_EC_PREFIX).as_bytes()));
}

#[test]
fn custom_ec_extraction_preserves_values() {
    let mut auth_ec = BTreeMap::new();
    auth_ec.insert(format!("{}color", CUSTOM_EC_PREFIX), "blue".to_string());
    auth_ec.insert(format!("{}size", CUSTOM_EC_PREFIX), "large".to_string());

    let result = custom_encryption_context_from_authenticated_encryption_context(&auth_ec).unwrap();
    assert_eq!(result.get(b"color".as_ref()).unwrap(), b"blue");
    assert_eq!(result.get(b"size".as_ref()).unwrap(), b"large");
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
    assert!(result.contains_key(b"included"));
}
