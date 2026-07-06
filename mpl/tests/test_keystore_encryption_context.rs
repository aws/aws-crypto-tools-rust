// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for keystore encryption context construction.

#![cfg(feature = "keystore")]

use aws_crypto_mpl::keystore::encryption_context::{
    CUSTOM_EC_PREFIX, EncryptionContextInput, KEY_BRANCH_KEY_ID, KEY_CREATE_TIME, KEY_ENC,
    KEY_HIERARCHY_VERSION, KEY_KMS_ARN, KEY_TABLENAME, KEY_TYPE, KEY_VERSION, TYPE_BEACON_ACTIVE,
    TYPE_BRANCH_ACTIVE, TYPE_BRANCH_VERSION_PREFIX, active_encryption_context,
    beacon_key_encryption_context, decrypt_only_encryption_context,
};
use aws_crypto_mpl::keystore::error::KeystoreErrorKind;
use aws_crypto_mpl::structures::EncryptionContext;

fn sample_input() -> EncryptionContextInput<'static> {
    EncryptionContextInput {
        branch_key_id: "b3c7f8a1-4d2e-4f6b-9a8c-1e2d3f4a5b6c",
        create_time: "2024-01-15T10:30:00.123456Z",
        logical_keystore_name: "my-keystore-table",
        kms_arn: "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
        hierarchy_version: 1,
        custom_ec: None,
    }
}

#[test]
fn active_encryption_context_contains_required_keys() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1-uuid").unwrap();

    assert!(ec.contains_key(KEY_BRANCH_KEY_ID));

    assert!(ec.contains_key(KEY_TYPE));

    assert!(ec.contains_key(KEY_CREATE_TIME));

    assert!(ec.contains_key(KEY_TABLENAME));

    assert!(ec.contains_key(KEY_KMS_ARN));

    assert!(ec.contains_key(KEY_HIERARCHY_VERSION));
}

#[test]
fn active_encryption_context_type_is_branch_active() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1-uuid").unwrap();

    assert_eq!(ec[KEY_TYPE], TYPE_BRANCH_ACTIVE);
}

#[test]
fn active_encryption_context_version_is_prefixed() {
    let input = sample_input();
    let version = "a1b2c3d4-5678-90ab-cdef-111213141516";
    let ec = active_encryption_context(&input, version).unwrap();

    assert!(ec.contains_key(KEY_VERSION));

    let expected = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    assert_eq!(ec[KEY_VERSION], expected);
}

#[test]
fn decrypt_only_encryption_context_omits_version_attribute() {
    let input = sample_input();
    let ec = decrypt_only_encryption_context(&input, "v1-uuid").unwrap();

    assert!(!ec.contains_key(KEY_VERSION));
}

#[test]
fn decrypt_only_encryption_context_type_is_branch_version_prefix() {
    let input = sample_input();
    let version = "a1b2c3d4-5678-90ab-cdef-111213141516";
    let ec = decrypt_only_encryption_context(&input, version).unwrap();

    let expected = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    assert_eq!(ec[KEY_TYPE], expected);
}

#[test]
fn beacon_key_encryption_context_type_is_beacon_active() {
    let input = sample_input();
    let ec = beacon_key_encryption_context(&input).unwrap();

    assert_eq!(ec[KEY_TYPE], TYPE_BEACON_ACTIVE);
}

#[test]
fn beacon_key_encryption_context_omits_version_attribute() {
    let input = sample_input();
    let ec = beacon_key_encryption_context(&input).unwrap();

    assert!(!ec.contains_key(KEY_VERSION));
}

#[test]
fn encryption_context_includes_tablename_from_logical_keystore_name() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    assert_eq!(ec[KEY_TABLENAME], "my-keystore-table");
}

#[test]
fn encryption_context_includes_hierarchy_version_as_string() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    assert_eq!(ec[KEY_HIERARCHY_VERSION], "1");
}

#[test]
fn encryption_context_omits_enc_attribute() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    assert!(!ec.contains_key(KEY_ENC));
}

#[test]
fn custom_ec_keys_are_prefixed_with_aws_crypto_ec() {
    let mut custom = EncryptionContext::new();
    custom.insert(b"tenant-id".to_vec(), b"acme-corp".to_vec());
    custom.insert(b"department".to_vec(), b"engineering".to_vec());

    let input = EncryptionContextInput {
        branch_key_id: "b3c7f8a1-4d2e-4f6b-9a8c-1e2d3f4a5b6c",
        create_time: "2024-01-15T10:30:00.123456Z",
        logical_keystore_name: "my-keystore-table",
        kms_arn: "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
        hierarchy_version: 1,
        custom_ec: Some(&custom),
    };

    let ec = active_encryption_context(&input, "v1").unwrap();

    assert!(ec.contains_key(&format!("{CUSTOM_EC_PREFIX}tenant-id")));
    assert!(ec.contains_key(&format!("{CUSTOM_EC_PREFIX}department")));
    // Original keys without prefix must NOT exist
    assert!(!ec.contains_key("tenant-id"));
    assert!(!ec.contains_key("department"));
}

#[test]
fn custom_ec_values_are_preserved() {
    let mut custom = EncryptionContext::new();
    custom.insert(b"tenant-id".to_vec(), b"acme-corp".to_vec());

    let input = EncryptionContextInput {
        branch_key_id: "b3c7f8a1-4d2e-4f6b-9a8c-1e2d3f4a5b6c",
        create_time: "2024-01-15T10:30:00.123456Z",
        logical_keystore_name: "my-keystore-table",
        kms_arn: "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
        hierarchy_version: 1,
        custom_ec: Some(&custom),
    };

    let ec = active_encryption_context(&input, "v1").unwrap();

    assert_eq!(ec[&format!("{CUSTOM_EC_PREFIX}tenant-id")], "acme-corp");
}

#[test]
fn empty_branch_key_id_is_rejected() {
    let input = EncryptionContextInput {
        branch_key_id: "",
        create_time: "2024-01-15T10:30:00.123456Z",
        logical_keystore_name: "my-keystore-table",
        kms_arn: "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
        hierarchy_version: 1,
        custom_ec: None,
    };

    let err =
        active_encryption_context(&input, "v1").expect_err("should reject empty branch-key-id");

    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn type_field_is_never_empty_in_active() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    assert!(!ec[KEY_TYPE].is_empty());
}

#[test]
fn encryption_context_additional_attributes_via_custom_ec() {
    // "Any additionally attributes on the DynamoDB item MUST be added to the encryption context"
    // This is realized via the custom_ec mechanism — additional DDB attributes
    // are passed through custom_ec by the record-format layer.
    let mut custom = EncryptionContext::new();
    custom.insert(b"extra-field".to_vec(), b"extra-value".to_vec());

    let input = EncryptionContextInput {
        branch_key_id: "b3c7f8a1-4d2e-4f6b-9a8c-1e2d3f4a5b6c",
        create_time: "2024-01-15T10:30:00.123456Z",
        logical_keystore_name: "my-keystore-table",
        kms_arn: "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
        hierarchy_version: 1,
        custom_ec: Some(&custom),
    };

    let ec = active_encryption_context(&input, "v1").unwrap();

    assert!(ec.contains_key(&format!("{CUSTOM_EC_PREFIX}extra-field")));
    assert_eq!(ec[&format!("{CUSTOM_EC_PREFIX}extra-field")], "extra-value");
}
