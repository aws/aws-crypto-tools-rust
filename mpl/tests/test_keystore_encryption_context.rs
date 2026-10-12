// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for keystore encryption context construction.

use aws_crypto_mpl::keystore::attributes::{
    ATTR_BRANCH_KEY_ID, ATTR_CREATE_TIME, ATTR_ENC, ATTR_HIERARCHY_VERSION, ATTR_KMS_ARN,
    ATTR_TABLENAME, ATTR_TYPE, ATTR_VERSION, CUSTOM_EC_PREFIX, TYPE_BEACON_ACTIVE,
    TYPE_BRANCH_ACTIVE, TYPE_BRANCH_VERSION_PREFIX,
};
use aws_crypto_mpl::keystore::encryption_context::{
    EncryptionContextInput, active_encryption_context, beacon_key_encryption_context,
    decrypt_only_encryption_context,
};
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

    assert!(ec.contains_key(ATTR_BRANCH_KEY_ID));

    assert!(ec.contains_key(ATTR_TYPE));

    assert!(ec.contains_key(ATTR_CREATE_TIME));

    assert!(ec.contains_key(ATTR_TABLENAME));

    assert!(ec.contains_key(ATTR_KMS_ARN));

    assert!(ec.contains_key(ATTR_HIERARCHY_VERSION));
}

#[test]
fn active_encryption_context_type_is_branch_active() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1-uuid").unwrap();

    assert_eq!(ec[ATTR_TYPE], TYPE_BRANCH_ACTIVE);
}

#[test]
fn active_encryption_context_version_is_prefixed() {
    let input = sample_input();
    let version = "a1b2c3d4-5678-90ab-cdef-111213141516";
    let ec = active_encryption_context(&input, version).unwrap();

    assert!(ec.contains_key(ATTR_VERSION));

    let expected = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    assert_eq!(ec[ATTR_VERSION], expected);
}

#[test]
fn decrypt_only_encryption_context_omits_version_attribute() {
    let input = sample_input();
    let ec = decrypt_only_encryption_context(&input, "v1-uuid").unwrap();

    assert!(!ec.contains_key(ATTR_VERSION));
}

#[test]
fn decrypt_only_encryption_context_type_is_branch_version_prefix() {
    let input = sample_input();
    let version = "a1b2c3d4-5678-90ab-cdef-111213141516";
    let ec = decrypt_only_encryption_context(&input, version).unwrap();

    let expected = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    assert_eq!(ec[ATTR_TYPE], expected);
}

#[test]
fn beacon_key_encryption_context_type_is_beacon_active() {
    let input = sample_input();
    let ec = beacon_key_encryption_context(&input).unwrap();

    assert_eq!(ec[ATTR_TYPE], TYPE_BEACON_ACTIVE);
}

#[test]
fn beacon_key_encryption_context_omits_version_attribute() {
    let input = sample_input();
    let ec = beacon_key_encryption_context(&input).unwrap();

    assert!(!ec.contains_key(ATTR_VERSION));
}

#[test]
fn encryption_context_includes_tablename_from_logical_keystore_name() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    assert_eq!(ec[ATTR_TABLENAME], "my-keystore-table");
}

#[test]
fn encryption_context_includes_hierarchy_version_as_string() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    assert_eq!(ec[ATTR_HIERARCHY_VERSION], "1");
}

#[test]
fn encryption_context_omits_enc_attribute() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    assert!(!ec.contains_key(ATTR_ENC));
}

#[test]
fn custom_ec_keys_are_prefixed_with_aws_crypto_ec() {
    let mut custom = EncryptionContext::new();
    custom.insert("tenant-id", "acme-corp");
    custom.insert("department", "engineering");

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
    custom.insert("tenant-id", "acme-corp");

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

    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn type_field_is_never_empty_in_active() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    assert!(!ec[ATTR_TYPE].is_empty());
}

#[test]
fn empty_version_is_rejected_for_decrypt_only() {
    let input = sample_input();
    let err = decrypt_only_encryption_context(&input, "")
        .expect_err("empty branch key version must be rejected");
    assert!(err.is_validation(), "{:?}", err);
}

#[test]
fn empty_version_is_rejected_for_active() {
    let input = sample_input();
    let err = active_encryption_context(&input, "")
        .expect_err("empty branch key version must be rejected");
    assert!(err.is_validation(), "{:?}", err);
}

// The ACTIVE context MUST be the DECRYPT_ONLY context with `type` set to
// "branch:ACTIVE" and the branch key version moved into the `version`
// attribute; every other entry MUST match.
#[test]
fn active_is_decrypt_only_with_type_and_version_overrides() {
    let input = sample_input();
    let version = "a1b2c3d4-5678-90ab-cdef-111213141516";

    let decrypt_only = decrypt_only_encryption_context(&input, version).unwrap();
    let active = active_encryption_context(&input, version).unwrap();

    // The DECRYPT_ONLY `type` becomes the ACTIVE `version`.
    assert_eq!(active[ATTR_VERSION], decrypt_only[ATTR_TYPE]);
    assert_eq!(active[ATTR_TYPE], TYPE_BRANCH_ACTIVE);

    // Every other entry is identical to DECRYPT_ONLY.
    for (key, value) in &decrypt_only {
        if key == ATTR_TYPE {
            continue;
        }
        assert_eq!(active.get(key), Some(value));
    }
}
