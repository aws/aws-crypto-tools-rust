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

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - MUST have a `branch-key-id` attribute
    assert!(ec.contains_key(ATTR_BRANCH_KEY_ID));

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - MUST have a `type` attribute
    assert!(ec.contains_key(ATTR_TYPE));

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - MUST have a `create-time` attribute
    assert!(ec.contains_key(ATTR_CREATE_TIME));

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - MUST have a `tablename` attribute to store the logicalKeyStoreName
    assert!(ec.contains_key(ATTR_TABLENAME));

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - MUST have a `kms-arn` attribute
    assert!(ec.contains_key(ATTR_KMS_ARN));

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - MUST have a `hierarchy-version`
    assert!(ec.contains_key(ATTR_HIERARCHY_VERSION));
}

#[test]
fn active_encryption_context_type_is_branch_active() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1-uuid").unwrap();

    //= spec/framework/branch-key-store.md#active-encryption-context
    //= type=test
    //# The ACTIVE encryption context value of the `type` attribute MUST equal to `"branch:ACTIVE"`.
    assert_eq!(ec[ATTR_TYPE], TYPE_BRANCH_ACTIVE);
}

#[test]
fn active_encryption_context_version_is_prefixed() {
    let input = sample_input();
    let version = "a1b2c3d4-5678-90ab-cdef-111213141516";
    let ec = active_encryption_context(&input, version).unwrap();

    //= spec/framework/branch-key-store.md#active-encryption-context
    //= type=test
    //# The ACTIVE encryption context MUST have a `version` attribute.
    assert!(ec.contains_key(ATTR_VERSION));

    let expected = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    //= spec/framework/branch-key-store.md#active-encryption-context
    //= type=test
    //# The `version` attribute MUST store the branch key version formatted like `"branch:version:"` + `version`.
    assert_eq!(ec[ATTR_VERSION], expected);
}

#[test]
fn decrypt_only_encryption_context_omits_version_attribute() {
    let input = sample_input();
    let ec = decrypt_only_encryption_context(&input, "v1-uuid").unwrap();

    //= spec/framework/branch-key-store.md#decrypt-only-encryption-context
    //= type=test
    //# The DECRYPT_ONLY encryption context MUST NOT have a `version` attribute.
    assert!(!ec.contains_key(ATTR_VERSION));
}

#[test]
fn decrypt_only_encryption_context_type_is_branch_version_prefix() {
    let input = sample_input();
    let version = "a1b2c3d4-5678-90ab-cdef-111213141516";
    let ec = decrypt_only_encryption_context(&input, version).unwrap();

    let expected = format!("{TYPE_BRANCH_VERSION_PREFIX}{version}");
    //= spec/framework/branch-key-store.md#decrypt-only-encryption-context
    //= type=test
    //# The `type` attribute MUST stores the branch key version formatted like `"branch:version:"` + `version`.
    assert_eq!(ec[ATTR_TYPE], expected);
}

#[test]
fn beacon_key_encryption_context_type_is_beacon_active() {
    let input = sample_input();
    let ec = beacon_key_encryption_context(&input).unwrap();

    //= spec/framework/branch-key-store.md#beacon-key-encryption-context
    //= type=test
    //# The Beacon key encryption context value of the `type` attribute MUST equal to `"beacon:ACTIVE"`.
    assert_eq!(ec[ATTR_TYPE], TYPE_BEACON_ACTIVE);
}

#[test]
fn beacon_key_encryption_context_omits_version_attribute() {
    let input = sample_input();
    let ec = beacon_key_encryption_context(&input).unwrap();

    //= spec/framework/branch-key-store.md#beacon-key-encryption-context
    //= type=test
    //# The Beacon key encryption context MUST NOT have a `version` attribute.
    assert!(!ec.contains_key(ATTR_VERSION));
}

#[test]
fn encryption_context_includes_tablename_from_logical_keystore_name() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    //= spec/framework/branch-key-store.md#logical-keystore-name
    //= type=test
    //# The logical keystore name MUST be bound to every created key.
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

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - MUST NOT have a `enc` attribute
    assert!(!ec.contains_key(ATTR_ENC));
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

    //= spec/framework/branch-key-store.md#custom-encryption-context
    //= type=test
    //# To avoid name collisions each added attribute from the custom [encryption context](./structures.md#encryption-context-3)
    //# MUST be prefixed with `aws-crypto-ec:`.
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

    //= spec/framework/branch-key-store.md#custom-encryption-context
    //= type=test
    //# If custom [encryption context](./structures.md#encryption-context-3)
    //# is associated with the branch key these values MUST be added to the AWS KMS encryption context.
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

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - The `branch-key-id` field MUST not be an empty string
    let err =
        active_encryption_context(&input, "v1").expect_err("should reject empty branch-key-id");

    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn type_field_is_never_empty_in_active() {
    let input = sample_input();
    let ec = active_encryption_context(&input, "v1").unwrap();

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=test
    //# - The `type` field MUST not be an empty string
    assert!(!ec[ATTR_TYPE].is_empty());
}

// The custom encryption context is a map of arbitrary bytes, but
// `branch-key-store.md` states it "is stored as map of UTF8 Encoded bytes" and
// that reconstruction uses "the UTF8 decode of this key". Non-UTF-8 input is
// therefore not representable in the KMS encryption context and MUST be
// rejected rather than silently substituted.

fn input_with_custom_ec(custom: &EncryptionContext) -> EncryptionContextInput<'_> {
    EncryptionContextInput {
        branch_key_id: "b3c7f8a1-4d2e-4f6b-9a8c-1e2d3f4a5b6c",
        create_time: "2024-01-15T10:30:00.123456Z",
        logical_keystore_name: "my-keystore-table",
        kms_arn: "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
        hierarchy_version: 1,
        custom_ec: Some(custom),
    }
}

#[test]
fn non_utf8_custom_ec_key_is_rejected() {
    let mut custom = EncryptionContext::new();
    // 0xFF is not a valid UTF-8 byte sequence.
    custom.insert(vec![0xFF], b"value".to_vec());

    let err = active_encryption_context(&input_with_custom_ec(&custom), "v1")
        .expect_err("non-UTF-8 custom encryption context key must be rejected");

    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn non_utf8_custom_ec_value_is_rejected() {
    let mut custom = EncryptionContext::new();
    custom.insert(b"key".to_vec(), vec![0xFF]);

    let err = active_encryption_context(&input_with_custom_ec(&custom), "v1")
        .expect_err("non-UTF-8 custom encryption context value must be rejected");

    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn distinct_non_utf8_custom_ec_keys_do_not_collapse() {
    let mut custom = EncryptionContext::new();
    // Two distinct invalid keys. Lossy decoding maps both to U+FFFD, which
    // collides and silently drops one entry.
    custom.insert(vec![0xFF], b"first".to_vec());
    custom.insert(vec![0xFE], b"second".to_vec());
    assert_eq!(custom.len(), 2);

    active_encryption_context(&input_with_custom_ec(&custom), "v1")
        .expect_err("distinct non-UTF-8 keys must not be silently merged");
}

#[test]
fn empty_version_is_rejected_for_decrypt_only() {
    let input = sample_input();
    let err = decrypt_only_encryption_context(&input, "")
        .expect_err("empty branch key version must be rejected");
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
}

#[test]
fn empty_version_is_rejected_for_active() {
    let input = sample_input();
    let err = active_encryption_context(&input, "")
        .expect_err("empty branch key version must be rejected");
    assert_eq!(err.kind, KeystoreErrorKind::Configuration);
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
