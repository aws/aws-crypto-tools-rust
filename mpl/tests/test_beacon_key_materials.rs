// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use aws_crypto_mpl::structures::{BeaconKeyMaterials, EncryptionContext};

#[test]
fn test_construction_required_fields_only() {
    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat = BeaconKeyMaterials::new(
        "beacon-id".to_string(),
        EncryptionContext::new(),
        None,
        None,
    );
    assert_eq!(mat.beacon_key_id(), "beacon-id");
    assert!(mat.beacon_key().is_none());
    assert!(mat.hmac_keys().is_none());
}

#[test]
fn test_construction_with_optional_fields() {
    let mut hmac_keys = BTreeMap::new();
    hmac_keys.insert("hmac1".to_string(), b"key1".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat = BeaconKeyMaterials::new(
        "beacon-id".to_string(),
        EncryptionContext::new(),
        Some(b"beacon-key-bytes".to_vec()),
        Some(hmac_keys),
    );
    assert_eq!(mat.beacon_key().unwrap(), b"beacon-key-bytes");
    assert_eq!(mat.hmac_keys().unwrap().len(), 1);
}

#[test]
fn test_debug_redacts_secret_material() {
    let mut hmac_keys = BTreeMap::new();
    hmac_keys.insert("key".to_string(), b"secret-hmac".to_vec());

    let mat = BeaconKeyMaterials::new(
        "id".to_string(),
        EncryptionContext::new(),
        Some(b"secret-beacon".to_vec()),
        Some(hmac_keys),
    );
    let debug_output = format!("{:?}", mat);
    assert!(!debug_output.contains("secret-beacon"));
    assert!(!debug_output.contains("secret-hmac"));
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_beacon_key_getter_none_path() {
    let mat = BeaconKeyMaterials::new(
        "beacon-none".to_string(),
        EncryptionContext::new(),
        None,
        None,
    );
    assert!(mat.beacon_key().is_none());
}

#[test]
fn test_beacon_key_getter_some_path() {
    let mat = BeaconKeyMaterials::new(
        "beacon-some".to_string(),
        EncryptionContext::new(),
        Some(b"test-key-data".to_vec()),
        None,
    );
    assert_eq!(mat.beacon_key().unwrap(), b"test-key-data");
}

#[test]
fn test_beacon_encryption_context_getter() {
    let mut ec = EncryptionContext::new();
    ec.insert(b"k".to_vec(), b"v".to_vec());
    let mat = BeaconKeyMaterials::new("id".to_string(), ec, None, None);
    assert_eq!(mat.encryption_context().len(), 1);
}
