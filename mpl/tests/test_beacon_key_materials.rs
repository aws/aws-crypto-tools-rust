// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use aws_crypto_mpl::structures::{BeaconKeyMaterials, EncryptionContext};

#[test]
fn test_construction_required_fields_only() {
    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat = BeaconKeyMaterials::builder()
        .beacon_key_id("beacon-id".to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap();
    assert_eq!(mat.beacon_key_id(), "beacon-id");
    assert!(mat.beacon_key().is_none());
    assert!(mat.hmac_keys().is_none());
}

#[test]
fn test_construction_with_optional_fields() {
    let mut hmac_keys = BTreeMap::new();
    hmac_keys.insert("hmac1".to_string(), b"key1".to_vec());

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let mat = BeaconKeyMaterials::builder()
        .beacon_key_id("beacon-id".to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .beacon_key(b"beacon-key-bytes".to_vec())
        .hmac_keys(hmac_keys)
        .build()
        .unwrap();
    assert_eq!(mat.beacon_key().unwrap(), b"beacon-key-bytes");
    assert_eq!(mat.hmac_keys().unwrap().len(), 1);
}

#[test]
fn test_debug_redacts_secret_material() {
    let mut hmac_keys = BTreeMap::new();
    hmac_keys.insert("key".to_string(), b"secret-hmac".to_vec());

    let mat = BeaconKeyMaterials::builder()
        .beacon_key_id("id".to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .beacon_key(b"secret-beacon".to_vec())
        .hmac_keys(hmac_keys)
        .build()
        .unwrap();
    let debug_output = format!("{:?}", mat);
    assert!(!debug_output.contains("secret-beacon"));
    assert!(!debug_output.contains("secret-hmac"));
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_beacon_key_getter_none_path() {
    let mat = BeaconKeyMaterials::builder()
        .beacon_key_id("beacon-none".to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap();
    assert!(mat.beacon_key().is_none());
}

#[test]
fn test_beacon_key_getter_some_path() {
    let mat = BeaconKeyMaterials::builder()
        .beacon_key_id("beacon-some".to_string())
        .set_encryption_context(Some(EncryptionContext::new()))
        .beacon_key(b"test-key-data".to_vec())
        .build()
        .unwrap();
    assert_eq!(mat.beacon_key().unwrap(), b"test-key-data");
}

#[test]
fn test_beacon_encryption_context_getter() {
    let mut ec = EncryptionContext::new();
    ec.insert("k", "v");
    let mat = BeaconKeyMaterials::builder()
        .beacon_key_id("id".to_string())
        .set_encryption_context(Some(ec))
        .build()
        .unwrap();
    assert_eq!(mat.encryption_context().len(), 1);
}

#[test]
fn build_rejects_an_empty_beacon_key_id() {
    let err = BeaconKeyMaterials::builder()
        .beacon_key_id("")
        .set_encryption_context(Some(EncryptionContext::new()))
        .build()
        .unwrap_err();
    assert!(err.is_validation(), "{err:?}");
}
