// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::structures::{BranchKeyMaterials, EncryptionContext};

#[test]
fn test_valid_construction() {
    let branch_key = [0xABu8; 32];
    let version = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".to_string();
    let ec = EncryptionContext::new();

    // Type-system enforcement (implication in source); test exists for regression coverage.
    let result = BranchKeyMaterials::new(branch_key, "key-id".to_string(), version, ec);
    assert!(result.is_ok());
    let mat = result.unwrap();
    assert_eq!(mat.branch_key(), &[0xAB; 32]);
    assert_eq!(mat.branch_key_id(), "key-id");
}

#[test]
fn test_construction_accepts_various_version_strings() {
    // With UUID validation removed, `new` accepts arbitrary version strings.
    // These three canonical v4 UUIDs are the intended real-world inputs.
    let branch_key = [0x00u8; 32];
    let valid_uuids = [
        "550e8400-e29b-41d4-a716-446655440000",
        "6ba7b810-9dad-41d4-8000-00c04fd430c8",
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    ];

    for uuid in valid_uuids {
        let result = BranchKeyMaterials::new(
            branch_key,
            "id".to_string(),
            uuid.to_string(),
            EncryptionContext::new(),
        );
        assert!(result.is_ok(), "Construction should succeed: {}", uuid);
    }
}

#[test]
fn test_branch_key_32_bytes_by_construction() {
    // Type-system enforcement (implication in source); test exists for regression coverage.
    let branch_key = [0x42u8; 32];
    let mat = BranchKeyMaterials::new(
        branch_key,
        "id".to_string(),
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".to_string(),
        EncryptionContext::new(),
    )
    .unwrap();
    assert_eq!(mat.branch_key().len(), 32);
}

#[test]
fn test_branch_key_version_getter() {
    let version = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let mat = BranchKeyMaterials::new(
        [0x00; 32],
        "id".to_string(),
        version.to_string(),
        EncryptionContext::new(),
    )
    .unwrap();
    assert_eq!(mat.branch_key_version(), version);
}

#[test]
fn test_branch_key_encryption_context_getter() {
    let mut ec = EncryptionContext::new();
    ec.insert("key", "value");
    let mat = BranchKeyMaterials::new(
        [0x00; 32],
        "id".to_string(),
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".to_string(),
        ec,
    )
    .unwrap();
    assert_eq!(mat.encryption_context().len(), 1);
}

#[test]
fn test_debug_redacts_branch_key() {
    let mat = BranchKeyMaterials::new(
        [0xFF; 32],
        "id".to_string(),
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".to_string(),
        EncryptionContext::new(),
    )
    .unwrap();
    let debug_output = format!("{:?}", mat);
    assert!(debug_output.contains("REDACTED"));
    assert!(!debug_output.contains("255")); // 0xFF = 255
}
