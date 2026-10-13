// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::structures::EncryptedDataKey;

#[test]
fn test_construct_and_access_fields() {
    // Smoke test for field accessibility; not tied to a specific spec requirement.
    let edk = EncryptedDataKey::new(
        "aws-kms".to_string(),
        b"key-info".to_vec(),
        b"encrypted-key-bytes".to_vec(),
    );
    assert_eq!(edk.key_provider_id, "aws-kms");
    assert_eq!(edk.key_provider_info, b"key-info");
    assert_eq!(edk.ciphertext, b"encrypted-key-bytes");
}

#[test]
fn test_clone_and_equality() {
    let edk = EncryptedDataKey::new("provider".to_string(), b"info".to_vec(), b"ct".to_vec());

    // Defense-in-depth: Clone/Eq behave as expected; not tied to a specific spec requirement.
    let cloned = edk.clone();
    assert_eq!(edk, cloned);
}
