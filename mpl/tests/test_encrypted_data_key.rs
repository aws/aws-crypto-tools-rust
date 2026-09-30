// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_crypto_mpl::ErrorKind;
use aws_crypto_mpl::structures::EncryptedDataKey;

#[test]
fn test_construct_and_access_fields() {
    // Smoke test for field accessibility; not tied to a specific spec requirement.
    let edk = EncryptedDataKey::builder()
        .key_provider_id("aws-kms")
        .key_provider_info(b"key-info")
        .ciphertext(b"encrypted-key-bytes")
        .build()
        .unwrap();
    assert_eq!(edk.key_provider_id(), "aws-kms");
    assert_eq!(edk.key_provider_info(), b"key-info");
    assert_eq!(edk.ciphertext(), b"encrypted-key-bytes");
}

#[test]
fn test_clone_and_equality() {
    let edk = EncryptedDataKey::builder()
        .key_provider_id("provider")
        .key_provider_info(b"info")
        .ciphertext(b"ct")
        .build()
        .unwrap();

    // Defense-in-depth: Clone/Eq behave as expected; not tied to a specific spec requirement.
    let cloned = edk.clone();
    assert_eq!(edk, cloned);
}

#[test]
fn test_builder_requires_every_field() {
    let full = || {
        EncryptedDataKey::builder()
            .key_provider_id("p")
            .key_provider_info(b"i")
            .ciphertext(b"c")
    };
    assert!(full().build().is_ok());
    let missing = [
        (
            EncryptedDataKey::builder()
                .key_provider_info(b"i")
                .ciphertext(b"c"),
            "key provider ID",
        ),
        (
            EncryptedDataKey::builder()
                .key_provider_id("p")
                .ciphertext(b"c"),
            "key provider information",
        ),
        (
            EncryptedDataKey::builder()
                .key_provider_id("p")
                .key_provider_info(b"i"),
            "ciphertext",
        ),
    ];
    for (builder, field) in missing {
        let err = builder.build().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Validation, "missing {field}");
    }
}
