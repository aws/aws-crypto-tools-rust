// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw AES keyring tests, ported from the Dafny `TestRawAESKeyring`.

use std::collections::BTreeSet;

use aws_crypto_mpl::{Keyring, RawAesKeyring};
use aws_mpl_primitives::AesGcm;

use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, MaterialsError, MaterialsErrorKind, PlaintextDataKey,
};

/// Mirrors the Dafny tests' `ALG_AES_256_GCM_IV12_TAG16_NO_KDF`.
const SUITE: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf;

/// Byte length of the serialized authentication-tag-length and IV-length
/// fields of the key provider information.
const LENGTH_FIELDS: usize = 4 + 4;

/// IV length in bytes, per the wrapping algorithm.
const IV_LENGTH: usize = 12;

/// Authentication tag length in bytes, per the wrapping algorithm.
const TAG_LENGTH: usize = 16;

/// Mirrors Dafny `TestUtils.NamespaceAndName(0)`.
fn namespace_and_name() -> (String, String) {
    ("child0 Namespace".to_string(), "child0 Name".to_string())
}

/// Mirrors Dafny `TestUtils.SmallEncryptionContext(A)`.
fn small_encryption_context_a() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert(b"keyA".to_vec(), b"valA".to_vec());
    ec
}

/// An encryption context whose value exceeds the `u16` length field of the
/// serialization format, so it cannot be serialized for use as AAD. Mirrors
/// Dafny `generateUnserializableEncryptionContext`.
fn unserializable_encryption_context() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert(b"keyA".to_vec(), vec![0u8; 0x1_0000]);
    ec
}

fn keyring_with(name: &str, wrapping_key_byte: u8) -> RawAesKeyring {
    let (namespace, _) = namespace_and_name();
    RawAesKeyring::new(
        namespace,
        name.to_string(),
        vec![wrapping_key_byte; 32],
        AesGcm::Aes256Gcm,
    )
    .expect("constructing a 256-bit raw AES keyring")
}

fn default_keyring() -> RawAesKeyring {
    let (_, name) = namespace_and_name();
    keyring_with(&name, 0)
}

fn encryption_materials(ec: EncryptionContext, pdk: Option<Vec<u8>>) -> EncryptionMaterials {
    EncryptionMaterials::new(
        SUITE,
        vec![],
        ec,
        BTreeSet::new(),
        pdk.map(PlaintextDataKey::new),
        None,
        None,
    )
    .expect("constructing encryption materials")
}

fn decryption_materials(ec: EncryptionContext, pdk: Option<Vec<u8>>) -> DecryptionMaterials {
    DecryptionMaterials::new(
        SUITE,
        ec,
        BTreeSet::new(),
        pdk.map(PlaintextDataKey::new),
        None,
        None,
    )
    .expect("constructing decryption materials")
}

fn assert_kind(err: &MaterialsError, expected: MaterialsErrorKind) {
    assert_eq!(
        err.kind, expected,
        "expected {expected:?}, got {:?}: {}",
        err.kind, err.message
    );
}

#[tokio::test]
async fn test_on_encrypt_on_decrypt_generate_data_key() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");

    // No plaintext data key was supplied, so on_encrypt generated one and set
    // it on the output materials.
    let generated_pdk = encrypt_output
        .plaintext_data_key()
        .expect("on_encrypt must set a plaintext data key")
        .as_bytes()
        .to_vec();
    assert_eq!(
        generated_pdk.len(),
        SUITE.specification().encryption_key_length(),
        "generated data key length must match the algorithm suite"
    );

    // The constructed EDK was appended to the encrypted data key list.
    assert_eq!(
        encrypt_output.encrypted_data_keys().len(),
        1,
        "on_encrypt must append exactly one encrypted data key"
    );
    let edk = encrypt_output.encrypted_data_keys()[0].clone();

    let decrypt_output = keyring
        .on_decrypt(decryption_materials(ec, None), &[edk])
        .await
        .expect("on_decrypt succeeds");

    assert_eq!(
        decrypt_output
            .plaintext_data_key()
            .expect("on_decrypt must set a plaintext data key")
            .as_bytes(),
        &generated_pdk,
        "on_decrypt must recover the generated plaintext data key"
    );
}

#[tokio::test]
async fn test_on_encrypt_on_decrypt_supplied_data_key() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();
    // A specific plaintext data key, to prove the keyring encrypts it rather
    // than generating a new one.
    let supplied_pdk = vec![0u8; 32];

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), Some(supplied_pdk.clone())))
        .await
        .expect("on_encrypt succeeds");

    assert_eq!(
        encrypt_output
            .plaintext_data_key()
            .expect("plaintext data key must be present")
            .as_bytes(),
        &supplied_pdk,
        "on_encrypt must not replace a supplied plaintext data key"
    );

    let edk = encrypt_output.encrypted_data_keys()[0].clone();

    let decrypt_output = keyring
        .on_decrypt(decryption_materials(ec, None), &[edk])
        .await
        .expect("on_decrypt succeeds");

    assert_eq!(
        decrypt_output
            .plaintext_data_key()
            .expect("plaintext data key must be present")
            .as_bytes(),
        &supplied_pdk,
        "the round trip recovers the supplied plaintext data key, proving it was the key encrypted"
    );
}

#[tokio::test]
async fn test_on_decrypt_key_name_mismatch() {
    let keyring = default_keyring();
    // Same key namespace, different key name and wrapping key.
    let mismatched_keyring = keyring_with("mismatched", 1);
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = encrypt_output.encrypted_data_keys()[0].clone();

    let result = mismatched_keyring
        .on_decrypt(decryption_materials(ec, None), &[edk])
        .await;

    let err = result.expect_err("a key name mismatch must not decrypt");
    assert_kind(&err, MaterialsErrorKind::NoMatchingDataKey);
    assert!(
        err.message.contains("EncryptedDataKey 0 did not match"),
        "error must report the non-matching EDK by index: {}",
        err.message
    );
}

#[tokio::test]
async fn test_on_decrypt_bad_and_good_edk_succeeds() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");
    let expected_pdk = encrypt_output
        .plaintext_data_key()
        .expect("plaintext data key must be present")
        .as_bytes()
        .to_vec();
    let edk = encrypt_output.encrypted_data_keys()[0].clone();

    // Same provider id and provider info, so the keyring attempts it, but the
    // ciphertext will fail authentication.
    let fake_edk = EncryptedDataKey::new(
        edk.key_provider_id.clone(),
        edk.key_provider_info.clone(),
        vec![0u8; edk.ciphertext.len()],
    );

    let decrypt_output = keyring
        .on_decrypt(decryption_materials(ec, None), &[fake_edk, edk])
        .await
        .expect("on_decrypt must keep going after a failing EDK and succeed on the next");

    assert_eq!(
        decrypt_output
            .plaintext_data_key()
            .expect("plaintext data key must be present")
            .as_bytes(),
        &expected_pdk,
        "the good EDK must still yield the original plaintext data key"
    );
}

#[tokio::test]
async fn test_on_decrypt_no_edks() {
    let keyring = default_keyring();

    let result = keyring
        .on_decrypt(
            decryption_materials(small_encryption_context_a(), None),
            &[],
        )
        .await;

    let err = result.expect_err("an empty encrypted data key list must fail");
    assert_kind(&err, MaterialsErrorKind::NoMatchingDataKey);
}

#[tokio::test]
async fn test_on_decrypt_with_existing_plaintext_data_key_fails() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = encrypt_output.encrypted_data_keys()[0].clone();

    let result = keyring
        .on_decrypt(decryption_materials(ec, Some(vec![0x11; 32])), &[edk])
        .await;

    let err = result.expect_err("materials that already carry a plaintext data key must fail");
    assert_kind(&err, MaterialsErrorKind::PlaintextDataKeyAlreadyPresent);
}

#[tokio::test]
async fn test_on_encrypt_unserializable_encryption_context() {
    let keyring = default_keyring();

    let result = keyring
        .on_encrypt(encryption_materials(
            unserializable_encryption_context(),
            None,
        ))
        .await;

    let err = result.expect_err("an unserializable encryption context must fail on_encrypt");
    assert_kind(&err, MaterialsErrorKind::KeyringFailed);
    assert!(
        err.message
            .contains("failed to serialize the encryption context"),
        "error must name the serialization failure: {}",
        err.message
    );
}

#[tokio::test]
async fn test_on_decrypt_unserializable_encryption_context() {
    let keyring = default_keyring();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(small_encryption_context_a(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = encrypt_output.encrypted_data_keys()[0].clone();

    let result = keyring
        .on_decrypt(
            decryption_materials(unserializable_encryption_context(), None),
            &[edk],
        )
        .await;

    let err = result.expect_err("an unserializable encryption context must fail on_decrypt");
    assert_kind(&err, MaterialsErrorKind::KeyringFailed);
    assert!(
        err.message
            .contains("failed to serialize the encryption context"),
        "error must name the serialization failure: {}",
        err.message
    );
}

#[tokio::test]
async fn test_on_decrypt_unserializable_encryption_context_fails_before_edk_loop() {
    // The encryption context is serialized before any EDK is examined, so an
    // unserializable context fails even when no EDK could ever match.
    let keyring = default_keyring();
    let foreign_edk = EncryptedDataKey::new(
        "some-other-provider".to_string(),
        b"some-other-info".to_vec(),
        vec![0u8; 48],
    );

    let result = keyring
        .on_decrypt(
            decryption_materials(unserializable_encryption_context(), None),
            &[foreign_edk],
        )
        .await;

    let err = result.expect_err("serialization must be attempted before the EDK loop");
    assert_kind(&err, MaterialsErrorKind::KeyringFailed);
    assert!(
        err.message
            .contains("failed to serialize the encryption context"),
        "the failure must be the serialization one, not a no-matching-EDK one: {}",
        err.message
    );
}

#[tokio::test]
async fn test_encrypted_data_key_wire_format() {
    let keyring = default_keyring();
    let (namespace, name) = namespace_and_name();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(small_encryption_context_a(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = &encrypt_output.encrypted_data_keys()[0];
    let pdk_len = encrypt_output
        .plaintext_data_key()
        .expect("plaintext data key must be present")
        .as_bytes()
        .len();

    assert_eq!(
        edk.key_provider_id, namespace,
        "the key provider ID is the keyring's key namespace"
    );

    // key provider info = key name || u32 tag length in bits || u32 IV length
    // in bytes || IV
    let name_bytes = name.as_bytes();
    assert_eq!(
        edk.key_provider_info.len(),
        name_bytes.len() + LENGTH_FIELDS + IV_LENGTH,
        "key provider info length"
    );
    assert_eq!(
        &edk.key_provider_info[..name_bytes.len()],
        name_bytes,
        "key provider info begins with the UTF-8 key name"
    );
    let tag_bits_offset = name_bytes.len();
    assert_eq!(
        &edk.key_provider_info[tag_bits_offset..tag_bits_offset + 4],
        &128u32.to_be_bytes(),
        "authentication tag length is 128 bits, as a big-endian UInt32"
    );
    let iv_len_offset = tag_bits_offset + 4;
    assert_eq!(
        &edk.key_provider_info[iv_len_offset..iv_len_offset + 4],
        &12u32.to_be_bytes(),
        "IV length is 12 bytes, as a big-endian UInt32"
    );

    // ciphertext = encrypted key || authentication tag
    assert_eq!(
        edk.ciphertext.len(),
        pdk_len + TAG_LENGTH,
        "ciphertext is the encrypted data key followed by the 16-byte authentication tag"
    );
}

#[tokio::test]
async fn test_round_trip_every_wrapping_algorithm() {
    for alg in [AesGcm::Aes128Gcm, AesGcm::Aes192Gcm, AesGcm::Aes256Gcm] {
        let (namespace, name) = namespace_and_name();
        let keyring =
            RawAesKeyring::new(namespace, name, vec![0x2A; usize::from(alg.key_len())], alg)
                .unwrap_or_else(|e| panic!("constructing a keyring for {alg:?}: {e}"));
        let ec = small_encryption_context_a();

        let encrypt_output = keyring
            .on_encrypt(encryption_materials(ec.clone(), None))
            .await
            .unwrap_or_else(|e| panic!("on_encrypt for {alg:?}: {e}"));
        let expected_pdk = encrypt_output
            .plaintext_data_key()
            .expect("plaintext data key must be present")
            .as_bytes()
            .to_vec();
        let edk = encrypt_output.encrypted_data_keys()[0].clone();

        let decrypt_output = keyring
            .on_decrypt(decryption_materials(ec, None), &[edk])
            .await
            .unwrap_or_else(|e| panic!("on_decrypt for {alg:?}: {e}"));

        assert_eq!(
            decrypt_output
                .plaintext_data_key()
                .expect("plaintext data key must be present")
                .as_bytes(),
            &expected_pdk,
            "{alg:?} must round-trip the plaintext data key"
        );
    }
}

#[tokio::test]
async fn test_on_decrypt_rejects_tampered_encryption_context() {
    let keyring = default_keyring();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(small_encryption_context_a(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = encrypt_output.encrypted_data_keys()[0].clone();

    // A different encryption context yields different AAD, so authentication
    // must fail. This is what proves the serialized context is used as the AAD.
    let mut tampered_ec = EncryptionContext::new();
    tampered_ec.insert(b"keyA".to_vec(), b"valB".to_vec());

    let result = keyring
        .on_decrypt(decryption_materials(tampered_ec, None), &[edk])
        .await;

    let err = result.expect_err("a mismatched encryption context must fail authentication");
    assert_kind(&err, MaterialsErrorKind::NoMatchingDataKey);
}

#[tokio::test]
async fn test_on_decrypt_rejects_tampered_iv() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = &encrypt_output.encrypted_data_keys()[0];

    // Flip a bit in the IV carried by the key provider info. The provider info
    // still deserializes, so the keyring attempts the decrypt and it fails.
    let mut tampered_info = edk.key_provider_info.clone();
    let last = tampered_info.len() - 1;
    tampered_info[last] ^= 0x01;
    let tampered_edk = EncryptedDataKey::new(
        edk.key_provider_id.clone(),
        tampered_info,
        edk.ciphertext.clone(),
    );

    let result = keyring
        .on_decrypt(decryption_materials(ec, None), &[tampered_edk])
        .await;

    let err = result.expect_err("a tampered IV must fail authentication");
    assert_kind(&err, MaterialsErrorKind::NoMatchingDataKey);
}

#[tokio::test]
async fn test_on_decrypt_skips_edk_with_wrong_key_provider_id() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = &encrypt_output.encrypted_data_keys()[0];

    let foreign_edk = EncryptedDataKey::new(
        "not-this-keyring".to_string(),
        edk.key_provider_info.clone(),
        edk.ciphertext.clone(),
    );

    let result = keyring
        .on_decrypt(decryption_materials(ec, None), &[foreign_edk])
        .await;

    let err = result.expect_err("an EDK from another provider must not be decrypted");
    assert_kind(&err, MaterialsErrorKind::NoMatchingDataKey);
}

#[tokio::test]
async fn test_on_decrypt_rejects_provider_info_with_wrong_tag_length() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = &encrypt_output.encrypted_data_keys()[0];
    let (_, name) = namespace_and_name();

    // Claim a 256-bit authentication tag, which does not match the wrapping
    // algorithm's 128-bit tag.
    let mut tampered_info = edk.key_provider_info.clone();
    let tag_bits_offset = name.as_bytes().len();
    tampered_info[tag_bits_offset..tag_bits_offset + 4].copy_from_slice(&256u32.to_be_bytes());
    let tampered_edk = EncryptedDataKey::new(
        edk.key_provider_id.clone(),
        tampered_info,
        edk.ciphertext.clone(),
    );

    let result = keyring
        .on_decrypt(decryption_materials(ec, None), &[tampered_edk])
        .await;

    let err = result.expect_err("a mismatched authentication tag length must not be decrypted");
    assert_kind(&err, MaterialsErrorKind::NoMatchingDataKey);
}

#[tokio::test]
async fn test_on_decrypt_rejects_provider_info_with_wrong_iv_length() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = &encrypt_output.encrypted_data_keys()[0];
    let (_, name) = namespace_and_name();

    // Claim a 16-byte IV, which does not match the wrapping algorithm's 12.
    let mut tampered_info = edk.key_provider_info.clone();
    let iv_len_offset = name.as_bytes().len() + 4;
    tampered_info[iv_len_offset..iv_len_offset + 4].copy_from_slice(&16u32.to_be_bytes());
    let tampered_edk = EncryptedDataKey::new(
        edk.key_provider_id.clone(),
        tampered_info,
        edk.ciphertext.clone(),
    );

    let result = keyring
        .on_decrypt(decryption_materials(ec, None), &[tampered_edk])
        .await;

    let err = result.expect_err("a mismatched IV length must not be decrypted");
    assert_kind(&err, MaterialsErrorKind::NoMatchingDataKey);
}

#[tokio::test]
async fn test_on_decrypt_rejects_ciphertext_shorter_than_the_tag() {
    let keyring = default_keyring();
    let ec = small_encryption_context_a();

    let encrypt_output = keyring
        .on_encrypt(encryption_materials(ec.clone(), None))
        .await
        .expect("on_encrypt succeeds");
    let edk = &encrypt_output.encrypted_data_keys()[0];

    let truncated_edk = EncryptedDataKey::new(
        edk.key_provider_id.clone(),
        edk.key_provider_info.clone(),
        vec![0u8; TAG_LENGTH - 1],
    );

    let result = keyring
        .on_decrypt(decryption_materials(ec, None), &[truncated_edk])
        .await;

    let err = result.expect_err("a ciphertext shorter than the tag must fail");
    assert_kind(&err, MaterialsErrorKind::NoMatchingDataKey);
    assert!(
        err.message.contains("insufficient data to decrypt"),
        "error must name the truncated ciphertext: {}",
        err.message
    );
}

#[test]
fn test_new_rejects_wrapping_key_length_mismatch() {
    let (namespace, name) = namespace_and_name();
    // 16 bytes supplied for an algorithm that specifies 32.
    let err = RawAesKeyring::new(namespace, name, vec![0u8; 16], AesGcm::Aes256Gcm)
        .expect_err("a wrapping key that does not match the algorithm must be rejected");
    assert_kind(&err, MaterialsErrorKind::Validation);
    assert!(
        err.message
            .contains("does not match the length specified by"),
        "error must name the length mismatch: {}",
        err.message
    );
}

#[test]
fn test_new_accepts_every_wrapping_key_length() {
    let (namespace, name) = namespace_and_name();
    for (alg, expected_len) in [
        (AesGcm::Aes128Gcm, 16),
        (AesGcm::Aes192Gcm, 24),
        (AesGcm::Aes256Gcm, 32),
    ] {
        assert_eq!(
            usize::from(alg.key_len()),
            expected_len,
            "{alg:?} key length in bytes"
        );
        RawAesKeyring::new(
            namespace.clone(),
            name.clone(),
            vec![0u8; expected_len],
            alg,
        )
        .unwrap_or_else(|e| panic!("{alg:?} with a {expected_len}-byte wrapping key: {e}"));
    }
}

#[test]
fn test_new_rejects_reserved_aws_kms_key_namespace() {
    let (_, name) = namespace_and_name();
    let err = RawAesKeyring::new("aws-kms", name, vec![0u8; 32], AesGcm::Aes256Gcm)
        .expect_err("the reserved `aws-kms` key namespace must be rejected");
    assert_kind(&err, MaterialsErrorKind::Validation);
    assert!(
        err.message.contains("must not be `aws-kms`"),
        "error must name the reserved namespace: {}",
        err.message
    );
}

#[test]
fn test_debug_does_not_leak_the_wrapping_key() {
    // The wrapping key is secret; Debug must not print its bytes.
    let (namespace, name) = namespace_and_name();
    let keyring = RawAesKeyring::new(namespace, name, vec![0xAB; 32], AesGcm::Aes256Gcm)
        .expect("constructing a keyring");

    let rendered = format!("{keyring:?}");

    assert!(
        rendered.contains("[REDACTED; 32 bytes]"),
        "Debug must redact the wrapping key: {rendered}"
    );
    assert!(
        !rendered.contains("171"),
        "Debug must not render wrapping key bytes: {rendered}"
    );
    assert!(
        rendered.contains("child0 Namespace") && rendered.contains("child0 Name"),
        "Debug must still show the non-secret configuration: {rendered}"
    );
}

#[test]
fn test_new_allows_key_namespace_that_merely_starts_with_aws_kms() {
    // Only the exact reserved value is rejected, matching the Dafny reference
    // implementation's `keyNamespace != "aws-kms"` check.
    let (_, name) = namespace_and_name();
    RawAesKeyring::new(
        "aws-kms-but-not-really",
        name,
        vec![0u8; 32],
        AesGcm::Aes256Gcm,
    )
    .expect("a namespace that only shares the prefix is accepted");
}
