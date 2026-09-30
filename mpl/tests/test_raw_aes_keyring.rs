// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw AES keyring tests, ported from the Dafny
//! [`TestRawAESKeyring.dfy`](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/test/Keyrings/TestRawAESKeyring.dfy).
//!
//! The fixtures mirror
//! [`TestUtils.dfy`](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/test/TestUtils.dfy):
//! `namespace_and_name` is `TestUtils.NamespaceAndName(0)`
//! (`"child0 Namespace"` / `"child0 Name"`), `small_encryption_context_a` is
//! `TestUtils.SmallEncryptionContext(A)` (`keyA` -> `valA`), and
//! `unserializable_encryption_context` is the Dafny
//! `generateUnserializableEncryptionContext` (a value of `0x1_0000` bytes,
//! one past what the `u16` length field of the serialization format can
//! express).
//!
//! The tests under `Rust-side additions` have no Dafny counterpart. They
//! cover the on-wire shape of the encrypted data key, the two constructor
//! validations, and the negative paths Dafny leaves to its proofs.

use aws_crypto_mpl::{Keyring, RawAesKeyring};
use aws_mpl_primitives::AesGcm;

use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, EsdkAlgorithmSuiteId, MaterialsError, MaterialsErrorKind,
    PlaintextDataKey,
};

/// Mirrors the Dafny tests' `ALG_AES_256_GCM_IV12_TAG16_NO_KDF`.
const SUITE: AlgorithmSuiteId =
    AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);

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
    ec.insert("keyA", "valA");
    ec
}

/// An encryption context whose value exceeds the `u16` length field of the
/// serialization format, so it cannot be serialized for use as AAD. Mirrors
/// Dafny `generateUnserializableEncryptionContext`.
fn unserializable_encryption_context() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("keyA", "\0".repeat(0x1_0000));
    ec
}

fn keyring_with(name: &str, wrapping_key_byte: u8) -> RawAesKeyring {
    let (namespace, _) = namespace_and_name();
    RawAesKeyring::builder()
        .key_namespace(namespace)
        .key_name(name.to_string())
        .wrapping_key(vec![wrapping_key_byte; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .expect("constructing a 256-bit raw AES keyring")
}

fn default_keyring() -> RawAesKeyring {
    let (_, name) = namespace_and_name();
    keyring_with(&name, 0)
}

fn encryption_materials(ec: EncryptionContext, pdk: Option<Vec<u8>>) -> EncryptionMaterials {
    EncryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .encryption_context(ec)
        .set_plaintext_data_key(pdk.map(PlaintextDataKey::new))
        .build()
        .expect("constructing encryption materials")
}

fn decryption_materials(ec: EncryptionContext, pdk: Option<Vec<u8>>) -> DecryptionMaterials {
    DecryptionMaterials::builder()
        .algorithm_suite_id(SUITE)
        .encryption_context(ec)
        .set_plaintext_data_key(pdk.map(PlaintextDataKey::new))
        .build()
        .expect("constructing decryption materials")
}

fn assert_kind(err: &MaterialsError, expected: MaterialsErrorKind) {
    assert_eq!(
        err.kind, expected,
        "expected {expected:?}, got {:?}: {}",
        err.kind, err.message
    );
}

// Ported from Dafny `TestOnEncryptOnDecryptGenerateDataKey`.
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

// Ported from Dafny `TestOnEncryptOnDecryptSuppliedDataKey`.
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

// Ported from Dafny `TestOnDecryptKeyNameMismatch`.
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
        err.is_collection(),
        "the rejected EDK must still be reported, collected on the error: {err}",
    );
    assert!(
        err.to_string().contains("EncryptedDataKey 0 did not match"),
        "error must report the non-matching EDK by index: {}",
        err.message
    );
}

// Ported from Dafny `TestOnDecryptBadAndGoodEdkSucceeds`.
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
    let fake_edk = EncryptedDataKey::builder()
        .key_provider_id(edk.key_provider_id())
        .key_provider_info(edk.key_provider_info().to_vec())
        .ciphertext(vec![0u8; edk.ciphertext().len()])
        .build()
        .unwrap();

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

// Ported from Dafny `TestOnDecryptNoEDKs`.
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

// Ported from Dafny `TestOnEncryptUnserializableEC`.
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

// Ported from Dafny `TestOnDecryptUnserializableEC`.
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

// ---------------------------------------------------------------------------
// Rust-side additions: no Dafny counterpart. See the module documentation
// for why these paths need runtime tests here but not in Dafny.
// ---------------------------------------------------------------------------

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
async fn test_on_decrypt_unserializable_encryption_context_fails_before_edk_loop() {
    // The encryption context is serialized before any EDK is examined, so an
    // unserializable context fails even when no EDK could ever match.
    let keyring = default_keyring();
    let foreign_edk = EncryptedDataKey::builder()
        .key_provider_id("some-other-provider")
        .key_provider_info(b"some-other-info")
        .ciphertext(vec![0u8; 48])
        .build()
        .unwrap();

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
        edk.key_provider_id(),
        namespace,
        "the key provider ID is the keyring's key namespace"
    );

    // key provider info = key name || u32 tag length in bits || u32 IV length
    // in bytes || IV
    let name_bytes = name.as_bytes();
    assert_eq!(
        edk.key_provider_info().len(),
        name_bytes.len() + LENGTH_FIELDS + IV_LENGTH,
        "key provider info length"
    );
    assert_eq!(
        &edk.key_provider_info()[..name_bytes.len()],
        name_bytes,
        "key provider info begins with the UTF-8 key name"
    );
    let tag_bits_offset = name_bytes.len();
    assert_eq!(
        &edk.key_provider_info()[tag_bits_offset..tag_bits_offset + 4],
        &128u32.to_be_bytes(),
        "authentication tag length is 128 bits, as a big-endian UInt32"
    );
    let iv_len_offset = tag_bits_offset + 4;
    assert_eq!(
        &edk.key_provider_info()[iv_len_offset..iv_len_offset + 4],
        &12u32.to_be_bytes(),
        "IV length is 12 bytes, as a big-endian UInt32"
    );

    // ciphertext = encrypted key || authentication tag
    assert_eq!(
        edk.ciphertext().len(),
        pdk_len + TAG_LENGTH,
        "ciphertext is the encrypted data key followed by the 16-byte authentication tag"
    );
}

#[tokio::test]
async fn test_round_trip_every_wrapping_algorithm() {
    for alg in [AesGcm::Aes128Gcm, AesGcm::Aes192Gcm, AesGcm::Aes256Gcm] {
        let (namespace, name) = namespace_and_name();
        let keyring = RawAesKeyring::builder()
            .key_namespace(namespace)
            .key_name(name)
            .wrapping_key(vec![0x2A; usize::from(alg.key_len())])
            .wrapping_alg(alg)
            .build()
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
    tampered_ec.insert("keyA", "valB");

    let result = keyring
        .on_decrypt(decryption_materials(tampered_ec, None), &[edk])
        .await;

    let err = result.expect_err("a mismatched encryption context must fail authentication");
    assert_kind(&err, MaterialsErrorKind::KeyringFailed);
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
    let mut tampered_info = edk.key_provider_info().to_vec();
    let last = tampered_info.len() - 1;
    tampered_info[last] ^= 0x01;
    let tampered_edk = EncryptedDataKey::builder()
        .key_provider_id(edk.key_provider_id())
        .key_provider_info(tampered_info)
        .ciphertext(edk.ciphertext().to_vec())
        .build()
        .unwrap();

    let result = keyring
        .on_decrypt(decryption_materials(ec, None), &[tampered_edk])
        .await;

    let err = result.expect_err("a tampered IV must fail authentication");
    assert_kind(&err, MaterialsErrorKind::KeyringFailed);
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

    let foreign_edk = EncryptedDataKey::builder()
        .key_provider_id("not-this-keyring")
        .key_provider_info(edk.key_provider_info().to_vec())
        .ciphertext(edk.ciphertext().to_vec())
        .build()
        .unwrap();

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
    let mut tampered_info = edk.key_provider_info().to_vec();
    let tag_bits_offset = name.len();
    tampered_info[tag_bits_offset..tag_bits_offset + 4].copy_from_slice(&256u32.to_be_bytes());
    let tampered_edk = EncryptedDataKey::builder()
        .key_provider_id(edk.key_provider_id())
        .key_provider_info(tampered_info)
        .ciphertext(edk.ciphertext().to_vec())
        .build()
        .unwrap();

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
    let mut tampered_info = edk.key_provider_info().to_vec();
    let iv_len_offset = name.len() + 4;
    tampered_info[iv_len_offset..iv_len_offset + 4].copy_from_slice(&16u32.to_be_bytes());
    let tampered_edk = EncryptedDataKey::builder()
        .key_provider_id(edk.key_provider_id())
        .key_provider_info(tampered_info)
        .ciphertext(edk.ciphertext().to_vec())
        .build()
        .unwrap();

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

    let truncated_edk = EncryptedDataKey::builder()
        .key_provider_id(edk.key_provider_id())
        .key_provider_info(edk.key_provider_info().to_vec())
        .ciphertext(vec![0u8; TAG_LENGTH - 1])
        .build()
        .unwrap();

    let result = keyring
        .on_decrypt(decryption_materials(ec, None), &[truncated_edk])
        .await;

    let err = result.expect_err("a ciphertext shorter than the tag must fail");
    // The provider info matched, so this EDK was attempted and the failure is
    // a decryption failure rather than a no-match.
    assert_kind(&err, MaterialsErrorKind::KeyringFailed);
    assert!(
        err.to_string().contains("insufficient data to decrypt"),
        "error must name the truncated ciphertext: {}",
        err.message
    );
}

#[test]
fn test_build_rejects_wrapping_key_length_mismatch() {
    let (namespace, name) = namespace_and_name();
    // 16 bytes supplied for an algorithm that specifies 32.
    let err = RawAesKeyring::builder()
        .key_namespace(namespace)
        .key_name(name)
        .wrapping_key(vec![0u8; 16])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
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
fn test_build_accepts_every_wrapping_key_length() {
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
        RawAesKeyring::builder()
            .key_namespace(namespace.clone())
            .key_name(name.clone())
            .wrapping_key(vec![0u8; expected_len])
            .wrapping_alg(alg)
            .build()
            .unwrap_or_else(|e| panic!("{alg:?} with a {expected_len}-byte wrapping key: {e}"));
    }
}

#[test]
fn test_build_rejects_reserved_aws_kms_key_namespace() {
    let (_, name) = namespace_and_name();
    let err = RawAesKeyring::builder()
        .key_namespace("aws-kms")
        .key_name(name)
        .wrapping_key(vec![0u8; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .expect_err("the reserved `aws-kms` key namespace must be rejected");
    assert_kind(&err, MaterialsErrorKind::Validation);
    assert!(
        err.message.contains("must not be or start with `aws-kms`"),
        "error must name the reserved namespace: {}",
        err.message
    );
}

#[test]
fn test_build_rejects_key_provider_ids_of_the_aws_kms_keyrings() {
    // The key namespace becomes the EDK's key provider ID, so accepting any of
    // these would let a raw AES keyring emit encrypted data keys that
    // impersonate the corresponding AWS KMS keyring. All four are reserved by
    // the `aws-kms` prefix rule, so a prefix check is required; an equality
    // check against `aws-kms` alone would let the last three through.
    let (_, name) = namespace_and_name();
    for namespace in [
        "aws-kms",
        "aws-kms-hierarchy",
        "aws-kms-rsa",
        "aws-kms-ecdh",
        // Not a real provider ID, but shares the reserved prefix.
        "aws-kms-but-not-really",
    ] {
        let Err(err) = RawAesKeyring::builder()
            .key_namespace(namespace)
            .key_name(name.clone())
            .wrapping_key(vec![0u8; 32])
            .wrapping_alg(AesGcm::Aes256Gcm)
            .build()
        else {
            panic!("`{namespace}` must be rejected as reserved");
        };
        assert_kind(&err, MaterialsErrorKind::Validation);
    }
}

#[test]
fn test_build_accepts_the_raw_ecdh_key_provider_id() {
    // `raw-ecdh` is the raw ECDH keyring's key provider ID, but it is not
    // covered by the reserved `aws-kms` prefix and the specification does not
    // reserve it against the raw AES keyring, so it is accepted. This pins the
    // rejection to the documented prefix rather than to a broader denylist.
    let (_, name) = namespace_and_name();
    RawAesKeyring::builder()
        .key_namespace("raw-ecdh")
        .key_name(name)
        .wrapping_key(vec![0u8; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .expect("`raw-ecdh` is not reserved against the raw AES keyring");
}

#[test]
fn test_debug_does_not_leak_the_wrapping_key() {
    // The wrapping key is secret; Debug must not print its bytes.
    let (namespace, name) = namespace_and_name();
    let keyring = RawAesKeyring::builder()
        .key_namespace(namespace)
        .key_name(name)
        .wrapping_key(vec![0xAB; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
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

#[tokio::test]
async fn test_clone_is_interchangeable_with_original() {
    let original = default_keyring();
    let clone = original.clone();
    let ec = small_encryption_context_a();

    for (encryptor, decryptor) in [(&original, &clone), (&clone, &original)] {
        let encrypt_output = encryptor
            .on_encrypt(encryption_materials(ec.clone(), None))
            .await
            .expect("on_encrypt succeeds");
        let pdk = encrypt_output
            .plaintext_data_key()
            .expect("on_encrypt must set a plaintext data key")
            .as_bytes()
            .to_vec();

        let decrypt_output = decryptor
            .on_decrypt(
                decryption_materials(ec.clone(), None),
                encrypt_output.encrypted_data_keys(),
            )
            .await
            .expect("on_decrypt succeeds");
        assert_eq!(
            decrypt_output
                .plaintext_data_key()
                .expect("on_decrypt must set a plaintext data key")
                .as_bytes(),
            &pdk,
        );
    }
}

#[test]
fn test_build_requires_every_field() {
    let key = || vec![0u8; 32];
    let cases = [
        (
            RawAesKeyring::builder()
                .key_name("n")
                .wrapping_key(key())
                .wrapping_alg(AesGcm::Aes256Gcm),
            "key namespace",
        ),
        (
            RawAesKeyring::builder()
                .key_namespace("ns")
                .wrapping_key(key())
                .wrapping_alg(AesGcm::Aes256Gcm),
            "key name",
        ),
        (
            RawAesKeyring::builder()
                .key_namespace("ns")
                .key_name("n")
                .wrapping_alg(AesGcm::Aes256Gcm),
            "wrapping key",
        ),
        (
            RawAesKeyring::builder()
                .key_namespace("ns")
                .key_name("n")
                .wrapping_key(key()),
            "wrapping algorithm",
        ),
    ];
    for (builder, field) in cases {
        let err = builder.build().unwrap_err();
        assert!(err.message.contains(field), "{field}: {}", err.message);
    }
}
