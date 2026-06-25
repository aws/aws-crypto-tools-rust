// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Round-trip and negative tests for the raw (non-KMS) `AesKeyring` and
//! `RsaKeyring`. These were moved out of an inline `#[cfg(test)]` module so
//! their annotations live under `tests/` where duvet counts them as test
//! coverage. They exercise the concrete S3 Keyring wrap/unwrap behavior
//! (`../spec/s3-encryption/materials/s3-keyring.md`).

use aws_s3_encryption::config::EncryptionAlgorithm;
use aws_s3_encryption::error::S3EncryptionError;
use aws_s3_encryption::keyring::{AesKeyring, RsaKeyring};

const COMMITTING: EncryptionAlgorithm = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
const NON_COMMITTING: EncryptionAlgorithm = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;

fn rsa_pkcs8_key() -> Vec<u8> {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
    let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    key.as_der().unwrap().as_ref().to_vec()
}

#[test]
fn aes_keyring_wrap_unwrap_round_trips() {
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let (plaintext_dk, wrapped) = keyring.wrap(COMMITTING).unwrap();
    // A fresh 256-bit data key is generated and wrapped (IV + key + tag).
    assert_eq!(plaintext_dk.len(), 32);
    assert_eq!(wrapped.len(), 12 + 32 + 16);
    let recovered = keyring.unwrap(&wrapped, COMMITTING).unwrap();
    assert_eq!(recovered, plaintext_dk);
}

#[test]
fn aes_keyring_unwrap_with_wrong_suite_aad_fails() {
    // The wrap AAD is the suite content-cipher value, so unwrapping a
    // committing-suite-wrapped key as a non-committing key must fail.
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let (_dk, wrapped) = keyring.wrap(COMMITTING).unwrap();
    let err = keyring.unwrap(&wrapped, NON_COMMITTING).unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}

#[test]
fn aes_keyring_rejects_wrong_length_key() {
    // A non-256-bit wrapping key is rejected by the AES-256-GCM primitive.
    let keyring = AesKeyring::new(vec![0x42u8; 16]);
    let err = keyring.wrap(COMMITTING).unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}

#[test]
fn aes_keyring_encrypt_data_key_preserves_existing_key() {
    // `encrypt_data_key` re-wraps an existing data key (re-encryption path) and
    // `unwrap` recovers exactly that data key.
    let keyring = AesKeyring::new(vec![0x42u8; 32]);
    let data_key = vec![0x5Au8; 32];
    let wrapped = keyring.encrypt_data_key(&data_key, COMMITTING).unwrap();
    assert_eq!(keyring.unwrap(&wrapped, COMMITTING).unwrap(), data_key);
}

#[test]
fn rsa_keyring_wrap_unwrap_round_trips() {
    let keyring = RsaKeyring::new(rsa_pkcs8_key());
    let (plaintext_dk, wrapped) = keyring.wrap(COMMITTING).unwrap();
    // A fresh 256-bit data key is generated; the wrapped form is the RSA-2048
    // OAEP ciphertext (256 bytes).
    assert_eq!(plaintext_dk.len(), 32);
    assert_eq!(wrapped.len(), 256);
    let recovered = keyring.unwrap(&wrapped, COMMITTING).unwrap();
    assert_eq!(recovered, plaintext_dk);
}

#[test]
fn rsa_keyring_unwrap_with_wrong_suite_fails() {
    // The framed content-cipher value binds the suite, so unwrapping a
    // committing-suite-wrapped key as a non-committing key must fail.
    let keyring = RsaKeyring::new(rsa_pkcs8_key());
    let (_dk, wrapped) = keyring.wrap(COMMITTING).unwrap();
    let err = keyring.unwrap(&wrapped, NON_COMMITTING).unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}

#[test]
fn rsa_keyring_rejects_invalid_key() {
    let keyring = RsaKeyring::new(b"not a pkcs8 key".to_vec());
    let err = keyring.wrap(COMMITTING).unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}

#[test]
fn rsa_keyring_encrypt_data_key_preserves_existing_key() {
    let keyring = RsaKeyring::new(rsa_pkcs8_key());
    let data_key = vec![0x5Au8; 32];
    let wrapped = keyring.encrypt_data_key(&data_key, COMMITTING).unwrap();
    assert_eq!(keyring.unwrap(&wrapped, COMMITTING).unwrap(), data_key);
}

#[test]
fn build_context_adds_committing_suite_id() {
    use std::collections::BTreeMap;
    use aws_s3_encryption::keyring::KmsKeyring;
    let caller: BTreeMap<String, String> =
        [("user".to_string(), "alice".to_string())].into_iter().collect();
    let built = KmsKeyring::build_encryption_context(&caller, COMMITTING);
    assert_eq!(built.get("user").unwrap(), "alice");
    // The committing suite records the decimal suite ID, not the cipher name.
    assert_eq!(built.get("aws:x-amz-cek-alg").unwrap(), "115");
}

#[test]
fn build_context_adds_gcm_cipher_name() {
    use std::collections::BTreeMap;
    use aws_s3_encryption::keyring::KmsKeyring;
    let built = KmsKeyring::build_encryption_context(&BTreeMap::new(), NON_COMMITTING);
    assert_eq!(built.get("aws:x-amz-cek-alg").unwrap(), "AES/GCM/NoPadding");
}
