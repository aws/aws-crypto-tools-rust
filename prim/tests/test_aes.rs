// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AES-GCM tests ported from Dafny [`TestAES.dfy`].
//!
//! The KAT (key, IV, AAD, ciphertext, auth tag) was generated in Node.js
//! against AES-256-GCM; see the leading comment in [`TestAES.dfy`] for the
//! generator recipe. Additional round-trip and error-path tests are added
//! to hit the wider prim API surface (AES-128-GCM, AES-192-GCM, length
//! validation).
//!
//! [`TestAES.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/test/TestAES.dfy

use aws_mpl_primitives::{AesGcm, Error, aes_decrypt, aes_encrypt};

const KEY_256: [u8; 32] = [1; 32];
const IV: [u8; 12] = [2; 12];
const AAD: [u8; 4] = [3; 4];
const PLAINTEXT: [u8; 4] = [97, 115, 100, 102]; // "asdf"

/// Expected AES-256-GCM ciphertext for the fixed inputs (from `TestAES.dfy`).
const EXPECTED_CIPHERTEXT: [u8; 4] = [102, 165, 173, 47];

/// Expected AES-256-GCM authentication tag for the fixed inputs (from `TestAES.dfy`).
const EXPECTED_AUTH_TAG: [u8; 16] = [
    54, 200, 18, 56, 172, 194, 174, 23, 239, 151, 47, 180, 143, 232, 142, 184,
];

#[test]
fn test_aes_256_gcm_encrypt_kat() -> Result<(), Error> {
    let mut cipher_text = Vec::new();
    aes_encrypt(
        AesGcm::Aes256Gcm,
        &IV,
        &KEY_256,
        &PLAINTEXT,
        &AAD,
        &mut cipher_text,
    )?;
    // aes_encrypt appends ciphertext followed by the auth tag to the buffer.
    let (ct, tag) = cipher_text.split_at(PLAINTEXT.len());
    assert_eq!(ct, EXPECTED_CIPHERTEXT);
    assert_eq!(tag, EXPECTED_AUTH_TAG);
    Ok(())
}

#[test]
fn test_aes_256_gcm_decrypt_kat() -> Result<(), Error> {
    let mut plain_text = vec![0u8; EXPECTED_CIPHERTEXT.len()];
    aes_decrypt(
        AesGcm::Aes256Gcm,
        &KEY_256,
        &EXPECTED_CIPHERTEXT,
        &EXPECTED_AUTH_TAG,
        &IV,
        &AAD,
        &mut plain_text,
    )?;
    assert_eq!(plain_text, PLAINTEXT);
    Ok(())
}

#[test]
fn test_aes_256_gcm_round_trip() -> Result<(), Error> {
    let mut cipher_text = Vec::new();
    aes_encrypt(
        AesGcm::Aes256Gcm,
        &IV,
        &KEY_256,
        &PLAINTEXT,
        &AAD,
        &mut cipher_text,
    )?;
    let (ct, tag) = cipher_text.split_at(PLAINTEXT.len());
    let mut plain_text = vec![0u8; ct.len()];
    aes_decrypt(
        AesGcm::Aes256Gcm,
        &KEY_256,
        ct,
        tag,
        &IV,
        &AAD,
        &mut plain_text,
    )?;
    assert_eq!(plain_text, PLAINTEXT);
    Ok(())
}

#[test]
fn test_aes_128_gcm_round_trip() -> Result<(), Error> {
    let key = [1u8; 16];
    let mut cipher_text = Vec::new();
    aes_encrypt(
        AesGcm::Aes128Gcm,
        &IV,
        &key,
        &PLAINTEXT,
        &AAD,
        &mut cipher_text,
    )?;
    let (ct, tag) = cipher_text.split_at(PLAINTEXT.len());
    let mut plain_text = vec![0u8; ct.len()];
    aes_decrypt(AesGcm::Aes128Gcm, &key, ct, tag, &IV, &AAD, &mut plain_text)?;
    assert_eq!(plain_text, PLAINTEXT);
    Ok(())
}

#[test]
fn test_aes_192_gcm_round_trip() -> Result<(), Error> {
    let key = [1u8; 24];
    let mut cipher_text = Vec::new();
    aes_encrypt(
        AesGcm::Aes192Gcm,
        &IV,
        &key,
        &PLAINTEXT,
        &AAD,
        &mut cipher_text,
    )?;
    let (ct, tag) = cipher_text.split_at(PLAINTEXT.len());
    let mut plain_text = vec![0u8; ct.len()];
    aes_decrypt(AesGcm::Aes192Gcm, &key, ct, tag, &IV, &AAD, &mut plain_text)?;
    assert_eq!(plain_text, PLAINTEXT);
    Ok(())
}

#[test]
fn test_aes_gcm_key_length() {
    assert_eq!(AesGcm::Aes128Gcm.key_length(), 16);
    assert_eq!(AesGcm::Aes192Gcm.key_length(), 24);
    assert_eq!(AesGcm::Aes256Gcm.key_length(), 32);
    assert_eq!(AesGcm::default().key_length(), 32); // default is Aes256Gcm
}

// Error paths — not in Dafny but required to reach 100% line coverage.

#[test]
fn test_aes_decrypt_output_buffer_too_small() {
    let mut plain_text = vec![0u8; EXPECTED_CIPHERTEXT.len() - 1];
    let err = aes_decrypt(
        AesGcm::Aes256Gcm,
        &KEY_256,
        &EXPECTED_CIPHERTEXT,
        &EXPECTED_AUTH_TAG,
        &IV,
        &AAD,
        &mut plain_text,
    )
    .unwrap_err();
    assert!(err.is_cryptographic(), "{:?}", err);
}

#[test]
fn test_aes_encrypt_bad_key_length() {
    let key = [1u8; 15];
    let mut cipher_text = Vec::new();
    let err = aes_encrypt(
        AesGcm::Aes256Gcm,
        &IV,
        &key,
        &PLAINTEXT,
        &AAD,
        &mut cipher_text,
    )
    .unwrap_err();
    assert!(err.is_cryptographic(), "{:?}", err);
}

#[test]
fn test_aes_encrypt_bad_iv_length() {
    let iv = [2u8; 11];
    let mut cipher_text = Vec::new();
    let err = aes_encrypt(
        AesGcm::Aes256Gcm,
        &iv,
        &KEY_256,
        &PLAINTEXT,
        &AAD,
        &mut cipher_text,
    )
    .unwrap_err();
    assert!(err.is_cryptographic(), "{:?}", err);
}

#[test]
fn test_aes_decrypt_bad_key_length() {
    let key = [1u8; 15];
    let mut plain_text = vec![0u8; EXPECTED_CIPHERTEXT.len()];
    let err = aes_decrypt(
        AesGcm::Aes256Gcm,
        &key,
        &EXPECTED_CIPHERTEXT,
        &EXPECTED_AUTH_TAG,
        &IV,
        &AAD,
        &mut plain_text,
    )
    .unwrap_err();
    assert!(err.is_cryptographic(), "{:?}", err);
}

#[test]
fn test_aes_decrypt_bad_iv_length() {
    let iv = [2u8; 11]; // Not 12 bytes; fails Nonce::try_assume_unique_for_key.
    let mut plain_text = vec![0u8; EXPECTED_CIPHERTEXT.len()];
    let err = aes_decrypt(
        AesGcm::Aes256Gcm,
        &KEY_256,
        &EXPECTED_CIPHERTEXT,
        &EXPECTED_AUTH_TAG,
        &iv,
        &AAD,
        &mut plain_text,
    )
    .unwrap_err();
    assert!(err.is_cryptographic(), "{:?}", err);
}

#[test]
fn test_aes_decrypt_tampered_auth_tag() {
    let mut bad_tag = EXPECTED_AUTH_TAG;
    bad_tag[0] ^= 1;
    let mut plain_text = vec![0u8; EXPECTED_CIPHERTEXT.len()];
    let err = aes_decrypt(
        AesGcm::Aes256Gcm,
        &KEY_256,
        &EXPECTED_CIPHERTEXT,
        &bad_tag,
        &IV,
        &AAD,
        &mut plain_text,
    )
    .unwrap_err();
    assert!(err.is_cryptographic(), "{:?}", err);
}
