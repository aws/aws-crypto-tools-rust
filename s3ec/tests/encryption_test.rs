// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the content-encryption requirements in
//! `../spec/s3-encryption/encryption.md`.
//!
//! These exercise the `crypto` module's content-encryption primitives
//! (non-committing AES-GCM and key-committing AES-GCM), the shared
//! IV/Message-ID generation and validation helpers, and the unconditional
//! failure of the decrypt-only AES-CTR suites.

use aws_s3_encryption::config::EncryptionAlgorithm;
use aws_s3_encryption::crypto::{
    decrypt_content_committing, decrypt_content_gcm, encrypt_content_committing,
    encrypt_content_committing_ctr, encrypt_content_ctr, encrypt_content_gcm,
    reject_if_iv_or_message_id_is_zeros, validate_content_length,
};
use aws_s3_encryption::error::S3EncryptionError;
use aws_s3_encryption::S3EncryptionConfig;

/// A fixed 256-bit content data key for the deterministic round-trip tests.
const DATA_KEY: [u8; 32] = [7u8; 32];
const COMMITTING: EncryptionAlgorithm = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;

// ===========================================================================
// Content Encryption (#content-encryption)
// ===========================================================================

#[test]
fn put_object_uses_the_configured_encryption_algorithm() {
    // The suite used for content encryption is the one configured at client
    // initialization, surfaced by `effective_encryption_algorithm()` (the value
    // PutObject passes to the content-encryption primitives).
    let cfg = S3EncryptionConfig {
        encryption_algorithm: Some(EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf),
        ..Default::default()
    };
    //= ../spec/s3-encryption/encryption.md#content-encryption
    //= type=test
    //# The S3EC MUST use the encryption algorithm configured during [client](./client.md) initialization.
    assert_eq!(
        cfg.effective_encryption_algorithm(),
        EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf
    );
}

#[test]
fn gcm_content_length_within_limit_is_accepted() {
    // A realistic object length is far below the 2^36-byte GCM limit; the
    // check must accept it.
    //= ../spec/s3-encryption/encryption.md#content-encryption
    //= type=test
    //# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
    assert!(validate_content_length(64 * 1024).is_ok());
}

#[test]
fn gcm_content_length_above_limit_is_rejected() {
    // One byte past the 2^36 maximum must be rejected. Passing the length as a
    // usize lets us exercise the bound without allocating 64 GiB.
    let over_limit = (1usize << 36) + 1;
    //= ../spec/s3-encryption/encryption.md#content-encryption
    //= type=test
    //# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
    let err = validate_content_length(over_limit).unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}

#[test]
fn gcm_generated_iv_has_suite_defined_length() {
    let suite = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;
    let (iv, _ct) = encrypt_content_gcm(&DATA_KEY, b"payload").unwrap();
    // The non-committing GCM suite defines a 12-byte IV.
    //= ../spec/s3-encryption/encryption.md#content-encryption
    //= type=test
    //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
    assert_eq!(iv.len(), suite.iv_length());
}

#[test]
fn committing_generated_message_id_has_suite_defined_length() {
    let (message_id, _commit, _ct) =
        encrypt_content_committing(COMMITTING, &DATA_KEY, b"payload").unwrap();
    // The committing suite defines a 28-byte Message ID (HKDF salt).
    //= ../spec/s3-encryption/encryption.md#content-encryption
    //= type=test
    //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
    assert_eq!(message_id.len(), COMMITTING.message_id_length());
}

#[test]
fn gcm_returned_iv_decrypts_the_content() {
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let (iv, ct) = encrypt_content_gcm(&DATA_KEY, plaintext).unwrap();
    // Decrypting with the returned IV recovers the plaintext, which is only
    // possible if the IV used for encryption was returned to the caller.
    //= ../spec/s3-encryption/encryption.md#content-encryption
    //= type=test
    //= reason=decrypt succeeds only with the encrypt IV, proving the IV was returned for the content metadata
    //# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
    let recovered = decrypt_content_gcm(&DATA_KEY, &iv, &ct).unwrap();
    assert_eq!(recovered, plaintext);
}

// ===========================================================================
// Cipher Initialization (#cipher-initialization)
// ===========================================================================

#[test]
fn all_zero_iv_or_message_id_is_rejected() {
    // An all-zero IV/Message ID is refused as a likely generation failure.
    //= ../spec/s3-encryption/encryption.md#cipher-initialization
    //= type=test
    //# The client SHOULD validate that the generated IV or Message ID is not zeros.
    let err = reject_if_iv_or_message_id_is_zeros(&[0u8; 12]).unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}

#[test]
fn non_zero_iv_or_message_id_is_accepted() {
    // A value with any non-zero byte passes the zero check.
    let mut iv = [0u8; 12];
    iv[11] = 1;
    //= ../spec/s3-encryption/encryption.md#cipher-initialization
    //= type=test
    //# The client SHOULD validate that the generated IV or Message ID is not zeros.
    assert!(reject_if_iv_or_message_id_is_zeros(&iv).is_ok());
}

// ===========================================================================
// ALG_AES_256_GCM_IV12_TAG16_NO_KDF (#alg-aes-256-gcm-iv12-tag16-no-kdf)
// ===========================================================================

#[test]
fn gcm_cipher_initialized_with_key_iv_and_tag_round_trips() {
    let plaintext = b"sensitive payload";
    let (iv, ct) = encrypt_content_gcm(&DATA_KEY, plaintext).unwrap();
    // A successful authenticated decryption proves the cipher was initialized
    // with the data key, the generated IV, and the 16-byte GCM tag.
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    //= type=test
    //= reason=authenticated decrypt with the same key+IV succeeds only if encrypt initialized the cipher with the data key, IV, and tag length
    //# The client MUST initialize the cipher, or call an AES-GCM encryption API, with the plaintext data key, the generated IV, and the tag length defined in the Algorithm Suite when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
    let recovered = decrypt_content_gcm(&DATA_KEY, &iv, &ct).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn gcm_encrypts_with_no_aad() {
    let plaintext = b"sensitive payload";
    let (iv, ct) = encrypt_content_gcm(&DATA_KEY, plaintext).unwrap();
    // The non-committing suite seals with empty AAD; decryption with empty AAD
    // therefore succeeds. (Decrypt with non-empty AAD is covered by the GCM
    // tag-binding tests in the unit suite.)
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    //= type=test
    //= reason=open with empty AAD succeeds, proving encrypt provided no AAD; any AAD would change the tag and fail authentication
    //# The client MUST NOT provide any AAD when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
    let recovered = decrypt_content_gcm(&DATA_KEY, &iv, &ct).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn gcm_appends_auth_tag_to_ciphertext() {
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let (_iv, ct) = encrypt_content_gcm(&DATA_KEY, plaintext).unwrap();
    // The ciphertext carries the appended 16-byte GCM tag.
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    //= type=test
    //# The client MUST append the GCM auth tag to the ciphertext if the underlying crypto provider does not do so automatically.
    assert_eq!(ct.len(), plaintext.len() + 16);
}

// ===========================================================================
// ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY (#alg-aes-256-gcm-hkdf-sha512-commit-key)
// ===========================================================================

#[test]
fn committing_uses_hkdf_for_derived_and_commit_keys() {
    let plaintext = b"committed content payload";
    let (message_id, commit_key, ct) =
        encrypt_content_committing(COMMITTING, &DATA_KEY, plaintext).unwrap();
    // Decryption re-derives the encryption key and key commitment via HKDF from
    // the same data key + Message ID; a successful authenticated decrypt proves
    // HKDF produced the derived encrypting key, and the commitment match proves
    // HKDF produced the key commitment value.
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    //= type=test
    //= reason=decrypt re-derives both keys via HKDF; success requires encrypt to have derived them the same way
    //# The client MUST use HKDF to derive the key commitment value and the derived encrypting key as described in [Key Derivation](key-derivation.md).
    let recovered =
        decrypt_content_committing(COMMITTING, &DATA_KEY, &message_id, &commit_key, &ct).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn committing_returns_key_commitment_for_metadata() {
    let (_message_id, commit_key, _ct) =
        encrypt_content_committing(COMMITTING, &DATA_KEY, b"payload").unwrap();
    // The returned key commitment has the suite-defined 28-byte length, ready
    // to be persisted as the x-amz-d content metadata field.
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    //= type=test
    //# The derived key commitment value MUST be set or returned from the encryption process such that it can be included in the content metadata.
    assert_eq!(commit_key.len(), COMMITTING.commitment_length());
}

#[test]
fn committing_appends_auth_tag_to_ciphertext() {
    let plaintext = b"committed content payload";
    let (_message_id, _commit_key, ct) =
        encrypt_content_committing(COMMITTING, &DATA_KEY, plaintext).unwrap();
    // The committing-suite ciphertext also carries the appended 16-byte GCM tag.
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    //= type=test
    //# The client MUST append the GCM auth tag to the ciphertext if the underlying crypto provider does not do so automatically.
    assert_eq!(ct.len(), plaintext.len() + 16);
}

// ===========================================================================
// AES-CTR encryption is unsupported (#alg-aes-256-ctr-*)
// ===========================================================================

#[test]
fn aes_ctr_encryption_fails() {
    // AES-CTR is a decrypt-only (ranged-get) suite; encrypting must fail.
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-ctr-iv16-tag16-no-kdf
    //= type=test
    //# Attempts to encrypt using AES-CTR MUST fail.
    let err = encrypt_content_ctr(&DATA_KEY, b"payload").unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}

#[test]
fn committing_aes_ctr_encryption_fails() {
    // Key-committing AES-CTR is likewise decrypt-only; encrypting must fail.
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-ctr-hkdf-sha512-commit-key
    //= type=test
    //# Attempts to encrypt using key committing AES-CTR MUST fail.
    let err = encrypt_content_committing_ctr(&DATA_KEY, b"payload").unwrap_err();
    assert!(matches!(err, S3EncryptionError::Crypto(_)));
}
