// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Content encryption and decryption for the S3 Encryption Client.
//!
//! Implements the two authenticated content-encryption paths used by the V4
//! S3EC release:
//!
//! * **Non-committing** ([`encrypt_content_gcm`] / [`decrypt_content_gcm`]) —
//!   `ALG_AES_256_GCM_IV12_TAG16_NO_KDF`, persisted using the V2 content
//!   metadata format.
//! * **Key-committing** ([`encrypt_content_committing`] /
//!   [`decrypt_content_committing`]) — `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY`,
//!   persisted using the V3 content metadata format.
//!
//! The data-key wrapping/unwrapping (KMS) and the S3 round-trip are layered on
//! top of these primitives by the client.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::cipher::{
    DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey, AES_256,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::{constant_time, hkdf, rand};

use crate::config::EncryptionAlgorithm;
use crate::error::{Result, S3EncryptionError};

fn crypto_err(context: &str) -> S3EncryptionError {
    S3EncryptionError::Crypto(context.to_string())
}

/// AES-256-GCM seal. Returns ciphertext with the authentication tag appended.
fn aes_gcm_seal(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| crypto_err("invalid AES-256-GCM key"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(iv).map_err(|_| crypto_err("invalid IV length"))?;

    let mut in_out = plaintext.to_vec();
    //= spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    //# The client MUST append the GCM auth tag to the ciphertext if the underlying crypto provider does not do so automatically.
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| crypto_err("AES-256-GCM encryption failed"))?;
    Ok(in_out)
}

/// AES-256-GCM open. Verifies the appended authentication tag and returns the
/// recovered plaintext.
fn aes_gcm_open(key: &[u8], iv: &[u8], aad: &[u8], ciphertext_with_tag: &[u8]) -> Result<Vec<u8>> {
    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| crypto_err("invalid AES-256-GCM key"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(iv).map_err(|_| crypto_err("invalid IV length"))?;

    let mut in_out = ciphertext_with_tag.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| crypto_err("AES-256-GCM authentication failed"))?;
    Ok(plaintext.to_vec())
}

// ---------------------------------------------------------------------------
// Non-committing AES-GCM (ALG_AES_256_GCM_IV12_TAG16_NO_KDF, V2 format).
// ---------------------------------------------------------------------------

/// Encrypt object content with `ALG_AES_256_GCM_IV12_TAG16_NO_KDF`.
///
/// Returns the freshly generated IV (persisted as `x-amz-iv`) and the
/// ciphertext with the GCM tag appended.
pub fn encrypt_content_gcm(data_key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let suite = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;

    //= spec/s3-encryption/encryption.md#content-encryption
    //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
    let mut iv = vec![0u8; suite.iv_length()];
    rand::fill(&mut iv).map_err(|_| crypto_err("failed to generate IV"))?;

    //= spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    //# The client MUST NOT provide any AAD when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
    let ciphertext = aes_gcm_seal(data_key, &iv, &[], plaintext)?;
    Ok((iv, ciphertext))
}

/// Decrypt object content encrypted with `ALG_AES_256_GCM_IV12_TAG16_NO_KDF`.
pub fn decrypt_content_gcm(
    data_key: &[u8],
    iv: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>> {
    //= spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    //# The client MUST NOT provide any AAD when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
    aes_gcm_open(data_key, iv, &[], ciphertext_with_tag)
}

// ---------------------------------------------------------------------------
// Legacy, unauthenticated AES-CBC (ALG_AES_256_CBC_IV16_NO_KDF).
//
// This is a decrypt-only legacy read path: objects written by older S3
// encryption clients (CryptoMode.EncryptionOnly) use AES-256-CBC with
// PKCS5/PKCS7 padding and a 16-byte IV. CBC carries no authentication tag, so
// the caller MUST gate this path on the legacy-unauthenticated-modes
// configuration before invoking it.
// ---------------------------------------------------------------------------

/// Decrypt object content encrypted with the legacy, unauthenticated
/// `ALG_AES_256_CBC_IV16_NO_KDF` suite: AES-256 in CBC mode with PKCS7 padding
/// (compatible with the Java JCE `AES/CBC/PKCS5Padding`) and a 16-byte IV.
///
/// CBC provides no authentication tag, so this path performs no integrity
/// verification. To avoid exposing a padding-oracle distinguisher, every
/// failure mode (bad padding, truncated ciphertext, wrong key) collapses to a
/// single uniform error.
pub fn decrypt_content_cbc(data_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    //= spec/s3-encryption/decryption.md#cbc-decryption
    //# If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and [legacy unauthenticated algorithm suites](#legacy-decryption) is enabled,
    //# then the S3EC MUST create a cipher with AES in CBC Mode with PKCS5Padding or PKCS7Padding compatible padding for a 16-byte block cipher (example: for the Java JCE, this is "AES/CBC/PKCS5Padding").
    let unbound = UnboundCipherKey::new(&AES_256, data_key)
        .map_err(|_| crypto_err("invalid AES-256-CBC key"))?;
    let key = PaddedBlockDecryptingKey::cbc_pkcs7(unbound)
        //= spec/s3-encryption/decryption.md#cbc-decryption
        //# If the cipher object cannot be created as described above,
        //# Decryption MUST fail.
        .map_err(|_| crypto_err("failed to initialize AES/CBC/PKCS5Padding cipher"))?;

    // The CBC IV is a fixed 16 bytes; a different length is a malformed object.
    let iv: FixedLength<16> = iv
        .try_into()
        .map_err(|_| crypto_err("invalid CBC IV length"))?;
    let context = DecryptionContext::Iv128(iv);

    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .decrypt(&mut in_out, context)
        // Uniform failure: do not distinguish padding errors from other faults.
        .map_err(|_| crypto_err("failed to decrypt CBC content"))?;
    Ok(plaintext.to_vec())
}

// ---------------------------------------------------------------------------
// Key-committing AES-GCM (ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, V3 format).
// ---------------------------------------------------------------------------

/// HKDF output length wrapper so [`hkdf::Prk::expand`] can emit a derived key
/// of an arbitrary, suite-defined length.
struct OkmLen(usize);

impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive the encryption key and the key-commitment value for a committing
/// suite from the plaintext data key and the message ID, per
/// [Key Derivation](../../spec/s3-encryption/key-derivation.md).
///
/// Returns `(derived_encryption_key, key_commitment)`.
pub fn derive_keys(
    suite: EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    message_id: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    //= spec/s3-encryption/key-derivation.md#hkdf-operation
    //# The salt MUST be the Message ID with the length defined in the algorithm suite.
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA512, message_id);

    //= spec/s3-encryption/key-derivation.md#hkdf-operation
    //# The input keying material MUST be the plaintext data key (PDK) generated by the key provider.
    let prk = salt.extract(plaintext_data_key);

    let suite_id = suite.suite_id_bytes();

    //= spec/s3-encryption/key-derivation.md#hkdf-operation
    //# The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string DERIVEKEY as UTF8 encoded bytes.
    let dek_info: [&[u8]; 2] = [&suite_id, b"DERIVEKEY"];
    let mut derived_encryption_key = vec![0u8; suite.data_key_length()];
    prk.expand(&dek_info, OkmLen(derived_encryption_key.len()))
        .and_then(|okm| okm.fill(&mut derived_encryption_key))
        .map_err(|_| crypto_err("HKDF expand for derived encryption key failed"))?;

    //= spec/s3-encryption/key-derivation.md#hkdf-operation
    //# The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string COMMITKEY as UTF8 encoded bytes.
    let commit_info: [&[u8]; 2] = [&suite_id, b"COMMITKEY"];
    let mut commit_key = vec![0u8; suite.commitment_length()];
    prk.expand(&commit_info, OkmLen(commit_key.len()))
        .and_then(|okm| okm.fill(&mut commit_key))
        .map_err(|_| crypto_err("HKDF expand for commit key failed"))?;

    Ok((derived_encryption_key, commit_key))
}

/// Encrypt object content with `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY`.
///
/// Returns `(message_id, key_commitment, ciphertext_with_tag)`. The message ID
/// is persisted as `x-amz-i` and the key commitment as `x-amz-d`.
pub fn encrypt_content_committing(
    suite: EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    //= spec/s3-encryption/encryption.md#content-encryption
    //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
    let mut message_id = vec![0u8; suite.message_id_length()];
    rand::fill(&mut message_id).map_err(|_| crypto_err("failed to generate message ID"))?;

    //= spec/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    //# The client MUST use HKDF to derive the key commitment value and the derived encrypting key as described in [Key Derivation](key-derivation.md).
    let (derived_encryption_key, commit_key) = derive_keys(suite, plaintext_data_key, &message_id)?;

    let iv = suite.committing_iv();

    //= spec/s3-encryption/key-derivation.md#hkdf-operation
    //# The client MUST set the AAD to the Algorithm Suite ID represented as bytes.
    let aad = suite.suite_id_bytes();
    let ciphertext = aes_gcm_seal(&derived_encryption_key, &iv, &aad, plaintext)?;

    Ok((message_id, commit_key, ciphertext))
}

/// Decrypt object content encrypted with
/// `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY`, verifying the stored key
/// commitment before releasing any plaintext.
pub fn decrypt_content_committing(
    suite: EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    message_id: &[u8],
    stored_commitment: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>> {
    //= spec/s3-encryption/decryption.md#decrypting-with-commitment
    //# When using an algorithm suite which supports key commitment, the client MUST verify the key commitment values match before deriving the [derived encryption key](./key-derivation.md#hkdf-operation).
    let (derived_encryption_key, derived_commitment) =
        derive_keys(suite, plaintext_data_key, message_id)?;

    //= spec/s3-encryption/decryption.md#decrypting-with-commitment
    //# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
    //
    //= spec/s3-encryption/decryption.md#decrypting-with-commitment
    //# When using an algorithm suite which supports key commitment, the verification of the derived key commitment value MUST be done in constant time.
    //
    //= spec/s3-encryption/decryption.md#decrypting-with-commitment
    //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
    constant_time::verify_slices_are_equal(stored_commitment, &derived_commitment)
        .map_err(|_| crypto_err("key commitment verification failed"))?;

    let iv = suite.committing_iv();
    let aad = suite.suite_id_bytes();
    aes_gcm_open(&derived_encryption_key, &iv, &aad, ciphertext_with_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA_KEY: [u8; 32] = [7u8; 32];
    const COMMITTING: EncryptionAlgorithm = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;

    /// Encrypt with AES-256-CBC/PKCS7 to produce a legacy fixture, returning
    /// `(iv, ciphertext)`. Mirrors what an old S3 encryption client writes.
    fn cbc_encrypt(data_key: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use aws_lc_rs::cipher::{PaddedBlockEncryptingKey, UnboundCipherKey, AES_256};
        let unbound = UnboundCipherKey::new(&AES_256, data_key).unwrap();
        let key = PaddedBlockEncryptingKey::cbc_pkcs7(unbound).unwrap();
        let mut in_out = plaintext.to_vec();
        let context = key.encrypt(&mut in_out).unwrap();
        let iv = <&[u8]>::try_from(&context).unwrap().to_vec();
        (iv, in_out)
    }

    #[test]
    fn cbc_round_trip_recovers_plaintext() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let (iv, ct) = cbc_encrypt(&DATA_KEY, plaintext);

        // CBC uses a 16-byte IV and pads to the 16-byte block boundary.
        assert_eq!(iv.len(), 16);
        assert_eq!(ct.len() % 16, 0);

        let recovered = decrypt_content_cbc(&DATA_KEY, &iv, &ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn cbc_round_trip_handles_block_aligned_plaintext() {
        // Exactly one block: PKCS7 adds a full padding block.
        let plaintext = [0xABu8; 16];
        let (iv, ct) = cbc_encrypt(&DATA_KEY, &plaintext);
        assert_eq!(ct.len(), 32);
        let recovered = decrypt_content_cbc(&DATA_KEY, &iv, &ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn cbc_wrong_key_fails() {
        let (iv, ct) = cbc_encrypt(&DATA_KEY, b"sensitive payload");
        let wrong_key = [9u8; 32];
        let err = decrypt_content_cbc(&wrong_key, &iv, &ct).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn cbc_rejects_malformed_iv_length() {
        let (_iv, ct) = cbc_encrypt(&DATA_KEY, b"payload");
        // A 12-byte (GCM-sized) IV is not a valid CBC IV.
        let err = decrypt_content_cbc(&DATA_KEY, &[0u8; 12], &ct).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn gcm_round_trip_recovers_plaintext() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let (iv, ct) = encrypt_content_gcm(&DATA_KEY, plaintext).unwrap();

        assert_eq!(iv.len(), 12);
        // Ciphertext carries the appended 16-byte GCM tag.
        assert_eq!(ct.len(), plaintext.len() + 16);
        // The ciphertext must not equal the plaintext.
        assert_ne!(&ct[..plaintext.len()], &plaintext[..]);

        let recovered = decrypt_content_gcm(&DATA_KEY, &iv, &ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn gcm_round_trip_handles_empty_plaintext() {
        let (iv, ct) = encrypt_content_gcm(&DATA_KEY, b"").unwrap();
        assert_eq!(ct.len(), 16); // tag only
        let recovered = decrypt_content_gcm(&DATA_KEY, &iv, &ct).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn gcm_tampered_ciphertext_fails_authentication() {
        let plaintext = b"sensitive payload";
        let (iv, mut ct) = encrypt_content_gcm(&DATA_KEY, plaintext).unwrap();
        ct[0] ^= 0xFF;
        let err = decrypt_content_gcm(&DATA_KEY, &iv, &ct).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn gcm_wrong_key_fails_authentication() {
        let plaintext = b"sensitive payload";
        let (iv, ct) = encrypt_content_gcm(&DATA_KEY, plaintext).unwrap();
        let wrong_key = [9u8; 32];
        let err = decrypt_content_gcm(&wrong_key, &iv, &ct).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn derive_keys_is_deterministic_and_well_sized() {
        let message_id = [3u8; 28];
        let (dek1, ck1) = derive_keys(COMMITTING, &DATA_KEY, &message_id).unwrap();
        let (dek2, ck2) = derive_keys(COMMITTING, &DATA_KEY, &message_id).unwrap();
        assert_eq!(dek1, dek2);
        assert_eq!(ck1, ck2);
        assert_eq!(dek1.len(), 32);
        assert_eq!(ck1.len(), 28);
        // Different info strings must yield different keys.
        assert_ne!(dek1, ck1);
    }

    #[test]
    fn derive_keys_varies_with_message_id() {
        let (_, ck_a) = derive_keys(COMMITTING, &DATA_KEY, &[1u8; 28]).unwrap();
        let (_, ck_b) = derive_keys(COMMITTING, &DATA_KEY, &[2u8; 28]).unwrap();
        assert_ne!(ck_a, ck_b);
    }

    #[test]
    fn committing_round_trip_recovers_plaintext() {
        let plaintext = b"committed content payload";
        let (message_id, commit_key, ct) =
            encrypt_content_committing(COMMITTING, &DATA_KEY, plaintext).unwrap();

        assert_eq!(message_id.len(), 28);
        assert_eq!(commit_key.len(), 28);
        assert_eq!(ct.len(), plaintext.len() + 16);

        let recovered =
            decrypt_content_committing(COMMITTING, &DATA_KEY, &message_id, &commit_key, &ct)
                .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn committing_wrong_commitment_is_rejected() {
        let plaintext = b"committed content payload";
        let (message_id, mut commit_key, ct) =
            encrypt_content_committing(COMMITTING, &DATA_KEY, plaintext).unwrap();
        commit_key[0] ^= 0xFF;
        let err = decrypt_content_committing(COMMITTING, &DATA_KEY, &message_id, &commit_key, &ct)
            .unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn committing_tampered_ciphertext_fails() {
        let plaintext = b"committed content payload";
        let (message_id, commit_key, mut ct) =
            encrypt_content_committing(COMMITTING, &DATA_KEY, plaintext).unwrap();
        ct[2] ^= 0x01;
        let err = decrypt_content_committing(COMMITTING, &DATA_KEY, &message_id, &commit_key, &ct)
            .unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }
}
