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
    DecryptingKey, DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey, AES_256,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rsa::{
    OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey, OAEP_SHA1_MGF1SHA1,
};
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
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
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

/// Fill a fresh buffer of `len` cryptographically random bytes.
//= ../spec/s3-encryption/client.md#randomness
//= type=exception
//= reason=randomness is sourced from the platform CSPRNG (aws-lc-rs / ring SystemRandom); this client does not accept an injectable source-of-randomness parameter at initialization
//# The S3EC MAY accept a source of randomness during client initialization.
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    rand::fill(&mut buf).map_err(|_| crypto_err("failed to generate random bytes"))?;
    Ok(buf)
}

/// The maximum plaintext content length (in bytes) for the AES-GCM content
/// suites. AES-GCM with a 32-bit block counter can authenticate at most
/// `2^36 - 32` bytes under a single key/IV; `2^36` is the conservative limit
/// shared across the S3EC content suites.
const MAX_GCM_CONTENT_LENGTH: usize = 1 << 36;

/// Validate that a plaintext content length does not exceed the algorithm
/// suite's cipher maximum content length.
///
/// Taking the length as a `usize` (rather than the plaintext slice) keeps this
/// check exercisable without allocating a multi-gigabyte buffer.
pub fn validate_content_length(len: usize) -> Result<()> {
    //= ../spec/s3-encryption/encryption.md#content-encryption
    //# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
    if len > MAX_GCM_CONTENT_LENGTH {
        return Err(crypto_err("plaintext exceeds maximum content length"));
    }
    Ok(())
}

/// Reject an IV or Message ID that is entirely zero bytes.
///
/// An all-zero IV/Message ID is technically valid but overwhelmingly indicates
/// the value was not generated correctly, so the client refuses it.
pub fn reject_if_iv_or_message_id_is_zeros(bytes: &[u8]) -> Result<()> {
    //= ../spec/s3-encryption/encryption.md#cipher-initialization
    //# The client SHOULD validate that the generated IV or Message ID is not zeros.
    if bytes.iter().all(|&b| b == 0) {
        return Err(crypto_err("generated IV or message ID is all zeros"));
    }
    Ok(())
}

/// Generate a fresh IV or Message ID of `len` bytes and reject an all-zero
/// result. Callers pass the IV / Message ID length defined by the algorithm
/// suite (`suite.iv_length()` / `suite.message_id_length()`).
fn generate_iv_or_message_id(len: usize) -> Result<Vec<u8>> {
    //= ../spec/s3-encryption/encryption.md#content-encryption
    //= reason=`len` is the IV or Message ID length defined by the algorithm suite, supplied by the encrypt functions
    //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
    let mut buf = vec![0u8; len];
    rand::fill(&mut buf).map_err(|_| crypto_err("failed to generate IV or message ID"))?;
    reject_if_iv_or_message_id_is_zeros(&buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Raw AES-GCM data-key wrapping (RawAes keyring, "AES/GCM" wrapping algorithm).
//
// A raw AES keyring wraps the content data key with a caller-supplied AES-256
// key using AES-GCM. The wrapped form is the 12-byte GCM IV prepended to the
// GCM ciphertext (which carries the appended 16-byte tag). The AAD is the
// content-cipher value of the algorithm suite ("115" for the committing suite,
// "AES/GCM/NoPadding" for the non-committing suite), matching the canonical
// Java `AesKeyring` so wrapped keys interoperate across implementations.
// ---------------------------------------------------------------------------

/// Length of the GCM IV prepended to an AES-GCM-wrapped data key.
const AES_WRAP_IV_LEN: usize = 12;

/// Wrap a plaintext data key with a raw AES-256 key using AES-GCM, binding
/// `aad` (the suite content-cipher value) into the tag. Returns the 12-byte IV
/// prepended to the GCM ciphertext-with-tag.
pub fn wrap_data_key_aes_gcm(
    wrapping_key: &[u8],
    aad: &[u8],
    plaintext_data_key: &[u8],
) -> Result<Vec<u8>> {
    let iv = random_bytes(AES_WRAP_IV_LEN)?;
    let ciphertext = aes_gcm_seal(wrapping_key, &iv, aad, plaintext_data_key)?;
    // The wrapped data key is the IV prepended to the ciphertext.
    let mut wrapped = iv;
    wrapped.extend_from_slice(&ciphertext);
    Ok(wrapped)
}

/// Unwrap an AES-GCM-wrapped data key produced by [`wrap_data_key_aes_gcm`].
/// Splits the leading 12-byte IV from the GCM ciphertext, verifies the tag
/// (binding `aad`), and returns the recovered plaintext data key.
pub fn unwrap_data_key_aes_gcm(
    wrapping_key: &[u8],
    aad: &[u8],
    wrapped: &[u8],
) -> Result<Vec<u8>> {
    if wrapped.len() <= AES_WRAP_IV_LEN {
        return Err(crypto_err("AES-GCM wrapped data key is too short"));
    }
    let (iv, ciphertext) = wrapped.split_at(AES_WRAP_IV_LEN);
    aes_gcm_open(wrapping_key, iv, aad, ciphertext)
}

// ---------------------------------------------------------------------------
// Raw RSA-OAEP-SHA1 data-key wrapping (RawRsa keyring, "RSA-OAEP-SHA1" wrapping
// algorithm).
//
// A raw RSA keyring wraps the content data key under an RSA public key using
// RSA-OAEP with a SHA-1 hash and MGF1-SHA1 mask. The wrapped plaintext is NOT
// the bare data key: matching the canonical Java `RsaKeyring`, it is a
// "pseudo data key" framing the data key together with the content-cipher
// value so the decryptor can verify the data key was wrapped for the same
// algorithm suite:
//
//   pseudo_data_key = [1-byte data-key length] || [data key] || [content-cipher value]
//
// where the content-cipher value is the suite's `x-amz-c`/`x-amz-cek-alg`
// value ("115" for the committing suite, "AES/GCM/NoPadding" for the
// non-committing suite). The harness supplies the RSA key as the PKCS#8 DER
// encoding of the private key (`KeyPair.getPrivate().getEncoded()`); the public
// key used for wrapping is derived from it.
// ---------------------------------------------------------------------------

/// The valid raw data-key lengths (bytes) recovered from an RSA-wrapped pseudo
/// data key: AES-128, AES-192, or AES-256.
const VALID_DATA_KEY_LENGTHS: [usize; 3] = [16, 24, 32];

/// Parse and verify an RSA-unwrapped pseudo data key, returning the bare data
/// key. The leading length byte selects the data key, and the trailing
/// content-cipher bytes are compared (in constant time) against the
/// `expected_content_cipher` derived from the object's algorithm suite. A
/// mismatch means the object was altered or wrapped for a different suite.
fn parse_pseudo_data_key(pseudo: &[u8], expected_content_cipher: &[u8]) -> Result<Vec<u8>> {
    let data_key_len = *pseudo
        .first()
        .ok_or_else(|| crypto_err("RSA-wrapped data key is empty"))? as usize;
    if !VALID_DATA_KEY_LENGTHS.contains(&data_key_len) {
        return Err(crypto_err("invalid key length in RSA-wrapped data key"));
    }

    // A well-formed pseudo data key is exactly the length byte, the data key,
    // and the content-cipher bytes for the suite.
    let expected_total = 1 + data_key_len + expected_content_cipher.len();
    if pseudo.len() != expected_total {
        return Err(crypto_err(
            "RSA-wrapped data key has an unexpected length",
        ));
    }

    let data_key = &pseudo[1..1 + data_key_len];
    let content_cipher = &pseudo[1 + data_key_len..];

    // Constant-time comparison of the recorded content cipher: a mismatch means
    // the data cipher does not match the one used for encryption (the object
    // may be altered or corrupted).
    constant_time::verify_slices_are_equal(expected_content_cipher, content_cipher)
        .map_err(|_| crypto_err("the data cipher does not match the data cipher used for encryption"))?;

    Ok(data_key.to_vec())
}

/// Wrap a plaintext data key under the RSA public key derived from
/// `pkcs8_private_key` using RSA-OAEP-SHA1. `content_cipher` is the suite's
/// content-cipher value, framed into the pseudo data key (see module note).
pub fn wrap_data_key_rsa_oaep(
    pkcs8_private_key: &[u8],
    content_cipher: &[u8],
    plaintext_data_key: &[u8],
) -> Result<Vec<u8>> {
    let data_key_len = u8::try_from(plaintext_data_key.len())
        .map_err(|_| crypto_err("data key is too long to RSA-wrap"))?;

    // Build the pseudo data key: length byte || data key || content cipher.
    let mut pseudo = Vec::with_capacity(1 + plaintext_data_key.len() + content_cipher.len());
    pseudo.push(data_key_len);
    pseudo.extend_from_slice(plaintext_data_key);
    pseudo.extend_from_slice(content_cipher);

    let private = PrivateDecryptingKey::from_pkcs8(pkcs8_private_key)
        .map_err(|_| crypto_err("invalid RSA private key (expected PKCS#8 DER)"))?;
    let public = private.public_key();
    let oaep = OaepPublicEncryptingKey::new(public)
        .map_err(|_| crypto_err("failed to initialize RSA-OAEP encrypting key"))?;

    let mut ciphertext = vec![0u8; oaep.ciphertext_size()];
    let wrapped = oaep
        .encrypt(&OAEP_SHA1_MGF1SHA1, &pseudo, &mut ciphertext, None)
        .map_err(|_| crypto_err("RSA-OAEP data key wrap failed"))?;
    Ok(wrapped.to_vec())
}

/// Unwrap an RSA-OAEP-SHA1-wrapped data key with the private key in
/// `pkcs8_private_key`, verifying the framed content-cipher value against
/// `expected_content_cipher` (the object suite's content-cipher value) before
/// returning the bare data key.
pub fn unwrap_data_key_rsa_oaep(
    pkcs8_private_key: &[u8],
    expected_content_cipher: &[u8],
    wrapped: &[u8],
) -> Result<Vec<u8>> {
    let private = PrivateDecryptingKey::from_pkcs8(pkcs8_private_key)
        .map_err(|_| crypto_err("invalid RSA private key (expected PKCS#8 DER)"))?;
    let oaep = OaepPrivateDecryptingKey::new(private)
        .map_err(|_| crypto_err("failed to initialize RSA-OAEP decrypting key"))?;

    let mut plaintext = vec![0u8; oaep.key_size_bytes()];
    let pseudo = oaep
        .decrypt(&OAEP_SHA1_MGF1SHA1, wrapped, &mut plaintext, None)
        .map_err(|_| crypto_err("RSA-OAEP data key unwrap failed"))?;

    parse_pseudo_data_key(pseudo, expected_content_cipher)
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

    validate_content_length(plaintext.len())?;

    let iv = generate_iv_or_message_id(suite.iv_length())?;

    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    //# The client MUST initialize the cipher, or call an AES-GCM encryption API, with the plaintext data key, the generated IV, and the tag length defined in the Algorithm Suite when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
    //
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    //# The client MUST NOT provide any AAD when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
    let ciphertext = aes_gcm_seal(data_key, &iv, &[], plaintext)?;

    //= ../spec/s3-encryption/encryption.md#content-encryption
    //= reason=the returned IV is persisted as the x-amz-iv content metadata field by the caller
    //# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
    Ok((iv, ciphertext))
}

/// Decrypt object content encrypted with `ALG_AES_256_GCM_IV12_TAG16_NO_KDF`.
pub fn decrypt_content_gcm(
    data_key: &[u8],
    iv: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>> {
    // No AAD is provided for the non-committing GCM suite, mirroring the
    // encrypt path (see `encrypt_content_gcm`).
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
    //= ../spec/s3-encryption/decryption.md#cbc-decryption
    //# If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and [legacy unauthenticated algorithm suites](#legacy-decryption) is enabled,
    //# then the S3EC MUST create a cipher with AES in CBC Mode with PKCS5Padding or PKCS7Padding compatible padding for a 16-byte block cipher (example: for the Java JCE, this is "AES/CBC/PKCS5Padding").
    let unbound = UnboundCipherKey::new(&AES_256, data_key)
        .map_err(|_| crypto_err("invalid AES-256-CBC key"))?;
    let key = PaddedBlockDecryptingKey::cbc_pkcs7(unbound)
        //= ../spec/s3-encryption/decryption.md#cbc-decryption
        //# If the cipher object cannot be created as described above,
        //# Decryption MUST fail.
        //
        //= ../spec/s3-encryption/decryption.md#cbc-decryption
        //= type=exception
        //= reason=aws-lc-rs supports AES-CBC with PKCS7 padding, so the cipher-initialization failure this SHOULD describes (the crypto provider lacking CBC/PKCS5Padding support) cannot arise
        //# The error SHOULD detail why the cipher could not be initialized
        //# (such as CBC or PKCS5Padding is not supported by the underlying crypto provider).
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
    // The key derivation input length for the committing suite is the suite's
    // data-key length (the plaintext data key fed to HKDF is the AES-256 key).
    if plaintext_data_key.len() != suite.data_key_length() {
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //# - The length of the input keying material MUST equal the key derivation input length specified by the algorithm suite commit key derivation setting.
        return Err(crypto_err(
            "plaintext data key length does not match the key derivation input length",
        ));
    }

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The hash function MUST be specified by the algorithm suite commitment settings.
    //
    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The salt MUST be the Message ID with the length defined in the algorithm suite.
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA512, message_id);

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The input keying material MUST be the plaintext data key (PDK) generated by the key provider.
    let prk = salt.extract(plaintext_data_key);

    let suite_id = suite.suite_id_bytes();

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string DERIVEKEY as UTF8 encoded bytes.
    let dek_info: [&[u8]; 2] = [&suite_id, b"DERIVEKEY"];

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The length of the output keying material MUST equal the encryption key length specified by the algorithm suite encryption settings.
    let mut derived_encryption_key = vec![0u8; suite.data_key_length()];

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The DEK input pseudorandom key MUST be the output from the extract step.
    prk.expand(&dek_info, OkmLen(derived_encryption_key.len()))
        .and_then(|okm| okm.fill(&mut derived_encryption_key))
        .map_err(|_| crypto_err("HKDF expand for derived encryption key failed"))?;

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string COMMITKEY as UTF8 encoded bytes.
    let commit_info: [&[u8]; 2] = [&suite_id, b"COMMITKEY"];

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The length of the output keying material MUST equal the commit key length specified by the supported algorithm suites.
    let mut commit_key = vec![0u8; suite.commitment_length()];

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# - The CK input pseudorandom key MUST be the output from the extract step.
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
    validate_content_length(plaintext.len())?;

    let message_id = generate_iv_or_message_id(suite.message_id_length())?;

    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    //# The client MUST use HKDF to derive the key commitment value and the derived encrypting key as described in [Key Derivation](key-derivation.md).
    let (derived_encryption_key, commit_key) = derive_keys(suite, plaintext_data_key, &message_id)?;

    let iv = suite.committing_iv();

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# The client MUST set the AAD to the Algorithm Suite ID represented as bytes.
    let aad = suite.suite_id_bytes();

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# The client MUST initialize the cipher, or call an AES-GCM encryption API, with the derived encryption key, an IV containing only bytes with the value 0x01,
    //# and the tag length defined in the Algorithm Suite when encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.
    //
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    //# The client MUST append the GCM auth tag to the ciphertext if the underlying crypto provider does not do so automatically.
    let ciphertext = aes_gcm_seal(&derived_encryption_key, &iv, &aad, plaintext)?;

    //= ../spec/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    //# The derived key commitment value MUST be set or returned from the encryption process such that it can be included in the content metadata.
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
    //= ../spec/s3-encryption/decryption.md#decrypting-with-commitment
    //= type=implication
    //= reason=the derived encryption key is never applied: aes_gcm_open below is unreachable unless verify_slices_are_equal succeeds via `?`, so an unverified key cannot be used to decrypt
    //# When using an algorithm suite which supports key commitment, the client MUST verify the key commitment values match before deriving the [derived encryption key](./key-derivation.md#hkdf-operation).
    let (derived_encryption_key, derived_commitment) =
        derive_keys(suite, plaintext_data_key, message_id)?;

    //= ../spec/s3-encryption/decryption.md#decrypting-with-commitment
    //# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
    //
    //= ../spec/s3-encryption/decryption.md#decrypting-with-commitment
    //= type=implication
    //= reason=verification uses aws-lc-rs constant_time::verify_slices_are_equal, which compares in constant time by construction
    //# When using an algorithm suite which supports key commitment, the verification of the derived key commitment value MUST be done in constant time.
    //
    //= ../spec/s3-encryption/decryption.md#decrypting-with-commitment
    //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
    constant_time::verify_slices_are_equal(stored_commitment, &derived_commitment)
        .map_err(|_| crypto_err("key commitment verification failed"))?;

    let iv = suite.committing_iv();
    let aad = suite.suite_id_bytes();
    aes_gcm_open(&derived_encryption_key, &iv, &aad, ciphertext_with_tag)
}

// ---------------------------------------------------------------------------
// AES-CTR content encryption is unsupported.
//
// The CTR algorithm suites (ALG_AES_256_CTR_IV16_TAG16_NO_KDF and
// ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY) exist only to decrypt *ranges* of an
// object that was encrypted with the corresponding AES-GCM suite (see
// `decrypt_range_ctr`). They are never used to encrypt, so any attempt to do
// so fails unconditionally.
// ---------------------------------------------------------------------------

/// Attempting to encrypt content with `ALG_AES_256_CTR_IV16_TAG16_NO_KDF`
/// always fails: AES-CTR is a decrypt-only (ranged-get) suite.
pub fn encrypt_content_ctr(_data_key: &[u8], _plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-ctr-iv16-tag16-no-kdf
    //# Attempts to encrypt using AES-CTR MUST fail.
    Err(crypto_err("encryption using AES-CTR is not supported"))
}

/// Attempting to encrypt content with `ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY`
/// always fails: key-committing AES-CTR is a decrypt-only (ranged-get) suite.
pub fn encrypt_content_committing_ctr(
    _data_key: &[u8],
    _plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    //= ../spec/s3-encryption/encryption.md#alg-aes-256-ctr-hkdf-sha512-commit-key
    //# Attempts to encrypt using key committing AES-CTR MUST fail.
    Err(crypto_err(
        "encryption using key committing AES-CTR is not supported",
    ))
}

// ---------------------------------------------------------------------------
// Ranged Gets (partial content decryption).
//
// A ranged GetObject returns a subset of the object's plaintext bytes. Because
// only part of the ciphertext is available (or, when the whole object is held
// in memory, because the whole-object GCM tag does not cover an arbitrary
// sub-range), an authenticated GCM suite cannot verify its tag over a range.
// The spec therefore mandates decrypting the range with the corresponding
// CTR-based algorithm suite. AES-GCM encryption is AES-CTR under the hood, so
// the same content key reproduces the keystream when started from the GCM
// counter block (J0) for the first requested plaintext block.
// ---------------------------------------------------------------------------

/// The number of bytes covered by a single AES cipher block.
const AES_BLOCK_LEN: usize = 16;

/// Decrypt an inclusive plaintext byte range `[start, end_inclusive]` of
/// GCM-encrypted `content` (the ciphertext body, with the trailing GCM tag
/// already removed) using AES-CTR.
///
/// `iv` is the 12-byte GCM IV. The AES-GCM counter for plaintext block `i`
/// (0-indexed) is `inc32` applied `i + 1` times to the pre-counter block
/// `J0 = iv || 0x0000_0001`, i.e. a counter value of `i + 2` in the trailing
/// 32 bits. To decrypt a byte that falls inside block `b`, the keystream must
/// begin at that block boundary, so the range is widened down to `b * 16`
/// before applying CTR and the partial-block prefix is then discarded.
pub fn decrypt_range_ctr(
    key: &[u8],
    iv: &[u8],
    content: &[u8],
    start: usize,
    end_inclusive: usize,
) -> Result<Vec<u8>> {
    if iv.len() != 12 {
        return Err(crypto_err(
            "ranged GCM decryption requires a 12-byte GCM IV",
        ));
    }
    if content.is_empty() || start >= content.len() || start > end_inclusive {
        return Ok(Vec::new());
    }
    // The customer range is clamped to the available plaintext (the ciphertext
    // body length equals the plaintext length for the stream-cipher suites).
    let end_inclusive = end_inclusive.min(content.len() - 1);

    //= ../spec/s3-encryption/decryption.md#ranged-gets
    //# If the S3EC supports Ranged Gets, the S3EC MUST adjust the customer-provided range to include the beginning and end of the cipher blocks for the given range.
    let block_index = start / AES_BLOCK_LEN;
    let aligned_start = block_index * AES_BLOCK_LEN;

    // GCM counter for plaintext block `block_index` is `block_index + 2` in the
    // trailing 32-bit counter field (J0 counter is 1; the first plaintext block
    // uses J0 + 1). Objects in scope never wrap the 32-bit counter; use wrapping
    // arithmetic defensively.
    let counter = u32::try_from(block_index)
        .unwrap_or(u32::MAX)
        .wrapping_add(2);
    let mut counter_block = [0u8; AES_BLOCK_LEN];
    counter_block[..12].copy_from_slice(iv);
    counter_block[12..].copy_from_slice(&counter.to_be_bytes());

    let mut buf = content[aligned_start..=end_inclusive].to_vec();

    let unbound =
        UnboundCipherKey::new(&AES_256, key).map_err(|_| crypto_err("invalid AES-256 key"))?;
    let decrypting_key =
        DecryptingKey::ctr(unbound).map_err(|_| crypto_err("failed to initialize AES-CTR cipher"))?;
    let context: FixedLength<16> = counter_block
        .as_slice()
        .try_into()
        .map_err(|_| crypto_err("invalid AES-CTR counter block"))?;
    let plaintext = decrypting_key
        .decrypt(&mut buf, DecryptionContext::Iv128(context))
        .map_err(|_| crypto_err("AES-CTR decryption failed"))?;

    // Discard the partial-block prefix introduced by aligning down to the block
    // boundary, leaving exactly the requested `[start, end_inclusive]` bytes.
    let prefix = start - aligned_start;
    Ok(plaintext[prefix..].to_vec())
}

/// Decrypt an inclusive plaintext byte range of key-committing
/// (`ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY`) content using the corresponding
/// CTR suite, after verifying the stored key commitment.
///
/// `content` is the ciphertext body with the trailing GCM tag removed.
pub fn decrypt_range_committing(
    suite: EncryptionAlgorithm,
    plaintext_data_key: &[u8],
    message_id: &[u8],
    stored_commitment: &[u8],
    content: &[u8],
    start: usize,
    end_inclusive: usize,
) -> Result<Vec<u8>> {
    let (derived_encryption_key, derived_commitment) =
        derive_keys(suite, plaintext_data_key, message_id)?;

    constant_time::verify_slices_are_equal(stored_commitment, &derived_commitment)
        .map_err(|_| crypto_err("key commitment verification failed"))?;

    //= ../spec/s3-encryption/decryption.md#ranged-gets
    //# If the object was encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, then ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY MUST be used to decrypt the range of the object.
    let iv = suite.committing_iv();
    decrypt_range_ctr(&derived_encryption_key, &iv, content, start, end_inclusive)
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

        //= ../spec/s3-encryption/decryption.md#cbc-decryption
        //= type=test
        //= reason=decrypting a CBC/PKCS7 fixture recovers the exact plaintext, proving an AES-CBC cipher with PKCS7 padding for a 16-byte block was created
        //# If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and [legacy unauthenticated algorithm suites](#legacy-decryption) is enabled,
        //# then the S3EC MUST create a cipher with AES in CBC Mode with PKCS5Padding or PKCS7Padding compatible padding for a 16-byte block cipher (example: for the Java JCE, this is "AES/CBC/PKCS5Padding").
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
        //= ../spec/s3-encryption/decryption.md#cbc-decryption
        //= type=test
        //= reason=a malformed 12-byte IV cannot initialize the 16-byte-block CBC cipher context, so decryption fails
        //# If the cipher object cannot be created as described above,
        //# Decryption MUST fail.
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
        //= ../spec/s3-encryption/decryption.md#decrypting-with-commitment
        //= type=test
        //= reason=mutating the stored commitment makes it differ from the derived commitment, and decrypt is rejected, proving the derived value is compared against the stored bytes
        //# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
        //
        //= ../spec/s3-encryption/decryption.md#decrypting-with-commitment
        //= type=test
        //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
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

    /// Independent RFC 5869 HKDF-SHA512 built directly from the HMAC-SHA512
    /// primitive — deliberately NOT the `hkdf` module under test — so the
    /// derived-key tests assert against an external authority. Only a single
    /// expand block is needed since every output here is <= 64 bytes.
    fn rfc5869_hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        use aws_lc_rs::hmac;
        assert!(len <= 64, "test helper only supports a single HKDF expand block");
        // Extract: PRK = HMAC-SHA512(salt, IKM).
        let prk = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, salt), ikm);
        // Expand: T(1) = HMAC-SHA512(PRK, info || 0x01); OKM = first `len` bytes.
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, prk.as_ref()));
        ctx.update(info);
        ctx.update(&[0x01]);
        ctx.sign().as_ref()[..len].to_vec()
    }

    #[test]
    fn derive_keys_matches_rfc5869_hkdf_sha512() {
        let message_id = [0x42u8; 28];
        let pdk = DATA_KEY;
        let suite_id = COMMITTING.suite_id_bytes();

        let mut dek_info = suite_id.clone();
        dek_info.extend_from_slice(b"DERIVEKEY");
        let mut ck_info = suite_id.clone();
        ck_info.extend_from_slice(b"COMMITKEY");

        // Authority values computed independently of the `hkdf` module.
        let expected_dek = rfc5869_hkdf_sha512(&message_id, &pdk, &dek_info, 32);
        let expected_ck = rfc5869_hkdf_sha512(&message_id, &pdk, &ck_info, 28);

        let (dek, ck) = derive_keys(COMMITTING, &pdk, &message_id).unwrap();

        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=DEK matches independent HKDF-SHA512; a different hash function changes these bytes
        //# - The hash function MUST be specified by the algorithm suite commitment settings.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=independent HKDF uses the PDK as IKM; a different IKM changes these bytes
        //# - The input keying material MUST be the plaintext data key (PDK) generated by the key provider.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=independent HKDF uses the message ID as salt; a different salt changes these bytes
        //# - The salt MUST be the Message ID with the length defined in the algorithm suite.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=independent HKDF expands the extract-step PRK; a different PRK changes these bytes
        //# - The DEK input pseudorandom key MUST be the output from the extract step.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=expected DEK is 32 bytes (encryption key length); a different length fails this equality
        //# - The length of the output keying material MUST equal the encryption key length specified by the algorithm suite encryption settings.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=independent HKDF info is suite ID then "DERIVEKEY"; different info changes these bytes
        //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string DERIVEKEY as UTF8 encoded bytes.
        assert_eq!(dek, expected_dek, "DEK must match independent HKDF-SHA512");

        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=independent HKDF expands the extract-step PRK; a different PRK changes these bytes
        //# - The CK input pseudorandom key MUST be the output from the extract step.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=expected CK is 28 bytes (commit key length); a different length fails this equality
        //# - The length of the output keying material MUST equal the commit key length specified by the supported algorithm suites.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=independent HKDF info is suite ID then "COMMITKEY"; different info changes these bytes
        //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string COMMITKEY as UTF8 encoded bytes.
        assert_eq!(ck, expected_ck, "commit key must match independent HKDF-SHA512");
    }

    #[test]
    fn derive_keys_rejects_pdk_of_wrong_length() {
        let message_id = [5u8; 28];
        let correct_pdk = DATA_KEY; // 32 bytes == key derivation input length
        let wrong_pdk = [7u8; 31]; // 31 bytes != key derivation input length

        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=a PDK whose length equals the derivation input length derives; any other length is rejected
        //# - The length of the input keying material MUST equal the key derivation input length specified by the algorithm suite commit key derivation setting.
        assert!(
            derive_keys(COMMITTING, &correct_pdk, &message_id).is_ok(),
            "PDK with the correct length must derive"
        );
        assert!(
            matches!(
                derive_keys(COMMITTING, &wrong_pdk, &message_id).unwrap_err(),
                S3EncryptionError::Crypto(_)
            ),
            "PDK with the wrong length must be rejected"
        );
    }

    #[test]
    fn committing_encrypt_uses_derived_key_ones_iv_and_suite_id_aad() {
        let plaintext = b"committed content payload";
        let (message_id, _commit_key, ct) =
            encrypt_content_committing(COMMITTING, &DATA_KEY, plaintext).unwrap();

        // Independently reconstruct the AEAD inputs the encryptor must have used.
        let (derived_key, _) = derive_keys(COMMITTING, &DATA_KEY, &message_id).unwrap();
        let ones_iv = vec![0x01u8; COMMITTING.iv_length()];
        let suite_id_aad = COMMITTING.suite_id_bytes();

        // The GCM tag (tag length bytes) is appended to the ciphertext.
        assert_eq!(ct.len(), plaintext.len() + COMMITTING.tag_length());

        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=opening with the derived key + all-0x01 IV recovers plaintext; a different key or IV fails GCM authentication
        //# The client MUST initialize the cipher, or call an AES-GCM encryption API, with the derived encryption key, an IV containing only bytes with the value 0x01,
        //# and the tag length defined in the Algorithm Suite when encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.
        assert_eq!(
            aes_gcm_open(&derived_key, &ones_iv, &suite_id_aad, &ct).unwrap(),
            plaintext.to_vec(),
            "derived key + all-0x01 IV must open the committing ciphertext"
        );

        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //= reason=the suite-ID AAD opens the ciphertext (above); any other AAD fails GCM auth, proving the seal bound the suite ID
        //# The client MUST set the AAD to the Algorithm Suite ID represented as bytes.
        assert!(
            matches!(
                aes_gcm_open(&derived_key, &ones_iv, b"not-the-suite-id", &ct).unwrap_err(),
                S3EncryptionError::Crypto(_)
            ),
            "an AAD other than the suite ID must fail authentication"
        );
    }

    const WRAP_KEY: [u8; 32] = [0x5Au8; 32];

    #[test]
    fn aes_gcm_data_key_wrap_round_trips() {
        let aad = b"115";
        let wrapped = wrap_data_key_aes_gcm(&WRAP_KEY, aad, &DATA_KEY).unwrap();
        // 12-byte IV + 32-byte key + 16-byte tag.
        assert_eq!(wrapped.len(), 12 + 32 + 16);
        let recovered = unwrap_data_key_aes_gcm(&WRAP_KEY, aad, &wrapped).unwrap();
        assert_eq!(recovered, DATA_KEY);
    }

    #[test]
    fn aes_gcm_data_key_unwrap_rejects_mismatched_aad() {
        // The AAD binds the algorithm-suite content-cipher value; unwrapping
        // with a different suite's AAD must fail the GCM tag check.
        let wrapped = wrap_data_key_aes_gcm(&WRAP_KEY, b"115", &DATA_KEY).unwrap();
        let err = unwrap_data_key_aes_gcm(&WRAP_KEY, b"AES/GCM/NoPadding", &wrapped).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn aes_gcm_data_key_unwrap_rejects_wrong_key() {
        let wrapped = wrap_data_key_aes_gcm(&WRAP_KEY, b"115", &DATA_KEY).unwrap();
        let err = unwrap_data_key_aes_gcm(&[0x11u8; 32], b"115", &wrapped).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn aes_gcm_data_key_unwrap_rejects_truncated_input() {
        let err = unwrap_data_key_aes_gcm(&WRAP_KEY, b"115", &[0u8; 8]).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    // ---- Raw RSA-OAEP-SHA1 data-key wrapping ------------------------------

    /// Build a PKCS#8 RSA private key at runtime via aws-lc-rs, mirroring the
    /// PKCS#8 DER blob the harness supplies (`KeyPair.getPrivate().getEncoded()`).
    fn rsa_key_for_test() -> Vec<u8> {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
        let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        key.as_der().unwrap().as_ref().to_vec()
    }

    #[test]
    fn rsa_oaep_data_key_wrap_round_trips_committing() {
        let pkcs8 = rsa_key_for_test();
        // The committing suite frames "115" as the content cipher.
        let content_cipher = b"115";
        let wrapped = wrap_data_key_rsa_oaep(&pkcs8, content_cipher, &DATA_KEY).unwrap();
        // RSA-OAEP ciphertext is the modulus size (256 bytes for RSA-2048).
        assert_eq!(wrapped.len(), 256);
        let recovered = unwrap_data_key_rsa_oaep(&pkcs8, content_cipher, &wrapped).unwrap();
        assert_eq!(recovered, DATA_KEY);
    }

    #[test]
    fn rsa_oaep_data_key_wrap_round_trips_non_committing() {
        let pkcs8 = rsa_key_for_test();
        let content_cipher = b"AES/GCM/NoPadding";
        let wrapped = wrap_data_key_rsa_oaep(&pkcs8, content_cipher, &DATA_KEY).unwrap();
        let recovered = unwrap_data_key_rsa_oaep(&pkcs8, content_cipher, &wrapped).unwrap();
        assert_eq!(recovered, DATA_KEY);
    }

    #[test]
    fn rsa_oaep_unwrap_rejects_content_cipher_mismatch() {
        // Wrapping under one suite's content cipher and unwrapping while
        // expecting another must fail: the framed cipher value will not match.
        let pkcs8 = rsa_key_for_test();
        let wrapped = wrap_data_key_rsa_oaep(&pkcs8, b"115", &DATA_KEY).unwrap();
        let err = unwrap_data_key_rsa_oaep(&pkcs8, b"AES/GCM/NoPadding", &wrapped).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn rsa_oaep_unwrap_rejects_wrong_key() {
        let pkcs8 = rsa_key_for_test();
        let other = rsa_key_for_test();
        let wrapped = wrap_data_key_rsa_oaep(&pkcs8, b"115", &DATA_KEY).unwrap();
        // A different private key cannot OAEP-decrypt the ciphertext.
        let err = unwrap_data_key_rsa_oaep(&other, b"115", &wrapped).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn rsa_oaep_rejects_invalid_pkcs8() {
        let err = wrap_data_key_rsa_oaep(b"not a pkcs8 key", b"115", &DATA_KEY).unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    #[test]
    fn parse_pseudo_data_key_rejects_bad_length_byte() {
        // A length byte that is not a valid AES key length is rejected.
        let mut pseudo = vec![20u8]; // 20 is not 16/24/32
        pseudo.extend_from_slice(&[0u8; 20]);
        pseudo.extend_from_slice(b"115");
        let err = parse_pseudo_data_key(&pseudo, b"115").unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }

    // ---- Ranged Gets (CTR-based partial decryption) -----------------------

    /// A multi-block plaintext so that ranges can straddle block boundaries.
    fn ranged_plaintext() -> Vec<u8> {
        (0..=200u8).collect()
    }

    /// AES-CTR decryption of a range of GCM content must reproduce the exact
    /// plaintext slice that whole-object GCM decryption would yield. This
    /// validates the GCM counter-block arithmetic without needing S3 or KMS.
    #[test]
    fn gcm_ranged_matches_plaintext_slice() {
        let plaintext = ranged_plaintext();
        let (iv, ct) = encrypt_content_gcm(&DATA_KEY, &plaintext).unwrap();
        let content = &ct[..ct.len() - 16]; // strip the appended GCM tag

        // start, end (inclusive), and whole-file ranges, including block-aligned,
        // mid-block, and cross-block cases.
        let cases = [(0usize, 5usize), (5, 10), (10, 100), (15, 17), (16, 47), (0, plaintext.len() - 1), (200, 200)];
        for (start, end) in cases {
            let ranged = decrypt_range_ctr(&DATA_KEY, &iv, content, start, end).unwrap();
            //= ../spec/s3-encryption/decryption.md#ranged-gets
            //= type=test
            //= reason=mid-block start ranges (e.g. [15,17] and [16,47]) decrypt to the exact plaintext slice, proving the range was widened to the enclosing cipher-block boundaries
            //# If the S3EC supports Ranged Gets, the S3EC MUST adjust the customer-provided range to include the beginning and end of the cipher blocks for the given range.
            assert_eq!(
                ranged,
                &plaintext[start..=end],
                "GCM ranged decrypt mismatch for [{start}, {end}]"
            );
        }
    }

    /// A range whose end is clamped to the end of the content (the harness
    /// "Include tag" case requests a range beyond the plaintext length).
    #[test]
    fn gcm_ranged_clamps_end_to_content() {
        let plaintext = ranged_plaintext();
        let (iv, ct) = encrypt_content_gcm(&DATA_KEY, &plaintext).unwrap();
        let content = &ct[..ct.len() - 16];
        let ranged = decrypt_range_ctr(&DATA_KEY, &iv, content, 10, 1000).unwrap();
        assert_eq!(ranged, &plaintext[10..]);
    }

    /// Committing-suite (KC-GCM) ranged decrypt must match the plaintext slice
    /// and must reject a mutated commitment before releasing any plaintext.
    #[test]
    fn committing_ranged_matches_plaintext_slice() {
        let plaintext = ranged_plaintext();
        let (message_id, commit_key, ct) =
            encrypt_content_committing(COMMITTING, &DATA_KEY, &plaintext).unwrap();
        let content = &ct[..ct.len() - 16];

        for (start, end) in [(0usize, 5usize), (5, 10), (16, 100), (0, plaintext.len() - 1)] {
            let ranged = decrypt_range_committing(
                COMMITTING, &DATA_KEY, &message_id, &commit_key, content, start, end,
            )
            .unwrap();
            //= ../spec/s3-encryption/decryption.md#ranged-gets
            //= type=test
            //= reason=a committing GCM-HKDF object's range decrypts to the exact plaintext slice via the committing CTR suite (decrypt_range_committing)
            //# If the object was encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, then ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY MUST be used to decrypt the range of the object.
            assert_eq!(ranged, &plaintext[start..=end]);
        }
    }

    #[test]
    fn committing_ranged_rejects_mutated_commitment() {
        let plaintext = ranged_plaintext();
        let (message_id, mut commit_key, ct) =
            encrypt_content_committing(COMMITTING, &DATA_KEY, &plaintext).unwrap();
        let content = ct[..ct.len() - 16].to_vec();
        commit_key[0] ^= 0xFF;
        let err = decrypt_range_committing(
            COMMITTING, &DATA_KEY, &message_id, &commit_key, &content, 0, 10,
        )
        .unwrap_err();
        assert!(matches!(err, S3EncryptionError::Crypto(_)));
    }
}
