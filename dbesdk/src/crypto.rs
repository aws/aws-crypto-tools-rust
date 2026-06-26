// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Thin wrappers over `aws-lc-rs` for the primitives the item encryptor needs:
//! AES-GCM authenticated encryption, HKDF-SHA384 key derivation, HMAC-SHA384
//! signing, and CSPRNG byte generation.
//!
//! `aws-lc-rs` is the same FIPS-capable crypto provider the native MPL crate
//! uses; this module isolates its API so the encryptor reads in domain terms.

use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_192_GCM, AES_256_GCM, NONCE_LEN,
};
use aws_lc_rs::hkdf::{Salt, HKDF_SHA384};
use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::error::{DbEsdkError, Result};

/// AES-GCM nonce length (12 bytes) and tag length (16 bytes), fixed by the
/// `*_GCM_IV12_TAG16` algorithms this crate uses.
pub const GCM_NONCE_LEN: usize = NONCE_LEN;
/// AES-GCM authentication tag length in bytes.
pub const GCM_TAG_LEN: usize = 16;

/// Fill `buf` with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| DbEsdkError::crypto("failed to obtain random bytes"))
}

/// Generate `len` cryptographically secure random bytes.
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    fill_random(&mut buf)?;
    Ok(buf)
}

fn unbound_key(key_bytes: &[u8]) -> Result<UnboundKey> {
    let algorithm = match key_bytes.len() {
        16 => &AES_128_GCM,
        24 => &AES_192_GCM,
        32 => &AES_256_GCM,
        other => {
            return Err(DbEsdkError::crypto(format!(
                "unsupported AES key length {other} (expected 16, 24, or 32)"
            )))
        }
    };
    UnboundKey::new(algorithm, key_bytes)
        .map_err(|_| DbEsdkError::crypto("failed to construct AES-GCM key"))
}

/// AES-GCM seal: returns `nonce || ciphertext || tag`.
///
/// A fresh random nonce is generated for each call; callers MUST use a unique
/// key/nonce pair, which a random 96-bit nonce satisfies for the small message
/// counts here.
pub fn aes_gcm_seal(key_bytes: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = LessSafeKey::new(unbound_key(key_bytes)?);

    let mut nonce_bytes = [0u8; GCM_NONCE_LEN];
    fill_random(&mut nonce_bytes)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| DbEsdkError::crypto("AES-GCM seal failed"))?;

    let mut out = Vec::with_capacity(GCM_NONCE_LEN + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// AES-GCM open of a buffer produced by [`aes_gcm_seal`]
/// (`nonce || ciphertext || tag`). Returns the recovered plaintext.
pub fn aes_gcm_open(key_bytes: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        return Err(DbEsdkError::crypto(
            "AES-GCM ciphertext is too short to contain a nonce and tag",
        ));
    }
    let key = LessSafeKey::new(unbound_key(key_bytes)?);

    let (nonce_bytes, ciphertext) = sealed.split_at(GCM_NONCE_LEN);
    let mut nonce_array = [0u8; GCM_NONCE_LEN];
    nonce_array.copy_from_slice(nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_array);

    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| DbEsdkError::crypto("AES-GCM open failed (authentication tag mismatch)"))?;
    Ok(plaintext.to_vec())
}

/// HKDF-SHA384 extract-and-expand: derive `out_len` bytes from `ikm` using the
/// given `info` label (and no salt).
pub fn hkdf_sha384(ikm: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    struct OkmLen(usize);
    impl aws_lc_rs::hkdf::KeyType for OkmLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    let prk = Salt::new(HKDF_SHA384, &[]).extract(ikm);
    let info_components = [info];
    let okm = prk
        .expand(&info_components, OkmLen(out_len))
        .map_err(|_| DbEsdkError::crypto("HKDF expand failed"))?;
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out)
        .map_err(|_| DbEsdkError::crypto("HKDF fill failed"))?;
    Ok(out)
}

/// Compute an HMAC-SHA384 tag over `data` with `key_bytes`.
pub fn hmac_sha384(key_bytes: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA384, key_bytes);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// Constant-time verify of an HMAC-SHA384 tag over `data`.
pub fn hmac_sha384_verify(key_bytes: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()> {
    let key = hmac::Key::new(hmac::HMAC_SHA384, key_bytes);
    hmac::verify(&key, data, expected_tag)
        .map_err(|_| DbEsdkError::crypto("HMAC verification failed (signature mismatch)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_round_trips_and_detects_tampering() {
        let key = random_bytes(32).unwrap();
        let aad = b"attr-name";
        let plaintext = b"top-secret-value";

        let mut sealed = aes_gcm_seal(&key, aad, plaintext).unwrap();
        let opened = aes_gcm_open(&key, aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);

        // Flipping a ciphertext byte must fail authentication.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(aes_gcm_open(&key, aad, &sealed).is_err());
    }

    #[test]
    fn aes_gcm_open_fails_under_wrong_aad() {
        let key = random_bytes(32).unwrap();
        let sealed = aes_gcm_seal(&key, b"aad-1", b"data").unwrap();
        assert!(aes_gcm_open(&key, b"aad-2", &sealed).is_err());
    }

    #[test]
    fn hkdf_is_deterministic_and_label_separated() {
        let ikm = [7u8; 32];
        let a = hkdf_sha384(&ikm, b"label-a", 32).unwrap();
        let b = hkdf_sha384(&ikm, b"label-a", 32).unwrap();
        let c = hkdf_sha384(&ikm, b"label-b", 32).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn hmac_round_trips_and_detects_tampering() {
        let key = [3u8; 48];
        let tag = hmac_sha384(&key, b"signed-content");
        hmac_sha384_verify(&key, b"signed-content", &tag).unwrap();
        assert!(hmac_sha384_verify(&key, b"tampered", &tag).is_err());
    }
}
