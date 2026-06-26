// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Thin wrappers over `aws-lc-rs` for the primitives the item encryptor needs:
//! AES-GCM authenticated encryption, HKDF-SHA384 key derivation, HMAC-SHA384
//! signing, CSPRNG byte generation, plus the asymmetric primitives the raw
//! asymmetric keyrings drive — RSA-OAEP / PKCS#1 data-key wrapping and ECDH
//! static key agreement.
//!
//! `aws-lc-rs` is the same FIPS-capable crypto provider the native MPL crate
//! uses; this module isolates its API so the keyrings read in domain terms.

use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_192_GCM, AES_256_GCM, NONCE_LEN,
};
use aws_lc_rs::agreement::{
    self, agree, PrivateKey as EcdhPrivateKey, UnparsedPublicKey, ECDH_P256, ECDH_P384, ECDH_P521,
};
use aws_lc_rs::hkdf::{Salt, HKDF_SHA384};
use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::rsa::{
    OaepAlgorithm, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, Pkcs1PrivateDecryptingKey,
    Pkcs1PublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey, OAEP_SHA1_MGF1SHA1,
    OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
};

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

// =============================================================================
// RSA data-key wrapping (Raw RSA keyring)
// =============================================================================

/// The RSA padding scheme used to wrap a data key (the crypto-layer mirror of
/// the configured `PaddingScheme`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    /// RSA PKCS#1 v1.5 padding.
    Pkcs1,
    /// RSA-OAEP with SHA-1 (hash and MGF1).
    OaepSha1,
    /// RSA-OAEP with SHA-256 (hash and MGF1).
    OaepSha256,
    /// RSA-OAEP with SHA-384 (hash and MGF1).
    OaepSha384,
    /// RSA-OAEP with SHA-512 (hash and MGF1).
    OaepSha512,
}

impl RsaPadding {
    /// The matching `aws-lc-rs` OAEP algorithm, or `None` for PKCS#1 v1.5.
    fn oaep_algorithm(self) -> Option<&'static OaepAlgorithm> {
        match self {
            Self::Pkcs1 => None,
            Self::OaepSha1 => Some(&OAEP_SHA1_MGF1SHA1),
            Self::OaepSha256 => Some(&OAEP_SHA256_MGF1SHA256),
            Self::OaepSha384 => Some(&OAEP_SHA384_MGF1SHA384),
            Self::OaepSha512 => Some(&OAEP_SHA512_MGF1SHA512),
        }
    }
}

/// Encrypt (wrap) `plaintext` under an RSA public key supplied as DER-encoded
/// X.509 `SubjectPublicKeyInfo` bytes, using `padding`.
pub fn rsa_encrypt(public_key_der: &[u8], padding: RsaPadding, plaintext: &[u8]) -> Result<Vec<u8>> {
    let public_key = PublicEncryptingKey::from_der(public_key_der)
        .map_err(|_| DbEsdkError::crypto("invalid RSA public key (expected DER X.509 SPKI)"))?;

    match padding.oaep_algorithm() {
        None => {
            let key = Pkcs1PublicEncryptingKey::new(public_key)
                .map_err(|_| DbEsdkError::crypto("failed to construct RSA PKCS#1 public key"))?;
            let mut ciphertext = vec![0u8; key.ciphertext_size()];
            let out = key
                .encrypt(plaintext, &mut ciphertext)
                .map_err(|_| DbEsdkError::crypto("RSA PKCS#1 encryption failed"))?;
            Ok(out.to_vec())
        }
        Some(algorithm) => {
            let key = OaepPublicEncryptingKey::new(public_key)
                .map_err(|_| DbEsdkError::crypto("failed to construct RSA-OAEP public key"))?;
            let mut ciphertext = vec![0u8; key.ciphertext_size()];
            let out = key
                .encrypt(algorithm, plaintext, &mut ciphertext, None)
                .map_err(|_| DbEsdkError::crypto("RSA-OAEP encryption failed"))?;
            Ok(out.to_vec())
        }
    }
}

/// Decrypt (unwrap) `ciphertext` with an RSA private key supplied as DER-encoded
/// PKCS#8 `PrivateKeyInfo` bytes, using `padding`.
pub fn rsa_decrypt(
    private_key_pkcs8_der: &[u8],
    padding: RsaPadding,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let private_key = PrivateDecryptingKey::from_pkcs8(private_key_pkcs8_der)
        .map_err(|_| DbEsdkError::crypto("invalid RSA private key (expected DER PKCS#8)"))?;

    match padding.oaep_algorithm() {
        None => {
            let key = Pkcs1PrivateDecryptingKey::new(private_key)
                .map_err(|_| DbEsdkError::crypto("failed to construct RSA PKCS#1 private key"))?;
            let mut plaintext = vec![0u8; key.min_output_size()];
            let out = key
                .decrypt(ciphertext, &mut plaintext)
                .map_err(|_| DbEsdkError::crypto("RSA PKCS#1 decryption failed"))?;
            Ok(out.to_vec())
        }
        Some(algorithm) => {
            let key = OaepPrivateDecryptingKey::new(private_key)
                .map_err(|_| DbEsdkError::crypto("failed to construct RSA-OAEP private key"))?;
            let mut plaintext = vec![0u8; key.min_output_size()];
            let out = key
                .decrypt(algorithm, ciphertext, &mut plaintext, None)
                .map_err(|_| DbEsdkError::crypto("RSA-OAEP decryption failed"))?;
            Ok(out.to_vec())
        }
    }
}

// =============================================================================
// ECDH static key agreement (Raw ECDH keyring)
// =============================================================================

/// A NIST elliptic curve usable for ECDH key agreement (the crypto-layer mirror
/// of the configured `ECDHCurveSpec`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhCurve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
    /// NIST P-521 (secp521r1).
    P521,
}

impl EcdhCurve {
    fn agreement_algorithm(self) -> &'static agreement::Algorithm {
        match self {
            Self::P256 => &ECDH_P256,
            Self::P384 => &ECDH_P384,
            Self::P521 => &ECDH_P521,
        }
    }
}

/// Perform ECDH key agreement between a sender's static private key (DER-encoded
/// PKCS#8 `PrivateKeyInfo`) and a recipient's static public key (DER-encoded
/// X.509 `SubjectPublicKeyInfo`) on `curve`, returning the raw shared secret.
///
/// Both keys must lie on `curve`. The raw secret MUST be run through a KDF
/// before use as a key — callers derive a wrapping key from it via [`hkdf_sha384`].
pub fn ecdh_shared_secret(
    sender_private_key_pkcs8_der: &[u8],
    recipient_public_key_der: &[u8],
    curve: EcdhCurve,
) -> Result<Vec<u8>> {
    let algorithm = curve.agreement_algorithm();
    let private_key = EcdhPrivateKey::from_private_key_der(algorithm, sender_private_key_pkcs8_der)
        .map_err(|_| {
            DbEsdkError::crypto("invalid ECDH sender private key (expected DER PKCS#8 on the curve)")
        })?;
    let peer_public_key = UnparsedPublicKey::new(algorithm, recipient_public_key_der);

    agree(
        &private_key,
        peer_public_key,
        DbEsdkError::crypto("ECDH key agreement failed (curve mismatch or invalid public key)"),
        |shared_secret| Ok(shared_secret.to_vec()),
    )
}

// =============================================================================
// PEM decoding
// =============================================================================

/// Decode a single PEM document (any label) into its raw DER bytes.
///
/// The raw asymmetric keyring configs carry PEM-encoded UTF-8 key bytes (per the
/// MPL `CreateRaw*KeyringInput` contract); the `aws-lc-rs` key parsers want DER,
/// so callers strip the PEM armor here first.
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    let text =
        std::str::from_utf8(pem).map_err(|_| DbEsdkError::crypto("PEM key is not valid UTF-8"))?;

    let mut base64 = String::new();
    let mut in_body = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_body = true;
        } else if trimmed.starts_with("-----END") {
            in_body = false;
        } else if in_body {
            base64.push_str(trimmed);
        }
    }

    if base64.is_empty() {
        return Err(DbEsdkError::crypto(
            "PEM key contained no base64 body between BEGIN/END markers",
        ));
    }
    base64_decode(&base64)
}

/// Decode standard (RFC 4648) base64, ignoring whitespace and `=` padding.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let value = sextet(c).ok_or_else(|| DbEsdkError::crypto("invalid base64 in PEM key"))?;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Ok(out)
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

    #[test]
    fn pem_to_der_strips_armor_and_decodes_base64() {
        // base64("hello") == "aGVsbG8=", wrapped in PEM armor.
        let pem = b"-----BEGIN TEST KEY-----\naGVsbG8=\n-----END TEST KEY-----\n";
        assert_eq!(pem_to_der(pem).unwrap(), b"hello");
    }

    #[test]
    fn pem_to_der_rejects_a_body_with_no_markers() {
        assert!(pem_to_der(b"not a pem document").is_err());
    }

    #[test]
    fn rsa_oaep_wrap_unwrap_round_trips() {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
        use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let private_der = AsDer::<Pkcs8V1Der>::as_der(&private).unwrap();
        let public_der = AsDer::<PublicKeyX509Der>::as_der(&private.public_key()).unwrap();

        let data_key = random_bytes(32).unwrap();
        let wrapped = rsa_encrypt(public_der.as_ref(), RsaPadding::OaepSha256, &data_key).unwrap();
        assert_ne!(wrapped, data_key);
        let unwrapped =
            rsa_decrypt(private_der.as_ref(), RsaPadding::OaepSha256, &wrapped).unwrap();
        assert_eq!(unwrapped, data_key);
    }

    #[test]
    fn rsa_decrypt_rejects_a_different_key() {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
        use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

        let writer = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let writer_public = AsDer::<PublicKeyX509Der>::as_der(&writer.public_key()).unwrap();
        let other = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let other_private = AsDer::<Pkcs8V1Der>::as_der(&other).unwrap();

        let data_key = random_bytes(32).unwrap();
        let wrapped =
            rsa_encrypt(writer_public.as_ref(), RsaPadding::OaepSha256, &data_key).unwrap();
        assert!(rsa_decrypt(other_private.as_ref(), RsaPadding::OaepSha256, &wrapped).is_err());
    }

    #[test]
    fn ecdh_shared_secret_is_symmetric_and_deterministic() {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};

        let private = EcdhPrivateKey::generate(&ECDH_P256).unwrap();
        let private_der = AsDer::<Pkcs8V1Der>::as_der(&private).unwrap();
        let public = private.compute_public_key().unwrap();
        let public_der = AsDer::<PublicKeyX509Der>::as_der(&public).unwrap();

        // RawPrivateKeyToStaticPublicKey: the same key pair is both sender and
        // recipient, so encrypt and decrypt derive an identical shared secret.
        let a =
            ecdh_shared_secret(private_der.as_ref(), public_der.as_ref(), EcdhCurve::P256).unwrap();
        let b =
            ecdh_shared_secret(private_der.as_ref(), public_der.as_ref(), EcdhCurve::P256).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32, "P-256 shared secret is the 32-byte field element");
    }

    #[test]
    fn ecdh_rejects_a_public_key_on_a_different_curve() {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};

        let p256 = EcdhPrivateKey::generate(&ECDH_P256).unwrap();
        let p256_der = AsDer::<Pkcs8V1Der>::as_der(&p256).unwrap();
        let p384 = EcdhPrivateKey::generate(&ECDH_P384).unwrap();
        let p384_public = AsDer::<PublicKeyX509Der>::as_der(&p384.compute_public_key().unwrap())
            .unwrap();

        assert!(
            ecdh_shared_secret(p256_der.as_ref(), p384_public.as_ref(), EcdhCurve::P256).is_err()
        );
    }
}
