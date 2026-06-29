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
// Byte-faithful DB-ESDK format primitives
//
// These mirror the exact crypto the Dafny StructuredEncryption + MPL
// intermediate-key-wrapping use, so the on-DDB bytes interoperate with the
// canonical Java DB-ESDK. They are kept separate from the (spec-aligned but not
// byte-identical) helpers above, which the legacy `encrypt` path still uses.
// =============================================================================

use aws_lc_rs::cipher::{
    EncryptingKey, EncryptionContext, UnboundCipherKey, AES_256 as CIPHER_AES_256,
};
use aws_lc_rs::digest::{digest, SHA384};
use aws_lc_rs::hmac::{HMAC_SHA256, HMAC_SHA512, Key as HmacKey};
use aws_lc_rs::iv::FixedLength;

/// SHA-384 digest of `data` (48 bytes). The DB-ESDK footer canonical hash.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    digest(&SHA384, data).as_ref().to_vec()
}

/// HMAC-SHA512 tag over `data` with `key` (64 bytes).
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = HmacKey::new(HMAC_SHA512, key);
    aws_lc_rs::hmac::sign(&k, data).as_ref().to_vec()
}

/// HMAC-SHA256 tag over `data` with `key` (32 bytes).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = HmacKey::new(HMAC_SHA256, key);
    aws_lc_rs::hmac::sign(&k, data).as_ref().to_vec()
}

/// NIST SP 800-108 KDF in counter mode using HMAC-SHA256 as the PRF (the
/// Hierarchical keyring branch-key derivation, `KdfCtr.KdfCounterMode` with
/// `SHA_256`). PRF input for counter `i` is
/// `UInt32BE(i) || purpose || 0x00 || nonce || UInt32BE(out_len * 8)`.
pub fn kdf_ctr_hmac_sha256(
    ikm: &[u8],
    purpose: &[u8],
    nonce: &[u8],
    out_len: usize,
) -> Result<Vec<u8>> {
    const MAC_LEN: usize = 32; // SHA-256 output length.
    let length_bits = u32::try_from(out_len.saturating_mul(8))
        .map_err(|_| DbEsdkError::crypto("KDF output length is too large"))?;

    let mut explicit_info = Vec::with_capacity(purpose.len() + 1 + nonce.len() + 4);
    explicit_info.extend_from_slice(purpose);
    explicit_info.push(0x00);
    explicit_info.extend_from_slice(nonce);
    explicit_info.extend_from_slice(&length_bits.to_be_bytes());

    let iterations = out_len.div_ceil(MAC_LEN);
    let mut buffer = Vec::with_capacity(iterations * MAC_LEN);
    for i in 1..=iterations {
        let counter = u32::try_from(i).map_err(|_| DbEsdkError::crypto("KDF counter overflow"))?;
        let mut prf_input = Vec::with_capacity(4 + explicit_info.len());
        prf_input.extend_from_slice(&counter.to_be_bytes());
        prf_input.extend_from_slice(&explicit_info);
        buffer.extend_from_slice(&hmac_sha256(ikm, &prf_input));
    }
    buffer.truncate(out_len);
    Ok(buffer)
}

/// RFC 5869 HKDF-Extract with SHA-512: `PRK = HMAC-SHA512(salt, ikm)`.
///
/// An empty salt is replaced by a HashLen-zero block, per the RFC.
pub fn hkdf_sha512_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt = if salt.is_empty() { &[0u8; 64][..] } else { salt };
    hmac_sha512(salt, ikm)
}

/// RFC 5869 HKDF-Expand with SHA-512, for `out_len <= 64`
/// (`T(1) = HMAC-SHA512(prk, info || 0x01)`, truncated to `out_len`).
pub fn hkdf_sha512_expand(prk: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    if out_len > 64 {
        return Err(DbEsdkError::crypto(
            "HKDF-SHA512 expand of more than one block is not supported",
        ));
    }
    let mut msg = info.to_vec();
    msg.push(0x01);
    let mut okm = hmac_sha512(prk, &msg);
    okm.truncate(out_len);
    Ok(okm)
}

/// HKDF-SHA512 extract-and-expand with an empty salt, deriving `out_len` bytes.
pub fn hkdf_sha512(ikm: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let prk = hkdf_sha512_extract(&[], ikm);
    hkdf_sha512_expand(&prk, info, out_len)
}

/// AES-256-CTR keystream of `len` bytes, produced by encrypting zeros under
/// `key` with the 16-byte `iv`. Mirrors `AesKdfCtr.Stream` (the field-key KDF).
pub fn aes256_ctr_keystream(key: &[u8], iv: &[u8; 16], len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let unbound = UnboundCipherKey::new(&CIPHER_AES_256, key)
        .map_err(|_| DbEsdkError::crypto("failed to construct AES-256-CTR key"))?;
    let enc = EncryptingKey::ctr(unbound)
        .map_err(|_| DbEsdkError::crypto("failed to construct AES-256-CTR encryptor"))?;
    let context = EncryptionContext::Iv128(FixedLength::<16>::from(iv));
    enc.less_safe_encrypt(&mut buf, context)
        .map_err(|_| DbEsdkError::crypto("AES-256-CTR keystream generation failed"))?;
    Ok(buf)
}

/// AES-GCM encrypt with an explicit 12-byte nonce; returns `ciphertext || tag`
/// (no nonce prefix). The DB-ESDK stores the nonce out of band (or fixes it to
/// zero), unlike [`aes_gcm_seal`].
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let k = LessSafeKey::new(unbound_key(key)?);
    let mut in_out = plaintext.to_vec();
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(*nonce),
        Aad::from(aad),
        &mut in_out,
    )
    .map_err(|_| DbEsdkError::crypto("AES-GCM encrypt failed"))?;
    Ok(in_out)
}

/// AES-GCM decrypt of `ciphertext || tag` with an explicit 12-byte nonce.
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext_and_tag.len() < GCM_TAG_LEN {
        return Err(DbEsdkError::crypto("AES-GCM ciphertext too short for a tag"));
    }
    let k = LessSafeKey::new(unbound_key(key)?);
    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext = k
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| DbEsdkError::crypto("AES-GCM decrypt failed (tag mismatch)"))?;
    Ok(plaintext.to_vec())
}

/// Standard (RFC 4648) base64 encoding with `=` padding.
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

// =============================================================================
// ECDSA P-384 signing (DBE signing suite, flavor 0x01)
//
// Mirrors the AwsCryptographyPrimitives ECDSA extern as used by the DB-ESDK
// footer: sign the canonical hash with ECDSA-P384/SHA-384 (ASN.1/DER), retrying
// until the DER signature is exactly the fixed footer size, and store the
// verification key in SEC1 *compressed* form. Verification accepts the same
// compressed key directly (aws-lc-rs/AWS-LC parse compressed SEC1 points).
// =============================================================================

use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair as _, UnparsedPublicKey as SigUnparsedPublicKey, ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_ASN1_SIGNING,
};

/// The fixed DER-encoded ECDSA P-384 signature length the DB-ESDK footer uses
/// (`Footer.dfy` `SignatureSize`).
pub const ECDSA_P384_SIGNATURE_LEN: usize = 103;

/// A freshly generated ECDSA P-384 key pair used to sign one item's canonical
/// hash. Mirrors the DBE default CMM's per-message signing key: the verification
/// key is exported in SEC1 *compressed* form (49 bytes) to be stored, base64, in
/// the reserved `aws-crypto-public-key` encryption-context entry.
pub struct EcdsaP384Signer {
    key_pair: EcdsaKeyPair,
    compressed_public_key: Vec<u8>,
}

impl EcdsaP384Signer {
    /// Generate a new P-384 signing key pair and pre-compute its compressed
    /// verification key.
    pub fn generate() -> Result<Self> {
        let key_pair = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING)
            .map_err(|_| DbEsdkError::crypto("ECDSA P-384 key generation failed"))?;
        let compressed_public_key = sec1_compress_p384(key_pair.public_key().as_ref())?;
        Ok(Self {
            key_pair,
            compressed_public_key,
        })
    }

    /// The SEC1-compressed verification key (49 bytes: `0x02|0x03 || X`).
    pub fn compressed_public_key(&self) -> &[u8] {
        &self.compressed_public_key
    }

    /// Sign `message` (the footer canonical hash), retrying until the DER
    /// signature is exactly [`ECDSA_P384_SIGNATURE_LEN`] bytes — the fixed size
    /// the DB-ESDK footer requires. ECDSA signing is randomized, so re-signing
    /// yields a fresh signature; ~half of P-384 DER signatures are 103 bytes, so
    /// the bounded retry succeeds with overwhelming probability.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        for _ in 0..128 {
            let sig = self
                .key_pair
                .sign(&rng, message)
                .map_err(|_| DbEsdkError::crypto("ECDSA P-384 signing failed"))?;
            if sig.as_ref().len() == ECDSA_P384_SIGNATURE_LEN {
                return Ok(sig.as_ref().to_vec());
            }
        }
        Err(DbEsdkError::crypto(
            "could not produce a fixed-length ECDSA P-384 signature after retries",
        ))
    }
}

/// Verify a DB-ESDK footer ECDSA P-384 signature over `message` (the canonical
/// hash) with a SEC1-compressed (or uncompressed) `verification_key`.
pub fn ecdsa_p384_verify(verification_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    SigUnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, verification_key)
        .verify(message, signature)
        .map_err(|_| DbEsdkError::crypto("ECDSA P-384 signature did not verify"))
}

/// Compress a SEC1-uncompressed P-384 public point
/// (`0x04 || X(48) || Y(48)`, 97 bytes) to compressed form
/// (`0x02|0x03 || X(48)`, 49 bytes).
fn sec1_compress_p384(uncompressed: &[u8]) -> Result<Vec<u8>> {
    sec1_compress(uncompressed, 48)
}

/// Compress a SEC1-uncompressed public point (`0x04 || X || Y`, where each
/// coordinate is `coord_len` bytes) to compressed form (`0x02|0x03 || X`), per
/// SEC1 v2 §2.3.3. The prefix encodes the parity of the Y coordinate (`0x02`
/// even, `0x03` odd).
fn sec1_compress(uncompressed: &[u8], coord_len: usize) -> Result<Vec<u8>> {
    let expected = 1 + 2 * coord_len;
    if uncompressed.len() != expected || uncompressed[0] != 0x04 {
        return Err(DbEsdkError::crypto(
            "expected an uncompressed SEC1 public point (0x04 || X || Y)",
        ));
    }
    let x = &uncompressed[1..1 + coord_len];
    let y = &uncompressed[1 + coord_len..];
    let prefix = if y[y.len() - 1] & 1 == 0 { 0x02u8 } else { 0x03u8 };
    let mut out = Vec::with_capacity(1 + coord_len);
    out.push(prefix);
    out.extend_from_slice(x);
    Ok(out)
}

/// Decode standard (RFC 4648) base64 *bytes* (the ASCII encoding produced by
/// [`base64_encode`]) into the raw bytes, ignoring `=` padding and whitespace.
pub fn base64_decode_bytes(input: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(input)
        .map_err(|_| DbEsdkError::crypto("base64 input is not valid UTF-8"))?;
    base64_decode(text)
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

impl EcdhCurve {
    /// The byte length of one field coordinate on this curve (P-256 → 32,
    /// P-384 → 48, P-521 → 66). A SEC1-uncompressed point is `1 + 2 * coord`
    /// bytes and a compressed point is `1 + coord` bytes.
    pub fn coordinate_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// The lowercase curve name used in the ECDH key-derivation `FixedInfo`
    /// (`Constants.CurveSpecTypeToString`).
    pub fn kdf_name(self) -> &'static str {
        match self {
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::P521 => "p521",
        }
    }
}

/// The SEC1-*compressed* public key (`0x02|0x03 || X`) for the EC private key
/// supplied as DER-encoded PKCS#8 `PrivateKeyInfo` on `curve`.
///
/// The Raw ECDH keyring serializes both parties' public keys in compressed form
/// into the EDK provider info and the key-derivation `FixedInfo`.
pub fn ecdh_compressed_public_key(private_key_pkcs8_der: &[u8], curve: EcdhCurve) -> Result<Vec<u8>> {
    let algorithm = curve.agreement_algorithm();
    let private_key = EcdhPrivateKey::from_private_key_der(algorithm, private_key_pkcs8_der)
        .map_err(|_| DbEsdkError::crypto("invalid ECDH private key (expected DER PKCS#8)"))?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| DbEsdkError::crypto("failed to compute ECDH public key"))?;
    sec1_compress(public_key.as_ref(), curve.coordinate_len())
}

/// The SEC1-*compressed* public key for the public key supplied as DER-encoded
/// X.509 `SubjectPublicKeyInfo` on `curve`.
///
/// The uncompressed SEC1 point (`0x04 || X || Y`) is the trailing
/// `1 + 2 * coord` bytes of the SPKI DER (the final `BIT STRING` content).
pub fn ecdh_compress_spki_public_key(spki_der: &[u8], curve: EcdhCurve) -> Result<Vec<u8>> {
    let point_len = 1 + 2 * curve.coordinate_len();
    if spki_der.len() < point_len {
        return Err(DbEsdkError::crypto(
            "ECDH public key DER is too short to contain an uncompressed point",
        ));
    }
    let point = &spki_der[spki_der.len() - point_len..];
    sec1_compress(point, curve.coordinate_len())
}

/// NIST SP 800-108 KDF in counter mode using HMAC-SHA384 as the PRF (the ECDH
/// key-agreement key derivation, `KdfCtr.KdfCounterMode` with `SHA_384`).
///
/// For counter `i = 1, 2, …` the PRF input is
/// `UInt32BE(i) || purpose || 0x00 || nonce || UInt32BE(out_len * 8)`; the
/// blocks are concatenated and truncated to `out_len` bytes.
pub fn kdf_ctr_hmac_sha384(
    ikm: &[u8],
    purpose: &[u8],
    nonce: &[u8],
    out_len: usize,
) -> Result<Vec<u8>> {
    const MAC_LEN: usize = 48; // SHA-384 output length.
    let length_bits = u32::try_from(out_len.saturating_mul(8))
        .map_err(|_| DbEsdkError::crypto("KDF output length is too large"))?;

    // explicitInfo = purpose(label) || 0x00 (separator) || nonce(context) || L.
    let mut explicit_info = Vec::with_capacity(purpose.len() + 1 + nonce.len() + 4);
    explicit_info.extend_from_slice(purpose);
    explicit_info.push(0x00);
    explicit_info.extend_from_slice(nonce);
    explicit_info.extend_from_slice(&length_bits.to_be_bytes());

    let iterations = out_len.div_ceil(MAC_LEN);
    let mut buffer = Vec::with_capacity(iterations * MAC_LEN);
    for i in 1..=iterations {
        let counter = u32::try_from(i).map_err(|_| DbEsdkError::crypto("KDF counter overflow"))?;
        let mut prf_input = Vec::with_capacity(4 + explicit_info.len());
        prf_input.extend_from_slice(&counter.to_be_bytes());
        prf_input.extend_from_slice(&explicit_info);
        buffer.extend_from_slice(&hmac_sha384(ikm, &prf_input));
    }
    buffer.truncate(out_len);
    Ok(buffer)
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

    #[test]
    fn ecdsa_p384_sign_produces_fixed_length_and_verifies() {
        let signer = EcdsaP384Signer::generate().unwrap();
        // SEC1-compressed P-384 verification key is 49 bytes with a 0x02/0x03 prefix.
        let vk = signer.compressed_public_key();
        assert_eq!(vk.len(), 49);
        assert!(vk[0] == 0x02 || vk[0] == 0x03);

        // The canonical hash is SHA-384 (48 bytes); sign it and verify.
        let message = sha384(b"a canonical record");
        let sig = signer.sign(&message).unwrap();
        assert_eq!(sig.len(), ECDSA_P384_SIGNATURE_LEN, "footer signature is fixed 103 bytes");

        ecdsa_p384_verify(vk, &message, &sig).unwrap();
    }

    #[test]
    fn ecdsa_p384_verify_rejects_tampered_message_and_signature() {
        let signer = EcdsaP384Signer::generate().unwrap();
        let vk = signer.compressed_public_key();
        let message = sha384(b"original");
        let sig = signer.sign(&message).unwrap();

        // Wrong message must not verify.
        let other = sha384(b"different");
        assert!(ecdsa_p384_verify(vk, &other, &sig).is_err());

        // A flipped signature byte must not verify.
        let mut bad = sig.clone();
        bad[10] ^= 0x01;
        assert!(ecdsa_p384_verify(vk, &message, &bad).is_err());
    }

    #[test]
    fn base64_decode_bytes_round_trips_encode() {
        let raw = random_bytes(49).unwrap();
        let encoded = base64_encode(&raw);
        assert_eq!(base64_decode_bytes(encoded.as_bytes()).unwrap(), raw);
    }

    #[test]
    fn kdf_ctr_hmac_sha384_matches_manual_construction() {
        // The SP 800-108 counter-mode PRF input for block i is
        // UInt32BE(i) || purpose || 0x00 || nonce || UInt32BE(out_len*8).
        // A 32-byte (48-byte IKM is the P-384 secret length) derivation needs
        // one HMAC-SHA384 block; a 64-byte one needs two.
        let ikm = [0x11u8; 48];
        let purpose = b"some-fixed-info";
        let nonce = [0x22u8; 32];

        let mut explicit = Vec::new();
        explicit.extend_from_slice(purpose);
        explicit.push(0x00);
        explicit.extend_from_slice(&nonce);
        explicit.extend_from_slice(&(64u32 * 8).to_be_bytes());

        let mut block1 = vec![0, 0, 0, 1];
        block1.extend_from_slice(&explicit);
        let mut block2 = vec![0, 0, 0, 2];
        block2.extend_from_slice(&explicit);
        let mut expected = hmac_sha384(&ikm, &block1);
        expected.extend_from_slice(&hmac_sha384(&ikm, &block2));
        expected.truncate(64);

        let derived = kdf_ctr_hmac_sha384(&ikm, purpose, &nonce, 64).unwrap();
        assert_eq!(derived, expected);
        assert_eq!(derived.len(), 64);
    }

    #[test]
    fn ecdh_compressed_keys_agree_for_a_keypair() {
        use aws_lc_rs::agreement::{PrivateKey, ECDH_P256};
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};

        let private = PrivateKey::generate(&ECDH_P256).unwrap();
        let pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&private).unwrap();
        let public = private.compute_public_key().unwrap();
        let spki = AsDer::<PublicKeyX509Der>::as_der(&public).unwrap();

        // Compressing the public key derived from the private key and the
        // public key parsed from the SPKI DER must yield the same 33-byte point.
        let from_private = ecdh_compressed_public_key(pkcs8.as_ref(), EcdhCurve::P256).unwrap();
        let from_spki = ecdh_compress_spki_public_key(spki.as_ref(), EcdhCurve::P256).unwrap();
        assert_eq!(from_private, from_spki);
        assert_eq!(from_private.len(), 33);
        assert!(from_private[0] == 0x02 || from_private[0] == 0x03);
    }
}
