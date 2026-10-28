// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::Error;
use crate::err;
use crate::serr;

use aws_lc_rs::rsa::{
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
    OaepAlgorithm, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, Pkcs1PrivateDecryptingKey,
    Pkcs1PublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
};

/// RSA encryption padding scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RsaPadding {
    /// RSAES-PKCS1-v1_5.
    Pkcs1,
    /// RSAES-OAEP with SHA-1 and MGF1 with SHA-1.
    OaepSha1,
    /// RSAES-OAEP with SHA-256 and MGF1 with SHA-256.
    OaepSha256,
    /// RSAES-OAEP with SHA-384 and MGF1 with SHA-384.
    OaepSha384,
    /// RSAES-OAEP with SHA-512 and MGF1 with SHA-512.
    OaepSha512,
}

impl RsaPadding {
    /// The OAEP algorithm, or `None` for PKCS #1 v1.5.
    const fn oaep(self) -> Option<&'static OaepAlgorithm> {
        match self {
            Self::Pkcs1 => None,
            Self::OaepSha1 => Some(&OAEP_SHA1_MGF1SHA1),
            Self::OaepSha256 => Some(&OAEP_SHA256_MGF1SHA256),
            Self::OaepSha384 => Some(&OAEP_SHA384_MGF1SHA384),
            Self::OaepSha512 => Some(&OAEP_SHA512_MGF1SHA512),
        }
    }
}

/// The DER contents of a PEM-encoded key.
fn pem_contents(key: &[u8], what: &str) -> Result<Vec<u8>, Error> {
    let key = std::str::from_utf8(key)
        .map_err(|_| serr(format!("the RSA {what} key is not UTF-8 PEM")))?;
    let pem =
        pem::parse(key).map_err(|e| serr(format!("the RSA {what} key is not valid PEM: {e}")))?;
    Ok(pem.into_contents())
}

/// Parse a PEM-encoded X.509 `SubjectPublicKeyInfo` RSA public key.
fn public_key(public_key_pem: &[u8]) -> Result<PublicEncryptingKey, Error> {
    let der = pem_contents(public_key_pem, "public")?;
    PublicEncryptingKey::from_der(&der)
        .map_err(|_| serr("the RSA public key is not a valid X.509 RSA public key".to_owned()))
}

/// Parse a PEM-encoded PKCS #8 RSA private key.
fn private_key(private_key_pem: &[u8]) -> Result<PrivateDecryptingKey, Error> {
    let der = zeroize::Zeroizing::new(pem_contents(private_key_pem, "private")?);
    PrivateDecryptingKey::from_pkcs8(&der)
        .map_err(|_| serr("the RSA private key is not a valid PKCS #8 RSA private key".to_owned()))
}

/// The modulus length in bits of a PEM-encoded X.509 RSA public key.
///
/// # Errors
///
/// Returns an [`Error`] if `public_key_pem` is not a PEM-encoded X.509
/// `SubjectPublicKeyInfo` RSA public key.
pub fn rsa_modulus_length_bits(public_key_pem: &[u8]) -> Result<u32, Error> {
    let key = public_key(public_key_pem)?;
    u32::try_from(key.key_size_bits())
        .map_err(|_| serr("the RSA modulus length does not fit in 32 bits".to_owned()))
}

/// Encrypt `plaintext` with a PEM-encoded X.509 RSA public key.
///
/// # Errors
///
/// Returns an [`Error`] if `public_key_pem` or `plaintext` is empty, if the
/// key does not parse, or if `plaintext` is too long for the key and padding.
pub fn rsa_encrypt(
    padding: RsaPadding,
    public_key_pem: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if public_key_pem.is_empty() || plaintext.is_empty() {
        return err("RSA Encrypt : the public key and plaintext must not be empty".to_owned());
    }
    let key = public_key(public_key_pem)?;
    let mut ciphertext = vec![0u8; key.key_size_bytes()];
    let written = match padding.oaep() {
        None => {
            let key = Pkcs1PublicEncryptingKey::new(key)
                .map_err(|_| serr("RSA Encrypt : unsupported PKCS #1 public key".to_owned()))?;
            key.encrypt(plaintext, &mut ciphertext)
                .map_err(|_| serr("RSA Encrypt : PKCS #1 encryption failed".to_owned()))?
                .len()
        }
        Some(alg) => {
            let key = OaepPublicEncryptingKey::new(key)
                .map_err(|_| serr("RSA Encrypt : unsupported OAEP public key".to_owned()))?;
            key.encrypt(alg, plaintext, &mut ciphertext, None)
                .map_err(|_| serr(format!("RSA Encrypt : {padding:?} encryption failed")))?
                .len()
        }
    };
    ciphertext.truncate(written);
    Ok(ciphertext)
}

/// Decrypt `ciphertext` with a PEM-encoded PKCS #8 RSA private key.
///
/// # Errors
///
/// Returns an [`Error`] if `private_key_pem` or `ciphertext` is empty, if the
/// key does not parse, or if `ciphertext` does not decrypt under the key and
/// padding.
pub fn rsa_decrypt(
    padding: RsaPadding,
    private_key_pem: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if private_key_pem.is_empty() || ciphertext.is_empty() {
        return err("RSA Decrypt : the private key and ciphertext must not be empty".to_owned());
    }
    let key = private_key(private_key_pem)?;
    let mut plaintext = vec![0u8; ciphertext.len()];
    let written = match padding.oaep() {
        None => {
            let key = Pkcs1PrivateDecryptingKey::new(key)
                .map_err(|_| serr("RSA Decrypt : unsupported PKCS #1 private key".to_owned()))?;
            key.decrypt(ciphertext, &mut plaintext)
                .map_err(|_| serr("RSA Decrypt : PKCS #1 decryption failed".to_owned()))?
                .len()
        }
        Some(alg) => {
            let key = OaepPrivateDecryptingKey::new(key)
                .map_err(|_| serr("RSA Decrypt : unsupported OAEP private key".to_owned()))?;
            key.decrypt(alg, ciphertext, &mut plaintext, None)
                .map_err(|_| serr(format!("RSA Decrypt : {padding:?} decryption failed")))?
                .len()
        }
    };
    plaintext.truncate(written);
    Ok(plaintext)
}
