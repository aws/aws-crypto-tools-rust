// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Intermediate key wrapping, for suites whose [`EdkWrapping`](crate::types::EdkWrapping) is
//! [`IntermediateKeyWrapping`](crate::types::EdkWrapping::IntermediateKeyWrapping).
//!
//! The keyring wraps a fresh intermediate key instead of the plaintext data key.
//! Two keys are derived from the intermediate key: one encrypts the plaintext data key,
//! the other is the symmetric signing key that the message is signed with.
//! The encrypted data key's ciphertext is the encrypted plaintext data key
//! (ciphertext and tag) followed by the keyring's wrapping of the intermediate key.

use aws_mpl_primitives::{AesGcm, DigestAlg, aes_decrypt, aes_encrypt, hkdf_no_salt};
use zeroize::Zeroizing;

use crate::Error;
use crate::error::Kind;
use crate::structures::{
    AlgorithmSuite, KeyDerivationAlgorithm, PlaintextDataKey, SymmetricSigningKey,
};

const KEYWRAP_MAC_INFO: &[u8] = b"AWS_MPL_INTERMEDIATE_KEYWRAP_MAC";
const KEYWRAP_ENC_INFO: &[u8] = b"AWS_MPL_INTERMEDIATE_KEYWRAP_ENC";

/// The key-encryption key and symmetric signing key derived from an intermediate key.
struct DerivedKeys {
    pdk_encryption_key: Zeroizing<Vec<u8>>,
    symmetric_signing_key: SymmetricSigningKey,
}

fn hkdf_digest(suite: &AlgorithmSuite) -> Result<DigestAlg, Error> {
    match suite.commit_kdf() {
        Some(KeyDerivationAlgorithm::HkdfSha256) => Ok(DigestAlg::Sha256),
        Some(KeyDerivationAlgorithm::HkdfSha384) => Ok(DigestAlg::Sha384),
        Some(KeyDerivationAlgorithm::HkdfSha512) => Ok(DigestAlg::Sha512),
        _ => Err(Error::new(
            Kind::InvalidMaterials,
            "Invalid algorithm suite: suites with intermediate key wrapping must use key commitment.",
        )),
    }
}

fn aes_gcm(suite: &AlgorithmSuite) -> Result<AesGcm, Error> {
    match suite.encryption_key_length() {
        16 => Ok(AesGcm::Aes128Gcm),
        24 => Ok(AesGcm::Aes192Gcm),
        32 => Ok(AesGcm::Aes256Gcm),
        n => Err(Error::new(
            Kind::InvalidMaterials,
            format!("no AES-GCM algorithm has a {n}-byte key"),
        )),
    }
}

/// Derive the plaintext-data-key encryption key and the symmetric signing key from `ikm`.
fn derive_keys(suite: &AlgorithmSuite, ikm: &[u8]) -> Result<DerivedKeys, Error> {
    let alg = hkdf_digest(suite)?;
    let len = suite.encryption_key_length();
    let mut mac = Zeroizing::new(vec![0u8; len]);
    hkdf_no_salt(alg, ikm, &[KEYWRAP_MAC_INFO], &mut mac).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to derive the symmetric signing key",
            e,
        )
    })?;
    let mut enc = Zeroizing::new(vec![0u8; len]);
    hkdf_no_salt(alg, ikm, &[KEYWRAP_ENC_INFO], &mut enc).map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "failed to derive the data key encryption key",
            e,
        )
    })?;
    Ok(DerivedKeys {
        pdk_encryption_key: enc,
        symmetric_signing_key: SymmetricSigningKey::new(mac.to_vec()),
    })
}

/// The length of the encrypted plaintext data key at the front of the wrapped material.
pub(crate) const fn encrypted_pdk_len(suite: &AlgorithmSuite) -> usize {
    suite.encryption_key_length() + suite.authentication_tag_length()
}

/// Encrypt `pdk` under keys derived from `ikm`, authenticating `aad`.
/// Returns the encrypted plaintext data key (ciphertext and tag) and the symmetric signing key.
pub(crate) fn encrypt_pdk(
    suite: &AlgorithmSuite,
    ikm: &[u8],
    aad: &[u8],
    pdk: &PlaintextDataKey,
) -> Result<(Vec<u8>, SymmetricSigningKey), Error> {
    let keys = derive_keys(suite, ikm)?;
    let iv = vec![0u8; suite.iv_length()];
    let mut out = Vec::with_capacity(encrypted_pdk_len(suite));
    aes_encrypt(
        aes_gcm(suite)?,
        &iv,
        &keys.pdk_encryption_key,
        pdk.as_bytes(),
        aad,
        &mut out,
    )
    .map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "AES-GCM encryption of the plaintext data key failed",
            e,
        )
    })?;
    Ok((out, keys.symmetric_signing_key))
}

/// Split wrapped material into the encrypted plaintext data key and the keyring's
/// wrapping of the intermediate key.
pub(crate) fn split<'a>(
    suite: &AlgorithmSuite,
    material: &'a [u8],
) -> Result<(&'a [u8], &'a [u8]), Error> {
    let len = encrypted_pdk_len(suite);
    if material.len() < len {
        return Err(Error::new(
            Kind::Cryptographic,
            "Unable to deserialize Intermediate Key Wrapped material: too short.",
        ));
    }
    Ok(material.split_at(len))
}

/// Decrypt `encrypted_pdk` under keys derived from `ikm`, authenticating `aad`.
/// Returns the plaintext data key and the symmetric signing key.
pub(crate) fn decrypt_pdk(
    suite: &AlgorithmSuite,
    ikm: &[u8],
    aad: &[u8],
    encrypted_pdk: &[u8],
) -> Result<(PlaintextDataKey, SymmetricSigningKey), Error> {
    let keys = derive_keys(suite, ikm)?;
    let iv = vec![0u8; suite.iv_length()];
    let tag_index = encrypted_pdk
        .len()
        .checked_sub(suite.authentication_tag_length())
        .ok_or_else(|| {
            Error::new(
                Kind::Cryptographic,
                "encrypted plaintext data key too short",
            )
        })?;
    let (ct, tag) = encrypted_pdk.split_at(tag_index);
    let mut pdk = vec![0u8; ct.len()];
    aes_decrypt(
        aes_gcm(suite)?,
        &keys.pdk_encryption_key,
        ct,
        tag,
        &iv,
        aad,
        &mut pdk,
    )
    .map_err(|e| {
        Error::with_cause(
            Kind::Cryptographic,
            "AES-GCM decryption of the plaintext data key failed",
            e,
        )
    })?;
    Ok((PlaintextDataKey::new(pdk), keys.symmetric_signing_key))
}
