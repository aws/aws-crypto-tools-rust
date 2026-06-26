// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The Raw AES keyring: generate a plaintext data key and wrap / unwrap it with
//! a directly-supplied AES wrapping key.
//!
//! The native MPL crate currently ships only the abstract `Keyring` trait (no
//! concrete keyrings — see `BLOCKED.md`), so the data-key wrapping the DB-ESDK
//! item encryptor needs is implemented here over [`crate::crypto`]. When MPL
//! grows a concrete Raw AES keyring, this module should delegate to it.
//!
//! Wrapping uses AES-GCM: the wrapped form is `nonce || ciphertext || tag`, with
//! the keyring's namespace and name bound in as additional authenticated data so
//! a data key wrapped under one (namespace, name) cannot be unwrapped under
//! another.

use crate::config::RawAesKeyringConfig;
use crate::crypto;
use crate::error::Result;

/// The length of a generated plaintext data key (256 bits — the KDF input length
/// of the DBE algorithm suites).
pub const DATA_KEY_LEN: usize = 32;

/// A wrapped data key: the keyring identity plus the AES-GCM-wrapped key bytes.
///
/// This is what the item header persists so the data key can be recovered on
/// decrypt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDataKey {
    /// The wrapping keyring's namespace.
    pub key_namespace: String,
    /// The wrapping keyring's name.
    pub key_name: String,
    /// `nonce || ciphertext || tag` of the wrapped plaintext data key.
    pub ciphertext: Vec<u8>,
}

/// A Raw AES keyring built from a [`RawAesKeyringConfig`].
pub struct RawAesKeyring {
    key_namespace: String,
    key_name: String,
    wrapping_key: Vec<u8>,
}

impl RawAesKeyring {
    /// Build a keyring from its configuration. The configuration is assumed to
    /// have been validated (see [`crate::config::TableEncryptionConfig::validate`]).
    pub fn new(config: &RawAesKeyringConfig) -> Self {
        Self {
            key_namespace: config.key_namespace.clone(),
            key_name: config.key_name.clone(),
            wrapping_key: config.wrapping_key.clone(),
        }
    }

    /// The additional authenticated data bound into every wrap/unwrap: the
    /// length-delimited keyring namespace and name.
    fn wrap_aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        let ns = self.key_namespace.as_bytes();
        let name = self.key_name.as_bytes();
        aad.extend_from_slice(&(ns.len() as u32).to_be_bytes());
        aad.extend_from_slice(ns);
        aad.extend_from_slice(&(name.len() as u32).to_be_bytes());
        aad.extend_from_slice(name);
        aad
    }

    /// Generate a fresh plaintext data key and return it together with its
    /// wrapped form (the "OnEncrypt → Generate Data Key + Encrypt Data Key"
    /// behavior, specialized to a single keyring).
    pub fn generate_and_wrap(&self) -> Result<(Vec<u8>, WrappedDataKey)> {
        let plaintext_data_key = crypto::random_bytes(DATA_KEY_LEN)?;
        let wrapped = self.wrap(&plaintext_data_key)?;
        Ok((plaintext_data_key, wrapped))
    }

    /// Wrap an existing plaintext data key.
    pub fn wrap(&self, plaintext_data_key: &[u8]) -> Result<WrappedDataKey> {
        let ciphertext =
            crypto::aes_gcm_seal(&self.wrapping_key, &self.wrap_aad(), plaintext_data_key)?;
        Ok(WrappedDataKey {
            key_namespace: self.key_namespace.clone(),
            key_name: self.key_name.clone(),
            ciphertext,
        })
    }

    /// Recover a plaintext data key from its wrapped form (the "OnDecrypt →
    /// Decrypt Data Key" behavior). Fails if the wrapped key was produced under
    /// a different keyring identity or has been tampered with.
    pub fn unwrap(&self, wrapped: &WrappedDataKey) -> Result<Vec<u8>> {
        if wrapped.key_namespace != self.key_namespace || wrapped.key_name != self.key_name {
            return Err(crate::error::DbEsdkError::crypto(
                "wrapped data key was produced under a different keyring (namespace/name mismatch)",
            ));
        }
        crypto::aes_gcm_open(&self.wrapping_key, &self.wrap_aad(), &wrapped.ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AesWrappingAlg;

    fn keyring(name: &str) -> RawAesKeyring {
        RawAesKeyring::new(&RawAesKeyringConfig {
            key_namespace: "test-server-namespace".to_string(),
            key_name: name.to_string(),
            wrapping_key: vec![9u8; 32],
            wrapping_alg: AesWrappingAlg::Aes256,
        })
    }

    #[test]
    fn generate_wrap_unwrap_round_trips() {
        let k = keyring("raw-aes-key");
        let (pdk, wrapped) = k.generate_and_wrap().unwrap();
        assert_eq!(pdk.len(), DATA_KEY_LEN);
        let recovered = k.unwrap(&wrapped).unwrap();
        assert_eq!(recovered, pdk);
    }

    #[test]
    fn unwrap_rejects_different_keyring_identity() {
        let writer = keyring("key-a");
        let (_pdk, wrapped) = writer.generate_and_wrap().unwrap();
        let other = keyring("key-b");
        assert!(other.unwrap(&wrapped).is_err());
    }

    #[test]
    fn unwrap_rejects_tampered_ciphertext() {
        let k = keyring("raw-aes-key");
        let (_pdk, mut wrapped) = k.generate_and_wrap().unwrap();
        let last = wrapped.ciphertext.len() - 1;
        wrapped.ciphertext[last] ^= 0x01;
        assert!(k.unwrap(&wrapped).is_err());
    }
}
