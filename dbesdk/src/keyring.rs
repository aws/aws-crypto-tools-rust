// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Data-key wrapping keyrings driven by the item encryptor: the abstract
//! [`Keyring`] trait plus the concrete raw keyrings whose key material is
//! supplied directly in the configuration — [`RawAesKeyring`] (AES-GCM key
//! wrap), [`RawRsaKeyring`] (RSA-OAEP / PKCS#1 wrap), and [`RawEcdhKeyring`]
//! (ECDH static agreement + AES-GCM wrap).
//!
//! The native MPL crate currently ships only the abstract `Keyring` trait (no
//! concrete keyrings — see `BLOCKED.md`), so the data-key wrapping the DB-ESDK
//! item encryptor needs is implemented here over [`crate::crypto`]. When MPL
//! grows concrete keyrings, these should delegate to them. The I/O-bound KMS
//! keyrings live in the server adapter (they need an async client), not here.
//!
//! The Raw AES / Raw ECDH wraps use AES-GCM: the wrapped form is
//! `nonce || ciphertext || tag`, with the keyring's namespace and name bound in
//! as additional authenticated data so a data key wrapped under one
//! (namespace, name) cannot be unwrapped under another.

use crate::config::{
    EcdhCurveSpec, PaddingScheme, RawAesKeyringConfig, RawEcdhKeyringConfig, RawRsaKeyringConfig,
};
use crate::crypto;
use crate::error::{DbEsdkError, Result};

/// The length of a generated plaintext data key (256 bits — the KDF input length
/// of the DBE algorithm suites).
pub const DATA_KEY_LEN: usize = 32;

/// A data-key wrapping keyring: the abstraction the item encryptor drives to
/// obtain a fresh plaintext data key on encrypt and recover it on decrypt.
///
/// The item header persists the [`WrappedDataKey`] a keyring returns from
/// [`on_encrypt`](Keyring::on_encrypt); [`on_decrypt`](Keyring::on_decrypt) is
/// handed that same value to recover the plaintext data key. This decouples the
/// (synchronous, pure-crypto) item encryptor from how a particular keyring kind
/// wraps the data key — a Raw AES keyring does it locally (see [`RawAesKeyring`]),
/// while a KMS keyring performs network calls. The trait stays synchronous; an
/// I/O-bound keyring bridges to its async client internally.
pub trait Keyring {
    /// Produce a fresh plaintext data key together with the wrapped form to
    /// persist in the item header ("OnEncrypt → Generate + Encrypt Data Key").
    fn on_encrypt(&self) -> Result<(Vec<u8>, WrappedDataKey)>;

    /// Recover the plaintext data key from the header's wrapped form
    /// ("OnDecrypt → Decrypt Data Key"). Fails if the wrapped key cannot be
    /// recovered under this keyring's key material / identity.
    fn on_decrypt(&self, wrapped: &WrappedDataKey) -> Result<Vec<u8>>;
}

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

impl Keyring for RawAesKeyring {
    fn on_encrypt(&self) -> Result<(Vec<u8>, WrappedDataKey)> {
        self.generate_and_wrap()
    }

    fn on_decrypt(&self, wrapped: &WrappedDataKey) -> Result<Vec<u8>> {
        self.unwrap(wrapped)
    }
}

/// Map the configured RSA padding scheme to the crypto-layer padding.
fn rsa_padding(scheme: PaddingScheme) -> crypto::RsaPadding {
    match scheme {
        PaddingScheme::Pkcs1 => crypto::RsaPadding::Pkcs1,
        PaddingScheme::OaepSha1Mgf1 => crypto::RsaPadding::OaepSha1,
        PaddingScheme::OaepSha256Mgf1 => crypto::RsaPadding::OaepSha256,
        PaddingScheme::OaepSha384Mgf1 => crypto::RsaPadding::OaepSha384,
        PaddingScheme::OaepSha512Mgf1 => crypto::RsaPadding::OaepSha512,
    }
}

/// Map the configured ECDH curve to the crypto-layer curve.
fn ecdh_curve(spec: EcdhCurveSpec) -> crypto::EcdhCurve {
    match spec {
        EcdhCurveSpec::EccNistP256 => crypto::EcdhCurve::P256,
        EcdhCurveSpec::EccNistP384 => crypto::EcdhCurve::P384,
        EcdhCurveSpec::EccNistP521 => crypto::EcdhCurve::P521,
    }
}

/// A Raw RSA keyring built from a [`RawRsaKeyringConfig`].
///
/// The data key is wrapped directly with RSA (OAEP or PKCS#1 v1.5) under the
/// configured public key on encrypt and recovered with the private key on
/// decrypt. The public / private keys are PEM-encoded in the configuration and
/// parsed to DER once at construction.
pub struct RawRsaKeyring {
    key_namespace: String,
    key_name: String,
    padding: crypto::RsaPadding,
    /// DER X.509 SubjectPublicKeyInfo, present when the keyring can encrypt.
    public_key_der: Option<Vec<u8>>,
    /// DER PKCS#8 PrivateKeyInfo, present when the keyring can decrypt.
    private_key_der: Option<Vec<u8>>,
}

impl RawRsaKeyring {
    /// Build a keyring from its (validated) configuration, decoding the supplied
    /// PEM public / private keys to DER.
    pub fn new(config: &RawRsaKeyringConfig) -> Result<Self> {
        let public_key_der = config
            .public_key
            .as_deref()
            .map(crypto::pem_to_der)
            .transpose()?;
        let private_key_der = config
            .private_key
            .as_deref()
            .map(crypto::pem_to_der)
            .transpose()?;
        Ok(Self {
            key_namespace: config.key_namespace.clone(),
            key_name: config.key_name.clone(),
            padding: rsa_padding(config.padding_scheme),
            public_key_der,
            private_key_der,
        })
    }
}

impl Keyring for RawRsaKeyring {
    fn on_encrypt(&self) -> Result<(Vec<u8>, WrappedDataKey)> {
        let public_key_der = self.public_key_der.as_deref().ok_or_else(|| {
            DbEsdkError::crypto("Raw RSA keyring has no public key and cannot encrypt")
        })?;
        let plaintext_data_key = crypto::random_bytes(DATA_KEY_LEN)?;
        let ciphertext = crypto::rsa_encrypt(public_key_der, self.padding, &plaintext_data_key)?;
        Ok((
            plaintext_data_key,
            WrappedDataKey {
                key_namespace: self.key_namespace.clone(),
                key_name: self.key_name.clone(),
                ciphertext,
            },
        ))
    }

    fn on_decrypt(&self, wrapped: &WrappedDataKey) -> Result<Vec<u8>> {
        if wrapped.key_namespace != self.key_namespace || wrapped.key_name != self.key_name {
            return Err(DbEsdkError::crypto(
                "wrapped data key was produced under a different keyring (namespace/name mismatch)",
            ));
        }
        let private_key_der = self.private_key_der.as_deref().ok_or_else(|| {
            DbEsdkError::crypto("Raw RSA keyring has no private key and cannot decrypt")
        })?;
        crypto::rsa_decrypt(private_key_der, self.padding, &wrapped.ciphertext)
    }
}

/// A Raw ECDH keyring built from a [`RawEcdhKeyringConfig`] (the
/// RawPrivateKeyToStaticPublicKey scheme).
///
/// Data-key wrapping derives a symmetric wrapping key from the ECDH shared
/// secret between the sender's static private key and the recipient's static
/// public key, then wraps the data key with AES-GCM (like the Raw AES keyring).
/// Because both encrypt and decrypt hold the same sender private key and
/// recipient public key, they derive the same shared secret — so what this
/// keyring wraps it can unwrap.
pub struct RawEcdhKeyring {
    sender_private_key_der: Vec<u8>,
    recipient_public_key_der: Vec<u8>,
    curve: crypto::EcdhCurve,
}

/// Fixed keyring identity bound into the [`WrappedDataKey`] of a Raw ECDH
/// keyring (the config carries no namespace / name).
const RAW_ECDH_NAMESPACE: &str = "raw-ecdh";
/// Fixed keyring name for a Raw ECDH-wrapped data key.
const RAW_ECDH_NAME: &str = "raw-ecdh-static";

impl RawEcdhKeyring {
    /// Build a keyring from its (validated) configuration, decoding the sender
    /// private key from PEM PKCS#8 to DER.
    pub fn new(config: &RawEcdhKeyringConfig) -> Result<Self> {
        let sender_private_key_der = crypto::pem_to_der(&config.sender_static_private_key)?;
        Ok(Self {
            sender_private_key_der,
            recipient_public_key_der: config.recipient_public_key.clone(),
            curve: ecdh_curve(config.curve_spec),
        })
    }

    /// Derive the AES-256 wrapping key from the ECDH shared secret.
    fn derive_wrapping_key(&self) -> Result<Vec<u8>> {
        let shared_secret = crypto::ecdh_shared_secret(
            &self.sender_private_key_der,
            &self.recipient_public_key_der,
            self.curve,
        )?;
        crypto::hkdf_sha384(&shared_secret, b"aws-dbe raw ecdh wrapping key", DATA_KEY_LEN)
    }

    /// The AAD bound into the AES-GCM wrap of the data key (the fixed keyring
    /// identity), mirroring the Raw AES keyring's binding.
    fn wrap_aad() -> Vec<u8> {
        let mut aad = Vec::new();
        let ns = RAW_ECDH_NAMESPACE.as_bytes();
        let name = RAW_ECDH_NAME.as_bytes();
        aad.extend_from_slice(&(ns.len() as u32).to_be_bytes());
        aad.extend_from_slice(ns);
        aad.extend_from_slice(&(name.len() as u32).to_be_bytes());
        aad.extend_from_slice(name);
        aad
    }
}

impl Keyring for RawEcdhKeyring {
    fn on_encrypt(&self) -> Result<(Vec<u8>, WrappedDataKey)> {
        let plaintext_data_key = crypto::random_bytes(DATA_KEY_LEN)?;
        let wrapping_key = self.derive_wrapping_key()?;
        let ciphertext =
            crypto::aes_gcm_seal(&wrapping_key, &Self::wrap_aad(), &plaintext_data_key)?;
        Ok((
            plaintext_data_key,
            WrappedDataKey {
                key_namespace: RAW_ECDH_NAMESPACE.to_string(),
                key_name: RAW_ECDH_NAME.to_string(),
                ciphertext,
            },
        ))
    }

    fn on_decrypt(&self, wrapped: &WrappedDataKey) -> Result<Vec<u8>> {
        if wrapped.key_namespace != RAW_ECDH_NAMESPACE || wrapped.key_name != RAW_ECDH_NAME {
            return Err(DbEsdkError::crypto(
                "wrapped data key was not produced by a Raw ECDH keyring (namespace/name mismatch)",
            ));
        }
        let wrapping_key = self.derive_wrapping_key()?;
        crypto::aes_gcm_open(&wrapping_key, &Self::wrap_aad(), &wrapped.ciphertext)
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

    // --- Raw RSA / Raw ECDH test helpers ----------------------------------

    /// Minimal standard base64 encoder (test-only) for building PEM documents.
    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
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

    fn to_pem(label: &str, der: &[u8]) -> Vec<u8> {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            base64_encode(der)
        )
        .into_bytes()
    }

    /// Generate an RSA key pair as (public PEM X.509 SPKI, private PEM PKCS#8).
    fn rsa_key_pair_pem() -> (Vec<u8>, Vec<u8>) {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
        use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let private_der = AsDer::<Pkcs8V1Der>::as_der(&private).unwrap();
        let public_der = AsDer::<PublicKeyX509Der>::as_der(&private.public_key()).unwrap();
        (
            to_pem("PUBLIC KEY", public_der.as_ref()),
            to_pem("PRIVATE KEY", private_der.as_ref()),
        )
    }

    fn raw_rsa_config(public_key: Option<Vec<u8>>, private_key: Option<Vec<u8>>) -> RawRsaKeyringConfig {
        RawRsaKeyringConfig {
            key_namespace: "test-server-namespace".to_string(),
            key_name: "raw-rsa-key".to_string(),
            padding_scheme: PaddingScheme::OaepSha256Mgf1,
            public_key,
            private_key,
        }
    }

    #[test]
    fn raw_rsa_wrap_unwrap_round_trips() {
        let (public_pem, private_pem) = rsa_key_pair_pem();
        let k = RawRsaKeyring::new(&raw_rsa_config(Some(public_pem), Some(private_pem))).unwrap();
        let (pdk, wrapped) = k.on_encrypt().unwrap();
        assert_eq!(pdk.len(), DATA_KEY_LEN);
        assert_eq!(wrapped.key_namespace, "test-server-namespace");
        let recovered = k.on_decrypt(&wrapped).unwrap();
        assert_eq!(recovered, pdk);
    }

    #[test]
    fn raw_rsa_encrypt_only_keyring_cannot_decrypt() {
        let (public_pem, _private_pem) = rsa_key_pair_pem();
        let k = RawRsaKeyring::new(&raw_rsa_config(Some(public_pem), None)).unwrap();
        let (_pdk, wrapped) = k.on_encrypt().unwrap();
        assert!(k.on_decrypt(&wrapped).is_err());
    }

    #[test]
    fn raw_rsa_decrypt_only_keyring_cannot_encrypt() {
        let (_public_pem, private_pem) = rsa_key_pair_pem();
        let k = RawRsaKeyring::new(&raw_rsa_config(None, Some(private_pem))).unwrap();
        assert!(k.on_encrypt().is_err());
    }

    #[test]
    fn raw_rsa_unwrap_rejects_tampered_ciphertext() {
        let (public_pem, private_pem) = rsa_key_pair_pem();
        let k = RawRsaKeyring::new(&raw_rsa_config(Some(public_pem), Some(private_pem))).unwrap();
        let (_pdk, mut wrapped) = k.on_encrypt().unwrap();
        let last = wrapped.ciphertext.len() - 1;
        wrapped.ciphertext[last] ^= 0x01;
        assert!(k.on_decrypt(&wrapped).is_err());
    }

    /// Generate a P-256 ECDH config where the one key pair is both the sender
    /// (private PEM PKCS#8) and the recipient (public DER X.509 SPKI), mirroring
    /// the conformance test's RawPrivateKeyToStaticPublicKey usage.
    fn raw_ecdh_config() -> RawEcdhKeyringConfig {
        use aws_lc_rs::agreement::{PrivateKey, ECDH_P256};
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};

        let private = PrivateKey::generate(&ECDH_P256).unwrap();
        let private_der = AsDer::<Pkcs8V1Der>::as_der(&private).unwrap();
        let public = private.compute_public_key().unwrap();
        let public_der = AsDer::<PublicKeyX509Der>::as_der(&public).unwrap();
        RawEcdhKeyringConfig {
            sender_static_private_key: to_pem("PRIVATE KEY", private_der.as_ref()),
            recipient_public_key: public_der.as_ref().to_vec(),
            curve_spec: EcdhCurveSpec::EccNistP256,
        }
    }

    #[test]
    fn raw_ecdh_wrap_unwrap_round_trips() {
        let k = RawEcdhKeyring::new(&raw_ecdh_config()).unwrap();
        let (pdk, wrapped) = k.on_encrypt().unwrap();
        assert_eq!(pdk.len(), DATA_KEY_LEN);
        assert_eq!(wrapped.key_namespace, RAW_ECDH_NAMESPACE);
        let recovered = k.on_decrypt(&wrapped).unwrap();
        assert_eq!(recovered, pdk);
    }

    #[test]
    fn raw_ecdh_unwrap_rejects_tampered_ciphertext() {
        let k = RawEcdhKeyring::new(&raw_ecdh_config()).unwrap();
        let (_pdk, mut wrapped) = k.on_encrypt().unwrap();
        let last = wrapped.ciphertext.len() - 1;
        wrapped.ciphertext[last] ^= 0x01;
        assert!(k.on_decrypt(&wrapped).is_err());
    }

    #[test]
    fn raw_ecdh_decrypt_rejects_a_different_key_pair() {
        let writer = RawEcdhKeyring::new(&raw_ecdh_config()).unwrap();
        let (_pdk, wrapped) = writer.on_encrypt().unwrap();
        let other = RawEcdhKeyring::new(&raw_ecdh_config()).unwrap();
        assert!(other.on_decrypt(&wrapped).is_err());
    }
}
