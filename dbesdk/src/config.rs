// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-table encryption configuration: the typed mirror of the TestServer
//! `TableEncryptionConfig` the `CreateClient` operation supplies.
//!
//! The server decodes the `CreateClient` CBOR into these types and stores them
//! in the client registry; `WriteItem` / `ReadItem` then drive
//! [`crate::encrypt`] from the resolved [`TableEncryptionConfig`].

use std::collections::BTreeMap;

use crate::error::{DbEsdkError, Result};

/// The action taken for an attribute on encrypt (mirror of the structured
/// encryption `CryptoAction` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAction {
    /// Encrypt the value and include it in the signature.
    EncryptAndSign,
    /// Sign-only, and additionally include in the encryption context.
    SignAndIncludeInEncryptionContext,
    /// Sign the value but do not encrypt it.
    SignOnly,
    /// Neither sign nor encrypt the value.
    DoNothing,
}

impl CryptoAction {
    /// Parse the model enum's wire spelling (e.g. `"ENCRYPT_AND_SIGN"`).
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "ENCRYPT_AND_SIGN" => Ok(Self::EncryptAndSign),
            "SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT" => {
                Ok(Self::SignAndIncludeInEncryptionContext)
            }
            "SIGN_ONLY" => Ok(Self::SignOnly),
            "DO_NOTHING" => Ok(Self::DoNothing),
            other => Err(DbEsdkError::config(format!(
                "unknown crypto action '{other}'"
            ))),
        }
    }

    /// Whether this action encrypts the attribute value.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::EncryptAndSign)
    }

    /// Whether this action includes the attribute in the signature.
    pub fn is_signed(self) -> bool {
        !matches!(self, Self::DoNothing)
    }

    /// A stable one-byte code for the canonical signed form.
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::EncryptAndSign => 1,
            Self::SignAndIncludeInEncryptionContext => 2,
            Self::SignOnly => 3,
            Self::DoNothing => 4,
        }
    }
}

/// The DBE algorithm suite id (mirror of `DBEAlgorithmSuiteId`).
///
/// Only the symmetric-signing suite is fully exercised by the no-KMS round-trip
/// path this milestone targets; the ECDSA-signing suite is recognized so the
/// configuration decodes, with its signing behavior deferred to a later
/// milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmSuiteId {
    /// `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384`.
    EcdsaP384SymsigHmacSha384,
    /// `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384`.
    SymsigHmacSha384,
}

impl AlgorithmSuiteId {
    /// Parse the model enum's wire spelling.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384" => {
                Ok(Self::EcdsaP384SymsigHmacSha384)
            }
            "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384" => {
                Ok(Self::SymsigHmacSha384)
            }
            other => Err(DbEsdkError::config(format!(
                "unknown DBE algorithm suite id '{other}'"
            ))),
        }
    }

    /// The default suite when the configuration does not specify one (the
    /// symmetric-signing, key-committing suite).
    pub fn default_suite() -> Self {
        Self::SymsigHmacSha384
    }

    /// A stable two-byte code stored in the item header.
    pub(crate) fn code(self) -> u16 {
        match self {
            Self::EcdsaP384SymsigHmacSha384 => 0x0001,
            Self::SymsigHmacSha384 => 0x0002,
        }
    }

    /// Resolve a header code back to a suite id.
    pub(crate) fn from_code(code: u16) -> Result<Self> {
        match code {
            0x0001 => Ok(Self::EcdsaP384SymsigHmacSha384),
            0x0002 => Ok(Self::SymsigHmacSha384),
            other => Err(DbEsdkError::invalid_item(format!(
                "unknown algorithm suite code 0x{other:04x} in item header"
            ))),
        }
    }
}

/// The AES-GCM wrapping algorithm of a Raw AES keyring (mirror of the MPL
/// `AesWrappingAlg`); the variant fixes the wrapping-key length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesWrappingAlg {
    /// 128-bit wrapping key.
    Aes128,
    /// 192-bit wrapping key.
    Aes192,
    /// 256-bit wrapping key.
    Aes256,
}

impl AesWrappingAlg {
    /// Parse the model enum's wire spelling.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "ALG_AES128_GCM_IV12_TAG16" => Ok(Self::Aes128),
            "ALG_AES192_GCM_IV12_TAG16" => Ok(Self::Aes192),
            "ALG_AES256_GCM_IV12_TAG16" => Ok(Self::Aes256),
            other => Err(DbEsdkError::config(format!(
                "unknown AES wrapping algorithm '{other}'"
            ))),
        }
    }

    /// The required wrapping-key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

/// Configuration for a Raw AES keyring (mirror of `RawAesKeyringConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAesKeyringConfig {
    /// Namespace associated with the wrapping key.
    pub key_namespace: String,
    /// Name associated with the wrapping key.
    pub key_name: String,
    /// Raw AES wrapping-key bytes (length must match `wrapping_alg`).
    pub wrapping_key: Vec<u8>,
    /// The AES-GCM wrapping algorithm.
    pub wrapping_alg: AesWrappingAlg,
}

/// The RSA padding scheme of a Raw RSA keyring (mirror of the MPL
/// `PaddingScheme`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingScheme {
    /// RSA PKCS#1 v1.5 padding.
    Pkcs1,
    /// RSA-OAEP with SHA-1 and MGF1.
    OaepSha1Mgf1,
    /// RSA-OAEP with SHA-256 and MGF1.
    OaepSha256Mgf1,
    /// RSA-OAEP with SHA-384 and MGF1.
    OaepSha384Mgf1,
    /// RSA-OAEP with SHA-512 and MGF1.
    OaepSha512Mgf1,
}

impl PaddingScheme {
    /// Parse the model enum's wire spelling.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "PKCS1" => Ok(Self::Pkcs1),
            "OAEP_SHA1_MGF1" => Ok(Self::OaepSha1Mgf1),
            "OAEP_SHA256_MGF1" => Ok(Self::OaepSha256Mgf1),
            "OAEP_SHA384_MGF1" => Ok(Self::OaepSha384Mgf1),
            "OAEP_SHA512_MGF1" => Ok(Self::OaepSha512Mgf1),
            other => Err(DbEsdkError::config(format!(
                "unknown RSA padding scheme '{other}'"
            ))),
        }
    }
}

/// The named elliptic curve of a Raw ECDH keyring (mirror of the MPL
/// `ECDHCurveSpec`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhCurveSpec {
    /// NIST P-256 (secp256r1).
    EccNistP256,
    /// NIST P-384 (secp384r1).
    EccNistP384,
    /// NIST P-521 (secp521r1).
    EccNistP521,
}

impl EcdhCurveSpec {
    /// Parse the model enum's wire spelling. `SM2` is recognized by the model
    /// but not supported by this implementation.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "ECC_NIST_P256" => Ok(Self::EccNistP256),
            "ECC_NIST_P384" => Ok(Self::EccNistP384),
            "ECC_NIST_P521" => Ok(Self::EccNistP521),
            "SM2" => Err(DbEsdkError::config(
                "ECDH curve 'SM2' is not supported by this implementation",
            )),
            other => Err(DbEsdkError::config(format!(
                "unknown ECDH curve spec '{other}'"
            ))),
        }
    }
}

/// Configuration for a Raw RSA keyring (mirror of `RawRsaKeyringConfig`). At
/// least one of `public_key` (to encrypt) / `private_key` (to decrypt) must be
/// supplied; the round-trip suite supplies both, PEM-encoded as UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRsaKeyringConfig {
    /// Namespace associated with this wrapping key.
    pub key_namespace: String,
    /// Name associated with this wrapping key.
    pub key_name: String,
    /// The RSA padding scheme used to wrap the data key.
    pub padding_scheme: PaddingScheme,
    /// The public RSA key as PEM-encoded X.509 SubjectPublicKeyInfo UTF-8 bytes
    /// (needed to encrypt), if supplied.
    pub public_key: Option<Vec<u8>>,
    /// The private RSA key as PEM-encoded PKCS#8 PrivateKeyInfo UTF-8 bytes
    /// (needed to decrypt), if supplied.
    pub private_key: Option<Vec<u8>>,
}

/// Configuration for a Raw ECDH keyring using the RawPrivateKeyToStaticPublicKey
/// agreement scheme (mirror of `RawEcdhKeyringConfig`). No AWS access needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEcdhKeyringConfig {
    /// The sender's static private key as PEM-encoded PKCS#8 PrivateKeyInfo
    /// UTF-8 bytes.
    pub sender_static_private_key: Vec<u8>,
    /// The recipient's public key as raw DER-encoded X.509 SubjectPublicKeyInfo
    /// bytes.
    pub recipient_public_key: Vec<u8>,
    /// The named curve both keys lie on.
    pub curve_spec: EcdhCurveSpec,
}

/// Configuration for an AWS KMS keyring keyed by a single KMS key id (the
/// `awsKms` and `awsKmsMrk` variants share this shape). Mirrors
/// `CreateAwsKmsKeyringInput` / `CreateAwsKmsMrkKeyringInput`; the server
/// supplies the KMS client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsKeyringConfig {
    /// The AWS KMS key identifier (key id, alias, or ARN).
    pub kms_key_id: String,
    /// Optional grant tokens to use when calling KMS.
    pub grant_tokens: Vec<String>,
}

/// Configuration for an AWS KMS MRK multi-keyring (mirror of
/// `AwsKmsMrkMultiKeyringConfig`): an optional generator key plus any number of
/// additional key ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsMrkMultiKeyringConfig {
    /// The generator KMS key id (key id, alias, or ARN), if any.
    pub generator: Option<String>,
    /// Additional KMS key ids (other than the generator).
    pub kms_key_ids: Vec<String>,
}

/// The RSA wrapping algorithm of an AWS KMS RSA keyring (mirror of the KMS
/// `EncryptionAlgorithmSpec` values the model exposes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsRsaEncryptionAlgorithm {
    /// `RSAES_OAEP_SHA_256`.
    OaepSha256,
    /// `RSAES_OAEP_SHA_1`.
    OaepSha1,
}

impl KmsRsaEncryptionAlgorithm {
    /// Parse the model enum's wire spelling.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "RSAES_OAEP_SHA_256" => Ok(Self::OaepSha256),
            "RSAES_OAEP_SHA_1" => Ok(Self::OaepSha1),
            other => Err(DbEsdkError::config(format!(
                "unknown KMS RSA encryption algorithm '{other}'"
            ))),
        }
    }
}

/// Configuration for an AWS KMS RSA keyring (mirror of `AwsKmsRsaKeyringConfig`).
/// The data key is wrapped locally with the supplied RSA public key (PEM-encoded
/// X.509 SPKI, as exported from `kms:GetPublicKey`) and unwrapped by KMS
/// `Decrypt` with the configured `encryptionAlgorithm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsRsaKeyringConfig {
    /// The ARN of the asymmetric (ENCRYPT_DECRYPT, RSA) KMS key.
    pub kms_key_id: String,
    /// The RSA wrapping algorithm.
    pub encryption_algorithm: KmsRsaEncryptionAlgorithm,
    /// The RSA public key as PEM-encoded X.509 SPKI UTF-8 bytes (needed to
    /// encrypt). KMS decrypts with the private key it holds.
    pub public_key: Option<Vec<u8>>,
}

/// Configuration for an AWS KMS Discovery keyring (DECRYPT-ONLY) (mirror of
/// `AwsKmsDiscoveryKeyringConfig`). It decrypts using the KMS key ARN recorded
/// in the wrapped data key; an optional account id / partition restricts which
/// keys it will use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsDiscoveryKeyringConfig {
    /// An allowed AWS account id for the optional discovery filter.
    pub account_id: Option<String>,
    /// The AWS partition for the optional discovery filter (default "aws").
    pub partition: Option<String>,
}

/// Configuration for an AWS KMS MRK Discovery keyring (DECRYPT-ONLY, single
/// Region) (mirror of `AwsKmsMrkDiscoveryKeyringConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsMrkDiscoveryKeyringConfig {
    /// The Region this keyring decrypts in.
    pub region: String,
    /// An allowed AWS account id for the optional discovery filter.
    pub account_id: Option<String>,
    /// The AWS partition for the optional discovery filter (default "aws").
    pub partition: Option<String>,
}

/// Configuration for a multi-keyring (mirror of `MultiKeyringConfig`): an
/// optional generator keyring plus a (possibly empty) list of child keyrings.
/// References [`KeyringConfig`] recursively, so any keyring kind can be a
/// generator or child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiKeyringConfig {
    /// The generator keyring configuration (required to encrypt).
    pub generator: Option<Box<KeyringConfig>>,
    /// The child keyring configurations (may be empty).
    pub child_keyrings: Vec<KeyringConfig>,
}

/// A keyring configuration. The Raw AES / RSA / ECDH, AWS KMS (single-key, MRK,
/// MRK-multi, RSA), AWS KMS Discovery (single + MRK), and multi keyring variants
/// are implemented; the remaining kinds (AWS KMS ECDH, hierarchical) are
/// recognized and rejected with a clear modeled error rather than a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringConfig {
    /// A Raw AES keyring.
    RawAes(RawAesKeyringConfig),
    /// A Raw RSA keyring (asymmetric PEM-encoded key pair supplied directly).
    RawRsa(RawRsaKeyringConfig),
    /// A Raw ECDH keyring (RawPrivateKeyToStaticPublicKey agreement scheme).
    RawEcdh(RawEcdhKeyringConfig),
    /// An AWS KMS keyring for a single-Region symmetric KMS key (`awsKms`).
    AwsKms(AwsKmsKeyringConfig),
    /// An AWS KMS MRK keyring (single-Region or Multi-Region key) (`awsKmsMrk`).
    AwsKmsMrk(AwsKmsKeyringConfig),
    /// An AWS KMS MRK multi-keyring (`awsKmsMrkMulti`).
    AwsKmsMrkMulti(AwsKmsMrkMultiKeyringConfig),
    /// An AWS KMS RSA (asymmetric) keyring (`awsKmsRsa`).
    AwsKmsRsa(AwsKmsRsaKeyringConfig),
    /// An AWS KMS Discovery keyring, DECRYPT-ONLY (`awsKmsDiscovery`).
    AwsKmsDiscovery(AwsKmsDiscoveryKeyringConfig),
    /// An AWS KMS MRK Discovery keyring, DECRYPT-ONLY (`awsKmsMrkDiscovery`).
    AwsKmsMrkDiscovery(AwsKmsMrkDiscoveryKeyringConfig),
    /// A multi-keyring composed of an optional generator + child keyrings
    /// (`multi`).
    Multi(MultiKeyringConfig),
    /// Any other keyring kind, carried by its model member name so callers can
    /// report exactly which unsupported kind was requested.
    Unsupported(String),
}

/// Per-table encryption configuration (mirror of `TableEncryptionConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableEncryptionConfig {
    /// The logical table name (bound into the signature's AAD).
    pub logical_table_name: String,
    /// The partition-key attribute name.
    pub partition_key_name: String,
    /// The sort-key attribute name, if any.
    pub sort_key_name: Option<String>,
    /// Attribute name -> action taken on encrypt.
    pub attribute_actions: BTreeMap<String, CryptoAction>,
    /// Attribute names explicitly allowed to be unsigned on decrypt.
    pub allowed_unsigned_attributes: Vec<String>,
    /// Attribute-name prefix treated as unsigned on decrypt.
    pub allowed_unsigned_attribute_prefix: Option<String>,
    /// The algorithm suite (defaulted when absent).
    pub algorithm_suite_id: AlgorithmSuiteId,
    /// The keyring used to wrap / unwrap data keys.
    pub keyring: KeyringConfig,
}

impl TableEncryptionConfig {
    /// Resolve the action configured for `attribute_name`.
    ///
    /// Key attributes (partition / sort) default to `SIGN_ONLY` when no explicit
    /// action is configured; all other unconfigured attributes default to
    /// `DO_NOTHING` (they are passed through untouched).
    pub fn action_for(&self, attribute_name: &str) -> CryptoAction {
        if let Some(action) = self.attribute_actions.get(attribute_name) {
            return *action;
        }
        if self.is_key_attribute(attribute_name) {
            CryptoAction::SignOnly
        } else {
            CryptoAction::DoNothing
        }
    }

    /// Whether `attribute_name` is the partition or sort key.
    pub fn is_key_attribute(&self, attribute_name: &str) -> bool {
        attribute_name == self.partition_key_name
            || self.sort_key_name.as_deref() == Some(attribute_name)
    }

    /// Validate the configuration's internal consistency. Key attributes must
    /// never be encrypted (DynamoDB needs them in plaintext to key the item).
    pub fn validate(&self) -> Result<()> {
        for (name, action) in &self.attribute_actions {
            if self.is_key_attribute(name) && action.is_encrypted() {
                return Err(DbEsdkError::config(format!(
                    "key attribute '{name}' must not be encrypted (it must be SIGN_ONLY)"
                )));
            }
        }
        if let KeyringConfig::RawAes(raw) = &self.keyring {
            let expected = raw.wrapping_alg.key_len();
            if raw.wrapping_key.len() != expected {
                return Err(DbEsdkError::config(format!(
                    "raw AES wrapping key is {} bytes but {:?} requires {expected}",
                    raw.wrapping_key.len(),
                    raw.wrapping_alg
                )));
            }
        }
        match &self.keyring {
            KeyringConfig::AwsKms(c) | KeyringConfig::AwsKmsMrk(c) => {
                if c.kms_key_id.trim().is_empty() {
                    return Err(DbEsdkError::config(
                        "AWS KMS keyring requires a non-empty kmsKeyId",
                    ));
                }
            }
            KeyringConfig::AwsKmsMrkMulti(c) => {
                if c.generator.is_none() && c.kms_key_ids.is_empty() {
                    return Err(DbEsdkError::config(
                        "AWS KMS MRK multi-keyring requires a generator or at least one key id",
                    ));
                }
            }
            KeyringConfig::RawRsa(c) => {
                if c.public_key.is_none() && c.private_key.is_none() {
                    return Err(DbEsdkError::config(
                        "Raw RSA keyring requires a public key (to encrypt) or private key (to decrypt)",
                    ));
                }
            }
            KeyringConfig::RawEcdh(c) => {
                if c.sender_static_private_key.is_empty() || c.recipient_public_key.is_empty() {
                    return Err(DbEsdkError::config(
                        "Raw ECDH keyring requires a sender private key and a recipient public key",
                    ));
                }
            }
            KeyringConfig::AwsKmsRsa(c) => {
                if c.kms_key_id.trim().is_empty() {
                    return Err(DbEsdkError::config(
                        "AWS KMS RSA keyring requires a non-empty kmsKeyId",
                    ));
                }
                if c.public_key.as_ref().is_none_or(|k| k.is_empty()) {
                    return Err(DbEsdkError::config(
                        "AWS KMS RSA keyring requires a public key (to encrypt)",
                    ));
                }
            }
            KeyringConfig::AwsKmsMrkDiscovery(c) => {
                if c.region.trim().is_empty() {
                    return Err(DbEsdkError::config(
                        "AWS KMS MRK Discovery keyring requires a non-empty region",
                    ));
                }
            }
            KeyringConfig::Multi(c) => {
                if c.generator.is_none() && c.child_keyrings.is_empty() {
                    return Err(DbEsdkError::config(
                        "multi-keyring requires a generator or at least one child keyring",
                    ));
                }
                if let Some(generator) = &c.generator {
                    Self::validate_keyring(generator)?;
                }
                for child in &c.child_keyrings {
                    Self::validate_keyring(child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Validate a (possibly nested) keyring configuration in isolation, reusing
    /// the same checks `validate` applies to the table's own keyring. Used to
    /// recurse into a multi-keyring's generator and children.
    fn validate_keyring(keyring: &KeyringConfig) -> Result<()> {
        match keyring {
            KeyringConfig::RawAes(raw) => {
                let expected = raw.wrapping_alg.key_len();
                if raw.wrapping_key.len() != expected {
                    return Err(DbEsdkError::config(format!(
                        "raw AES wrapping key is {} bytes but {:?} requires {expected}",
                        raw.wrapping_key.len(),
                        raw.wrapping_alg
                    )));
                }
                Ok(())
            }
            KeyringConfig::AwsKms(c) | KeyringConfig::AwsKmsMrk(c) => {
                if c.kms_key_id.trim().is_empty() {
                    return Err(DbEsdkError::config(
                        "AWS KMS keyring requires a non-empty kmsKeyId",
                    ));
                }
                Ok(())
            }
            KeyringConfig::AwsKmsMrkMulti(c) => {
                if c.generator.is_none() && c.kms_key_ids.is_empty() {
                    return Err(DbEsdkError::config(
                        "AWS KMS MRK multi-keyring requires a generator or at least one key id",
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TableEncryptionConfig {
        let mut actions = BTreeMap::new();
        actions.insert("partition_key".to_string(), CryptoAction::SignOnly);
        actions.insert("secret".to_string(), CryptoAction::EncryptAndSign);
        TableEncryptionConfig {
            logical_table_name: "T".to_string(),
            partition_key_name: "partition_key".to_string(),
            sort_key_name: None,
            attribute_actions: actions,
            allowed_unsigned_attributes: Vec::new(),
            allowed_unsigned_attribute_prefix: None,
            algorithm_suite_id: AlgorithmSuiteId::default_suite(),
            keyring: KeyringConfig::RawAes(RawAesKeyringConfig {
                key_namespace: "ns".to_string(),
                key_name: "k".to_string(),
                wrapping_key: vec![0u8; 32],
                wrapping_alg: AesWrappingAlg::Aes256,
            }),
        }
    }

    #[test]
    fn action_defaults_distinguish_key_from_non_key() {
        let c = config();
        assert_eq!(c.action_for("secret"), CryptoAction::EncryptAndSign);
        assert_eq!(c.action_for("partition_key"), CryptoAction::SignOnly);
        // Unconfigured non-key attribute is passed through.
        assert_eq!(c.action_for("other"), CryptoAction::DoNothing);
    }

    #[test]
    fn validate_rejects_encrypted_key_attribute() {
        let mut c = config();
        c.attribute_actions
            .insert("partition_key".to_string(), CryptoAction::EncryptAndSign);
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_wrong_wrapping_key_length() {
        let mut c = config();
        c.keyring = KeyringConfig::RawAes(RawAesKeyringConfig {
            key_namespace: "ns".to_string(),
            key_name: "k".to_string(),
            wrapping_key: vec![0u8; 16],
            wrapping_alg: AesWrappingAlg::Aes256,
        });
        assert!(c.validate().is_err());
    }

    #[test]
    fn parsers_accept_known_wire_spellings() {
        assert_eq!(
            CryptoAction::parse("ENCRYPT_AND_SIGN").unwrap(),
            CryptoAction::EncryptAndSign
        );
        assert_eq!(
            AesWrappingAlg::parse("ALG_AES256_GCM_IV12_TAG16").unwrap(),
            AesWrappingAlg::Aes256
        );
        assert!(AlgorithmSuiteId::parse("nope").is_err());
    }

    #[test]
    fn asymmetric_parsers_accept_known_wire_spellings() {
        assert_eq!(
            PaddingScheme::parse("OAEP_SHA256_MGF1").unwrap(),
            PaddingScheme::OaepSha256Mgf1
        );
        assert_eq!(
            EcdhCurveSpec::parse("ECC_NIST_P256").unwrap(),
            EcdhCurveSpec::EccNistP256
        );
        // SM2 is a recognized model spelling we explicitly do not support.
        assert!(EcdhCurveSpec::parse("SM2").is_err());
        assert!(PaddingScheme::parse("nope").is_err());
    }

    #[test]
    fn validate_rejects_raw_rsa_with_no_keys() {
        let mut c = config();
        c.keyring = KeyringConfig::RawRsa(RawRsaKeyringConfig {
            key_namespace: "ns".to_string(),
            key_name: "k".to_string(),
            padding_scheme: PaddingScheme::OaepSha256Mgf1,
            public_key: None,
            private_key: None,
        });
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_raw_ecdh_missing_a_key() {
        let mut c = config();
        c.keyring = KeyringConfig::RawEcdh(RawEcdhKeyringConfig {
            sender_static_private_key: Vec::new(),
            recipient_public_key: vec![1, 2, 3],
            curve_spec: EcdhCurveSpec::EccNistP256,
        });
        assert!(c.validate().is_err());
    }
}
