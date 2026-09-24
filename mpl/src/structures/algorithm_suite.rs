// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Algorithm suite identifiers, suite specifications, and associated key newtypes.

use std::fmt;

// ============================================================================
// Algorithm suite ID enum
// ============================================================================

/// Identifies an algorithm suite supported by this Material Providers Library.
///
/// This enum exposes only the ESDK supported formats; DBE and S3EC suites are
/// not implemented (see the `type=exception` annotations on this declaration).
/// Construct an `AlgorithmSuite` from a variant via [`Self::specification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AlgorithmSuiteId {
    /// 00 14 — ESDK.ALG_AES_128_GCM_IV12_TAG16_NO_KDF
    AlgAes128GcmIv12Tag16NoKdf,
    /// 00 46 — ESDK.ALG_AES_192_GCM_IV12_TAG16_NO_KDF
    AlgAes192GcmIv12Tag16NoKdf,
    /// 00 78 — ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
    AlgAes256GcmIv12Tag16NoKdf,
    /// 01 14 — ESDK.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256
    AlgAes128GcmIv12Tag16HkdfSha256,
    /// 01 46 — ESDK.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256
    AlgAes192GcmIv12Tag16HkdfSha256,
    /// 01 78 — ESDK.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256
    AlgAes256GcmIv12Tag16HkdfSha256,
    /// 02 14 — ESDK.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
    /// 03 46 — ESDK.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
    /// 03 78 — ESDK.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    /// 04 78 — ESDK.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    AlgAes256GcmHkdfSha512CommitKey,
    /// 05 78 — ESDK.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
}

/// Backing array for [`AlgorithmSuiteId::ALL`], in ascending on-wire id order.
///
/// Kept in step with the enum by `exhaustive_over_algorithm_suite_id` below.
const ALL_SUITES: [AlgorithmSuiteId; 11] = [
    AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
    AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
    AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
    AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
    AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
    AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
];

// Ties `ALL_SUITES` to `AlgorithmSuiteId` at compile time. The match has no
// wildcard arm, so a suite added to `AlgorithmSuiteId` fails to compile until it
// is mapped here; each arm indexes `ALL_SUITES`, so the array must grow to match
// or the index fails const evaluation. Never called -- the coupling is the point.
#[expect(
    dead_code,
    reason = "exists for its exhaustiveness check, not to be called"
)]
const fn exhaustive_over_algorithm_suite_id(id: AlgorithmSuiteId) -> AlgorithmSuiteId {
    match id {
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf => ALL_SUITES[0],
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf => ALL_SUITES[1],
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf => ALL_SUITES[2],
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256 => ALL_SUITES[3],
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256 => ALL_SUITES[4],
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256 => ALL_SUITES[5],
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => ALL_SUITES[6],
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => ALL_SUITES[7],
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => ALL_SUITES[8],
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey => ALL_SUITES[9],
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => ALL_SUITES[10],
    }
}

impl AlgorithmSuiteId {
    /// Every algorithm suite id, in ascending on-wire id order.
    pub const ALL: &'static [AlgorithmSuiteId] = &ALL_SUITES;

    /// Resolves a 2-byte on-wire algorithm suite identifier to its suite id.
    /// The inverse of [`Self::id_bytes`].
    ///
    /// Returns `None` if no suite has that identifier.
    pub fn from_id_bytes(bytes: [u8; 2]) -> Option<AlgorithmSuiteId> {
        Self::ALL.iter().copied().find(|id| id.id_bytes() == bytes)
    }

    /// Materialize the [`AlgorithmSuite`] specification table for this suite ID.
    pub const fn specification(self) -> AlgorithmSuite {
        match self {
            Self::AlgAes128GcmIv12Tag16NoKdf => AlgorithmSuite {
                //
                id: [0x00, 0x14],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 16,
                iv_length: 12,
                authentication_tag_length: 16,
                //
                //
                encryption_kdf: KeyDerivationAlgorithm::IdentityKdf,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes192GcmIv12Tag16NoKdf => AlgorithmSuite {
                id: [0x00, 0x46],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 24,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::IdentityKdf,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes256GcmIv12Tag16NoKdf => AlgorithmSuite {
                id: [0x00, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::IdentityKdf,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes128GcmIv12Tag16HkdfSha256 => AlgorithmSuite {
                id: [0x01, 0x14],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 16,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha256,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes192GcmIv12Tag16HkdfSha256 => AlgorithmSuite {
                id: [0x01, 0x46],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 24,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha256,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes256GcmIv12Tag16HkdfSha256 => AlgorithmSuite {
                id: [0x01, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha256,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => AlgorithmSuite {
                id: [0x02, 0x14],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 16,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha256,
                commit_kdf: None,
                //
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP256),
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => AlgorithmSuite {
                id: [0x03, 0x46],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 24,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha384,
                commit_kdf: None,
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP384),
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => AlgorithmSuite {
                id: [0x03, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha384,
                commit_kdf: None,
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP384),
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes256GcmHkdfSha512CommitKey => AlgorithmSuite {
                id: [0x04, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha512,
                commit_kdf: Some(KeyDerivationAlgorithm::HkdfSha512),
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x02,
                algorithm_suite_data_length: 32,
            },
            Self::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => AlgorithmSuite {
                id: [0x05, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha512,
                commit_kdf: Some(KeyDerivationAlgorithm::HkdfSha512),
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP384),
                symmetric_signature_algorithm: None,
                message_format_version: 0x02,
                algorithm_suite_data_length: 32,
            },
        }
    }

    /// Returns the on-wire 2-byte algorithm suite identifier.
    ///
    /// The byte pair is unique across the supported-suites table. Reserved
    /// value `00 00` is never produced.
    //
    pub const fn id_bytes(self) -> [u8; 2] {
        self.specification().id
    }

    /// Returns true when this suite has an asymmetric signature algorithm.
    pub const fn has_asymmetric_signing(self) -> bool {
        self.specification()
            .asymmetric_signature_algorithm
            .is_some()
    }

    /// Returns true when this suite has a symmetric signature algorithm.
    ///
    /// No ESDK suite includes a symmetric signature algorithm; this is always
    /// `false` for any constructible variant of `AlgorithmSuiteId`. The
    /// MUST-NOT-generate / MUST-NOT-verify clauses are enforced at the
    /// `EncryptionMaterials::new` / `DecryptionMaterials::new` boundary.
    pub const fn has_symmetric_signing(self) -> bool {
        self.specification().symmetric_signature_algorithm.is_some()
    }
}

// ============================================================================
// Algorithm suite specification table (opaque struct)
// ============================================================================

/// The set of cryptographic parameters defined by an [`AlgorithmSuiteId`].
///
/// This struct is opaque: there is no public constructor. Construct one by
/// calling [`AlgorithmSuiteId::specification`] on a chosen suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmSuite {
    id: [u8; 2],
    encryption_algorithm: EncryptionAlgorithm,
    encryption_algorithm_mode: EncryptionAlgorithmMode,
    encryption_key_length: usize,
    iv_length: usize,
    authentication_tag_length: usize,
    encryption_kdf: KeyDerivationAlgorithm,
    commit_kdf: Option<KeyDerivationAlgorithm>,
    asymmetric_signature_algorithm: Option<AsymmetricSignatureAlgorithm>,
    symmetric_signature_algorithm: Option<SymmetricSignatureAlgorithm>,
    message_format_version: u8,
    algorithm_suite_data_length: usize,
}

impl AlgorithmSuite {
    /// Returns the suite's 2-byte algorithm suite identifier.
    pub const fn id(&self) -> [u8; 2] {
        self.id
    }

    pub const fn encryption_algorithm(&self) -> EncryptionAlgorithm {
        self.encryption_algorithm
    }

    pub const fn encryption_algorithm_mode(&self) -> EncryptionAlgorithmMode {
        self.encryption_algorithm_mode
    }

    /// Returns the encryption key length, in bytes.
    pub const fn encryption_key_length(&self) -> usize {
        self.encryption_key_length
    }

    /// Returns the IV length, in bytes (12 for every ESDK suite).
    pub const fn iv_length(&self) -> usize {
        self.iv_length
    }

    /// Returns the authentication tag length, in bytes (16 for every ESDK suite).
    pub const fn authentication_tag_length(&self) -> usize {
        self.authentication_tag_length
    }

    pub const fn encryption_kdf(&self) -> KeyDerivationAlgorithm {
        self.encryption_kdf
    }

    pub const fn commit_kdf(&self) -> Option<KeyDerivationAlgorithm> {
        self.commit_kdf
    }

    /// Returns true when this suite has a commitment KDF (i.e. its
    /// [Key Commitment] value is True). Convenience predicate so callers can
    /// match the spec phrasing literally.
    ///
    /// [Key Commitment]: ../../../spec/framework/algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings
    pub const fn key_commitment(&self) -> bool {
        self.commit_kdf.is_some()
    }

    pub const fn asymmetric_signature_algorithm(&self) -> Option<AsymmetricSignatureAlgorithm> {
        self.asymmetric_signature_algorithm
    }

    pub const fn symmetric_signature_algorithm(&self) -> Option<SymmetricSignatureAlgorithm> {
        self.symmetric_signature_algorithm
    }

    /// Returns the message format version byte (`0x01` for V1, `0x02` for V2).
    pub const fn message_format_version(&self) -> u8 {
        self.message_format_version
    }

    /// Returns the algorithm suite data field length, in bytes.
    pub const fn algorithm_suite_data_length(&self) -> usize {
        self.algorithm_suite_data_length
    }

    /// Required length of a verification key (public point, SEC1 compressed
    /// `tag || X` where `tag` is `0x02` when Y is even and `0x03` when Y is
    /// odd) for this suite, in bytes. Returns `None` for non-signing suites.
    pub const fn verification_key_length(&self) -> Option<usize> {
        match self.asymmetric_signature_algorithm {
            Some(AsymmetricSignatureAlgorithm::EcdsaP256) => Some(VERIFICATION_KEY_LEN_P256),
            Some(AsymmetricSignatureAlgorithm::EcdsaP384) => Some(VERIFICATION_KEY_LEN_P384),
            None => None,
        }
    }
}

// SEC1-compressed public key lengths: 1 byte tag + coord_len
const VERIFICATION_KEY_LEN_P256: usize = 33;
const VERIFICATION_KEY_LEN_P384: usize = 49;

// ============================================================================
// Encryption / KDF / signature algorithm enums
// ============================================================================

/// Block cipher encryption algorithm. Always AES for every ESDK suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncryptionAlgorithm {
    Aes,
}

/// Block cipher mode of operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncryptionAlgorithmMode {
    Gcm,
}

/// Key derivation algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyDerivationAlgorithm {
    /// Identity KDF — input bytes are returned unchanged.
    IdentityKdf,
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

/// Asymmetric signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AsymmetricSignatureAlgorithm {
    /// ECDSA with P-256 curve and SHA-256.
    EcdsaP256,
    /// ECDSA with P-384 curve and SHA-384.
    EcdsaP384,
}

/// Symmetric signature algorithm. No ESDK suite uses one; the variant exists so
/// `Option<SymmetricSignatureAlgorithm>` can express "OPTIONAL" per spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymmetricSignatureAlgorithm {
    HmacSha384,
}

// ============================================================================
// Cryptographic format identifier (ESDK only)
// ============================================================================

/// Cryptographic format identifier. Only the ESDK format is implemented in this
/// MPL — uniqueness of short and long name is trivial (single variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// AWS Encryption SDK Message Format / "ESDK".
    Esdk,
}

impl Format {
    pub const fn long_name(self) -> &'static str {
        match self {
            Self::Esdk => "AWS Encryption SDK Message Format",
        }
    }

    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Esdk => "ESDK",
        }
    }
}

// ============================================================================
// Key newtypes
// ============================================================================

/// Plaintext data key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct PlaintextDataKey(Vec<u8>);

impl PlaintextDataKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Zero the plaintext data key material.
    //
    pub fn zeroize(&mut self) {
        let ptr = self.0.as_mut_ptr();
        let len = self.0.len();
        for i in 0..len {
            // SAFETY: we're within bounds of the allocated Vec
            unsafe {
                core::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
}

impl fmt::Debug for PlaintextDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlaintextDataKey([REDACTED; {} bytes])", self.0.len())
    }
}

/// Signing key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKey(Vec<u8>);

impl SigningKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey([REDACTED; {} bytes])", self.0.len())
    }
}

/// Verification key (public, not secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey(Vec<u8>);

impl VerificationKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Symmetric signing key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct SymmetricSigningKey(Vec<u8>);

impl SymmetricSigningKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SymmetricSigningKey {
    //
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymmetricSigningKey([REDACTED; {} bytes])", self.0.len())
    }
}
