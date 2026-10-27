// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Algorithm suite identifiers, suite specifications, and associated key newtypes.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::error::Kind;

// ============================================================================
// Algorithm suite ID enum
// ============================================================================

/// Union Algorithm Suite enum across all supported formats.
///
/// Each variant tags a format and carries that format's Algorithm Suite ENUM.
/// For example, `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF` becomes
/// `AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf)`.
/// The ESDK and DBE formats are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AlgorithmSuiteId {
    /// ESDK format algorithm suites.
    Esdk(EsdkAlgorithmSuiteId),
    /// DBE (AWS Database Encryption SDK) format algorithm suites.
    Dbe(DbeAlgorithmSuiteId),
}

impl AlgorithmSuiteId {
    /// Materialize the [`AlgorithmSuite`] specification table for this suite ID.
    pub const fn specification(self) -> AlgorithmSuite {
        match self {
            Self::Esdk(id) => id.specification(),
            Self::Dbe(id) => id.specification(),
        }
    }

    /// Looks up the suite of any format with the given on-wire id; the inverse of [`Self::id_bytes`].
    ///
    /// Returns `None` if no suite has that id.
    pub fn from_id_bytes(bytes: [u8; 2]) -> Option<AlgorithmSuiteId> {
        EsdkAlgorithmSuiteId::from_id_bytes(bytes)
            .map(Self::Esdk)
            .or_else(|| DbeAlgorithmSuiteId::from_id_bytes(bytes).map(Self::Dbe))
    }

    /// The format whose suites this id belongs to.
    pub const fn format(self) -> Format {
        match self {
            Self::Esdk(_) => Format::Esdk,
            Self::Dbe(_) => Format::Dbe,
        }
    }

    /// Returns the 2-byte algorithm suite identifier.
    ///
    /// The identifier is unique across the suites of every format.
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
    pub const fn has_symmetric_signing(self) -> bool {
        self.specification().symmetric_signature_algorithm.is_some()
    }
}

impl From<EsdkAlgorithmSuiteId> for AlgorithmSuiteId {
    fn from(id: EsdkAlgorithmSuiteId) -> Self {
        Self::Esdk(id)
    }
}

impl From<DbeAlgorithmSuiteId> for AlgorithmSuiteId {
    fn from(id: DbeAlgorithmSuiteId) -> Self {
        Self::Dbe(id)
    }
}

/// DBE Format Algorithm Suite ENUM: the suites of the AWS Database Encryption SDK.
/// Its variants correspond 1:1 to the DBE rows of the Supported Algorithm Suites table.
///
/// Every DBE suite signs with HMAC-SHA-384 and wraps data keys with intermediate key wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DbeAlgorithmSuiteId {
    /// 67 00 — DBE.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384
    AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384,
    /// 67 01 — DBE.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
    AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384,
}

const ALL_DBE_SUITES: [DbeAlgorithmSuiteId; 2] = [
    DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384,
    DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384,
];

/// The intermediate key wrapping every DBE suite uses: HKDF-SHA-512 derives both
/// the key-encryption key and the MAC key, and AES-256-GCM encrypts the data key.
const DBE_EDK_WRAPPING: EdkWrapping =
    EdkWrapping::IntermediateKeyWrapping(IntermediateKeyWrapping {
        key_encryption_key_kdf: KeyDerivationAlgorithm::HkdfSha512,
        mac_key_kdf: KeyDerivationAlgorithm::HkdfSha512,
    });

impl DbeAlgorithmSuiteId {
    /// Every DBE algorithm suite id, in ascending on-wire id order.
    pub const ALL: &'static [DbeAlgorithmSuiteId] = &ALL_DBE_SUITES;

    /// Looks up the DBE suite with the given on-wire id; the inverse of [`Self::id_bytes`].
    ///
    /// Returns `None` if no DBE suite has that id.
    pub fn from_id_bytes(bytes: [u8; 2]) -> Option<DbeAlgorithmSuiteId> {
        Self::ALL.iter().copied().find(|id| id.id_bytes() == bytes)
    }

    /// Materialize the [`AlgorithmSuite`] specification table for this suite ID.
    pub const fn specification(self) -> AlgorithmSuite {
        match self {
            Self::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384 => AlgorithmSuite {
                id: [0x67, 0x00],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha512,
                commit_kdf: Some(KeyDerivationAlgorithm::HkdfSha512),
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: Some(SymmetricSignatureAlgorithm::HmacSha384),
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
                edk_wrapping: DBE_EDK_WRAPPING,
            },
            Self::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384 => AlgorithmSuite {
                id: [0x67, 0x01],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha512,
                commit_kdf: Some(KeyDerivationAlgorithm::HkdfSha512),
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP384),
                symmetric_signature_algorithm: Some(SymmetricSignatureAlgorithm::HmacSha384),
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
                edk_wrapping: DBE_EDK_WRAPPING,
            },
        }
    }

    /// Returns the on-wire 2-byte algorithm suite identifier.
    pub const fn id_bytes(self) -> [u8; 2] {
        self.specification().id
    }

    /// Returns true when this suite has an asymmetric signature algorithm.
    pub const fn has_asymmetric_signing(self) -> bool {
        self.specification()
            .asymmetric_signature_algorithm
            .is_some()
    }

    /// Returns true when this suite has a symmetric signature algorithm; always true for DBE suites.
    pub const fn has_symmetric_signing(self) -> bool {
        self.specification().symmetric_signature_algorithm.is_some()
    }
}
/// ESDK Format Algorithm Suite ENUM.
/// Its variants correspond 1:1 to the ESDK rows of the Supported Algorithm Suites table.
///
/// Construct an `AlgorithmSuite` from a variant via [`Self::specification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EsdkAlgorithmSuiteId {
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

const ALL_SUITES: [EsdkAlgorithmSuiteId; 11] = [
    EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
    EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
    EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
    EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
    EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
    EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
    EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
    EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
    EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
    EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
];

// Ties `ALL_SUITES` to `EsdkAlgorithmSuiteId` at compile time.
// The match has no wildcard arm, so a new suite fails to compile until it is mapped here.
// Each arm indexes `ALL_SUITES`, so the array must grow to match or const evaluation fails.
// Never called; the coupling is the point.
#[expect(
    dead_code,
    reason = "exists for its exhaustiveness check, not to be called"
)]
const fn exhaustive_over_algorithm_suite_id(id: EsdkAlgorithmSuiteId) -> EsdkAlgorithmSuiteId {
    match id {
        EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf => ALL_SUITES[0],
        EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf => ALL_SUITES[1],
        EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf => ALL_SUITES[2],
        EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256 => ALL_SUITES[3],
        EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256 => ALL_SUITES[4],
        EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256 => ALL_SUITES[5],
        EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => ALL_SUITES[6],
        EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => ALL_SUITES[7],
        EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => ALL_SUITES[8],
        EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey => ALL_SUITES[9],
        EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => ALL_SUITES[10],
    }
}

impl EsdkAlgorithmSuiteId {
    /// Every algorithm suite id, in ascending on-wire id order.
    pub const ALL: &'static [EsdkAlgorithmSuiteId] = &ALL_SUITES;

    /// Looks up the suite with the given on-wire id; the inverse of [`Self::id_bytes`].
    ///
    /// Returns `None` if no suite has that id.
    pub fn from_id_bytes(bytes: [u8; 2]) -> Option<EsdkAlgorithmSuiteId> {
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
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
                edk_wrapping: EdkWrapping::DirectKeyWrapping,
            },
        }
    }

    /// Returns the on-wire 2-byte algorithm suite identifier.
    ///
    /// The identifier is unique across the suites of every format.
    /// The reserved value `00 00` is never produced.
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
    /// `false` for any constructible variant of `EsdkAlgorithmSuiteId`. The
    /// MUST-NOT-generate / MUST-NOT-verify clauses are enforced at the
    /// `EncryptionMaterialsBuilder::build` / `DecryptionMaterialsBuilder::build` boundary.
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
    edk_wrapping: EdkWrapping,
}

impl AlgorithmSuite {
    /// Returns the suite's 2-byte algorithm suite identifier.
    #[must_use]
    pub const fn id(&self) -> [u8; 2] {
        self.id
    }

    #[must_use]
    pub const fn encryption_algorithm(&self) -> EncryptionAlgorithm {
        self.encryption_algorithm
    }

    #[must_use]
    pub const fn encryption_algorithm_mode(&self) -> EncryptionAlgorithmMode {
        self.encryption_algorithm_mode
    }

    /// Returns the encryption key length, in bytes.
    #[must_use]
    pub const fn encryption_key_length(&self) -> usize {
        self.encryption_key_length
    }

    /// Returns the IV length, in bytes (12 for every ESDK suite).
    #[must_use]
    pub const fn iv_length(&self) -> usize {
        self.iv_length
    }

    /// Returns the authentication tag length, in bytes (16 for every ESDK suite).
    #[must_use]
    pub const fn authentication_tag_length(&self) -> usize {
        self.authentication_tag_length
    }

    #[must_use]
    pub const fn encryption_kdf(&self) -> KeyDerivationAlgorithm {
        self.encryption_kdf
    }

    #[must_use]
    pub const fn commit_kdf(&self) -> Option<KeyDerivationAlgorithm> {
        self.commit_kdf
    }

    /// Returns true when this suite has a commitment KDF (i.e. its
    /// [Key Commitment] value is True). Convenience predicate so callers can
    /// match the spec phrasing literally.
    ///
    /// [Key Commitment]: ../../../spec/framework/algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings
    #[must_use]
    pub const fn key_commitment(&self) -> bool {
        self.commit_kdf.is_some()
    }

    #[must_use]
    pub const fn asymmetric_signature_algorithm(&self) -> Option<AsymmetricSignatureAlgorithm> {
        self.asymmetric_signature_algorithm
    }

    #[must_use]
    pub const fn symmetric_signature_algorithm(&self) -> Option<SymmetricSignatureAlgorithm> {
        self.symmetric_signature_algorithm
    }

    /// Returns the message format version byte (`0x01` for V1, `0x02` for V2).
    #[must_use]
    pub const fn message_format_version(&self) -> u8 {
        self.message_format_version
    }

    /// Returns the algorithm suite data field length, in bytes.
    #[must_use]
    pub const fn algorithm_suite_data_length(&self) -> usize {
        self.algorithm_suite_data_length
    }

    /// Returns how keyrings wrap the data key under this suite.
    #[must_use]
    pub const fn edk_wrapping(&self) -> EdkWrapping {
        self.edk_wrapping
    }

    /// Required length of a verification key (public point, SEC1 compressed
    /// `tag || X` where `tag` is `0x02` when Y is even and `0x03` when Y is
    /// odd) for this suite, in bytes. Returns `None` for non-signing suites.
    #[must_use]
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

/// Symmetric signature algorithm. No ESDK suite uses one; every DBE suite uses HMAC-SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymmetricSignatureAlgorithm {
    HmacSha384,
}

// ============================================================================
// EDK wrapping algorithm
// ============================================================================

/// How a keyring wraps the plaintext data key into an encrypted data key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EdkWrapping {
    /// The keyring encrypts the plaintext data key itself.
    DirectKeyWrapping,
    /// The keyring encrypts a fresh intermediate key; keys derived from it
    /// encrypt the plaintext data key and sign the message.
    IntermediateKeyWrapping(IntermediateKeyWrapping),
}

/// The key derivations of [`EdkWrapping::IntermediateKeyWrapping`].
///
/// The plaintext data key is encrypted with AES-GCM at the suite's encryption key length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct IntermediateKeyWrapping {
    key_encryption_key_kdf: KeyDerivationAlgorithm,
    mac_key_kdf: KeyDerivationAlgorithm,
}

impl IntermediateKeyWrapping {
    /// The KDF that derives the key that encrypts the plaintext data key.
    #[must_use]
    pub const fn key_encryption_key_kdf(&self) -> KeyDerivationAlgorithm {
        self.key_encryption_key_kdf
    }

    /// The KDF that derives the symmetric signing (MAC) key.
    #[must_use]
    pub const fn mac_key_kdf(&self) -> KeyDerivationAlgorithm {
        self.mac_key_kdf
    }
}

// ============================================================================
// Cryptographic format identifier
// ============================================================================

/// Cryptographic format identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// AWS Encryption SDK Message Format / "ESDK".
    Esdk,
    /// AWS Database Encryption SDK Structured Data Format / "DBE".
    Dbe,
}

impl Format {
    pub const fn long_name(self) -> &'static str {
        match self {
            Self::Esdk => "AWS Encryption SDK Message Format",
            Self::Dbe => "AWS Database Encryption SDK Structured Data Format",
        }
    }

    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Esdk => "ESDK",
            Self::Dbe => "DBE",
        }
    }
}

// ============================================================================
// Key newtypes
// ============================================================================

/// Plaintext data key (secret).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlaintextDataKey(Vec<u8>);

impl From<Vec<u8>> for PlaintextDataKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl PlaintextDataKey {
    /// Wrap `bytes`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `self` and `other` hold the same bytes, compared in constant time.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        aws_mpl_primitives::constant_time_equal(&self.0, &other.0)
    }
}

/// An `InvalidMaterials` error unless `key` is `suite`'s encryption key length.
pub(crate) fn check_data_key_length(
    suite: &AlgorithmSuite,
    key: &PlaintextDataKey,
) -> Result<(), Error> {
    let expected_len = suite.encryption_key_length();
    if key.len() != expected_len {
        return Err(Error::new(
            Kind::InvalidMaterials,
            format!(
                "plaintext data key is {} bytes, expected {expected_len} for the algorithm suite",
                key.len(),
            ),
        ));
    }
    Ok(())
}

impl fmt::Debug for PlaintextDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlaintextDataKey([REDACTED; {} bytes])", self.0.len())
    }
}

/// Signing key (secret).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey(Vec<u8>);

impl From<Vec<u8>> for SigningKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl SigningKey {
    /// Wrap `bytes`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `self` and `other` hold the same bytes, compared in constant time.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        aws_mpl_primitives::constant_time_equal(&self.0, &other.0)
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

impl From<Vec<u8>> for VerificationKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl VerificationKey {
    /// Wrap `bytes`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Symmetric signing key (secret).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricSigningKey(Vec<u8>);

impl From<Vec<u8>> for SymmetricSigningKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl SymmetricSigningKey {
    /// Wrap `bytes`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `self` and `other` hold the same bytes, compared in constant time.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        aws_mpl_primitives::constant_time_equal(&self.0, &other.0)
    }
}

impl fmt::Debug for SymmetricSigningKey {
    //
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymmetricSigningKey([REDACTED; {} bytes])", self.0.len())
    }
}
