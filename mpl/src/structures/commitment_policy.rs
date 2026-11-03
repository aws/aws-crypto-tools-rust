// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commitment policy enum and per-policy algorithm-suite predicates.

use super::algorithm_suite::{AlgorithmSuiteId, DbeAlgorithmSuiteId, EsdkAlgorithmSuiteId};

/// Union Commitment Policy ENUM across all supported formats. Each variant
/// tags a format and carries that format's Format Commitment Policy ENUM,
/// matching the spec's `Format.FormatENUM` notation. For example,
/// `ESDK.FORBID_ENCRYPT_ALLOW_DECRYPT` becomes
/// `CommitmentPolicy::Esdk(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentPolicy {
    /// ESDK format commitment policies.
    Esdk(EsdkCommitmentPolicy),
    /// DBE format commitment policies.
    Dbe(DbeCommitmentPolicy),
}

/// DBE Format Commitment Policy ENUM.
/// Every DBE suite commits to its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DbeCommitmentPolicy {
    /// `DBE.REQUIRE_ENCRYPT_REQUIRE_DECRYPT`: encrypt and decrypt with DBE suites only.
    RequireEncryptRequireDecrypt,
}

/// ESDK Format Commitment Policy ENUM. Its variants correspond 1:1 to the
/// rows of the ESDK Commitment Policy ENUM table in `commitment-policy.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EsdkCommitmentPolicy {
    /// `ESDK.FORBID_ENCRYPT_ALLOW_DECRYPT` — encrypt with non-committing suites
    /// only; decrypt any ESDK suite.
    ForbidEncryptAllowDecrypt,
    /// `ESDK.REQUIRE_ENCRYPT_ALLOW_DECRYPT` — encrypt with committing suites
    /// only; decrypt any ESDK suite.
    RequireEncryptAllowDecrypt,
    /// `ESDK.REQUIRE_ENCRYPT_REQUIRE_DECRYPT` — encrypt and decrypt with
    /// committing suites only.
    RequireEncryptRequireDecrypt,
}

impl CommitmentPolicy {
    /// Returns the algorithm suite used for encryption when the caller does
    /// not specify one.
    pub const fn default_algorithm_suite_id(self) -> AlgorithmSuiteId {
        match self {
            // commitment-policy.md says ALG_AES_256_GCM_IV12_TAG16_NO_KDF here;
            // that text is out of date. The Dafny MPL (Defaults.dfy) defaults
            // to ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.
            Self::Esdk(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt) => AlgorithmSuiteId::Esdk(
                EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
            ),
            Self::Esdk(
                EsdkCommitmentPolicy::RequireEncryptAllowDecrypt
                | EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
            ) => AlgorithmSuiteId::Esdk(
                EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
            ),
            Self::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt) => AlgorithmSuiteId::Dbe(
                DbeAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384,
            ),
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for encryption (the Get Encryption Materials path).
    pub const fn allows_for_encrypt(self, id: AlgorithmSuiteId) -> bool {
        match (self, id) {
            (Self::Esdk(policy), AlgorithmSuiteId::Esdk(id)) => {
                let committing = id.specification().key_commitment();
                match policy {
                    EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt => !committing,
                    EsdkCommitmentPolicy::RequireEncryptAllowDecrypt => committing,
                    EsdkCommitmentPolicy::RequireEncryptRequireDecrypt => committing,
                }
            }
            (
                Self::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt),
                AlgorithmSuiteId::Dbe(_),
            ) => true,
            (Self::Esdk(_), AlgorithmSuiteId::Dbe(_))
            | (Self::Dbe(_), AlgorithmSuiteId::Esdk(_)) => false,
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for decryption (the Decrypt Materials path).
    pub const fn allows_for_decrypt(self, id: AlgorithmSuiteId) -> bool {
        match (self, id) {
            (Self::Esdk(policy), AlgorithmSuiteId::Esdk(id)) => match policy {
                EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt => true,
                EsdkCommitmentPolicy::RequireEncryptAllowDecrypt => true,
                EsdkCommitmentPolicy::RequireEncryptRequireDecrypt => {
                    id.specification().key_commitment()
                }
            },
            (
                Self::Dbe(DbeCommitmentPolicy::RequireEncryptRequireDecrypt),
                AlgorithmSuiteId::Dbe(_),
            ) => true,
            (Self::Esdk(_), AlgorithmSuiteId::Dbe(_))
            | (Self::Dbe(_), AlgorithmSuiteId::Esdk(_)) => false,
        }
    }
}
