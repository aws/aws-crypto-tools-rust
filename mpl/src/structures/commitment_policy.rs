// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commitment policy enum and per-policy algorithm-suite predicates.

use super::algorithm_suite::{AlgorithmSuiteId, EsdkAlgorithmSuiteId};

// Only the ESDK format is implemented. The DBE.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
// commitment policy is excluded by the same rationale that excludes DBE/S3EC
// algorithm suites in `algorithm_suite.rs`.

/// Union Commitment Policy ENUM across all supported formats. Each variant
/// tags a format and carries that format's Format Commitment Policy ENUM,
/// matching the spec's `Format.FormatENUM` notation. For example,
/// `ESDK.FORBID_ENCRYPT_ALLOW_DECRYPT` becomes
/// `CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentPolicy {
    /// ESDK format commitment policies.
    Esdk(Esdk),
}

/// ESDK Format Commitment Policy ENUM. Its variants correspond 1:1 to the
/// rows of the ESDK Commitment Policy ENUM table in `commitment-policy.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Esdk {
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
    /// Returns the algorithm suite that MUST be used for encryption when the
    /// caller does not specify one. Defined per-variant by `commitment-policy.md`.
    pub const fn default_algorithm_suite_id(self) -> AlgorithmSuiteId {
        AlgorithmSuiteId::Esdk(match self {
            Self::Esdk(Esdk::ForbidEncryptAllowDecrypt) => {
                EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
            }
            Self::Esdk(Esdk::RequireEncryptAllowDecrypt) => {
                EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
            }
            Self::Esdk(Esdk::RequireEncryptRequireDecrypt) => {
                EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
            }
        })
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for encryption (the Get Encryption Materials path).
    pub const fn allows_for_encrypt(self, id: AlgorithmSuiteId) -> bool {
        match (self, id) {
            (Self::Esdk(policy), AlgorithmSuiteId::Esdk(id)) => {
                let committing = id.specification().key_commitment();
                match policy {
                    Esdk::ForbidEncryptAllowDecrypt => !committing,
                    Esdk::RequireEncryptAllowDecrypt => committing,
                    Esdk::RequireEncryptRequireDecrypt => committing,
                }
            }
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for decryption (the Decrypt Materials path).
    pub const fn allows_for_decrypt(self, id: AlgorithmSuiteId) -> bool {
        match (self, id) {
            (Self::Esdk(policy), AlgorithmSuiteId::Esdk(id)) => match policy {
                Esdk::ForbidEncryptAllowDecrypt => true,
                Esdk::RequireEncryptAllowDecrypt => true,
                Esdk::RequireEncryptRequireDecrypt => id.specification().key_commitment(),
            },
        }
    }
}
