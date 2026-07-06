// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commitment policy enum and per-policy algorithm-suite predicates.

use super::algorithm_suite::AlgorithmSuiteId;

// Only the ESDK format is implemented. The DBE.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
// commitment policy is excluded by the same rationale that excludes DBE/S3EC
// algorithm suites in `algorithm_suite.rs`.

// Only the ESDK format is implemented in this MPL. The single enum below
// simultaneously fulfills (a) the ESDK Format Commitment Policy ENUM (its
// three variants are the ESDK-row entries) and (b) the union Commitment
// Policy ENUM (because there is no second format whose values would collide).
// The MAY about duplicate Format Commitment Policy ENUM is vacuously
// satisfied: with one format implemented, no two formats can collide.

//
//
/// Selects which ESDK algorithm suites are allowed for encrypt/decrypt and
/// what the default suite is for encryption.
///
/// The three variants correspond 1:1 to the rows of the ESDK Commitment
/// Policy ENUM table in `commitment-policy.md`. DBE is not implemented (see
/// the `type=exception` annotations at the top of this file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommitmentPolicy {
    /// `ESDK.FORBID_ENCRYPT_ALLOW_DECRYPT` — encrypt with non-committing suites
    /// only; decrypt any ESDK suite.
    EsdkForbidEncryptAllowDecrypt,
    /// `ESDK.REQUIRE_ENCRYPT_ALLOW_DECRYPT` — encrypt with committing suites
    /// only; decrypt any ESDK suite.
    EsdkRequireEncryptAllowDecrypt,
    /// `ESDK.REQUIRE_ENCRYPT_REQUIRE_DECRYPT` — encrypt and decrypt with
    /// committing suites only.
    EsdkRequireEncryptRequireDecrypt,
}

impl CommitmentPolicy {
    /// Returns the algorithm suite that MUST be used for encryption when the
    /// caller does not specify one. Defined per-variant by `commitment-policy.md`.
    pub const fn default_algorithm_suite_id(self) -> AlgorithmSuiteId {
        match self {
            Self::EsdkForbidEncryptAllowDecrypt => AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
            Self::EsdkRequireEncryptAllowDecrypt => {
                AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
            }
            Self::EsdkRequireEncryptRequireDecrypt => {
                AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
            }
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for encryption (the Get Encryption Materials path).
    pub const fn allows_for_encrypt(self, id: AlgorithmSuiteId) -> bool {
        match self {
            Self::EsdkForbidEncryptAllowDecrypt => !id.specification().key_commitment(),
            Self::EsdkRequireEncryptAllowDecrypt => id.specification().key_commitment(),
            Self::EsdkRequireEncryptRequireDecrypt => id.specification().key_commitment(),
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for decryption (the Decrypt Materials path).
    pub const fn allows_for_decrypt(self, id: AlgorithmSuiteId) -> bool {
        match self {
            Self::EsdkForbidEncryptAllowDecrypt => true,
            Self::EsdkRequireEncryptAllowDecrypt => true,
            Self::EsdkRequireEncryptRequireDecrypt => id.specification().key_commitment(),
        }
    }
}
