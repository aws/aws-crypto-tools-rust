// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commitment policy enum and per-policy algorithm-suite predicates.

use super::algorithm_suite::AlgorithmSuiteId;

// Only the ESDK format is implemented. The DBE.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
// commitment policy is excluded by the same rationale that excludes DBE/S3EC
// algorithm suites in `algorithm_suite.rs`.

/// Union Commitment Policy ENUM across all supported formats. Each variant
/// tags a format and carries that format's Format Commitment Policy ENUM,
/// matching the spec's `Format.FormatENUM` notation. For example,
/// `ESDK.FORBID_ENCRYPT_ALLOW_DECRYPT` becomes
/// `CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt)`.
//= spec/framework/commitment-policy.md#supported-commitment-policy-enum
//= type=implication
//# The Material Providers Library also MUST provide
//# a union ENUM for all distinct commitment policy ENUMs
//# called the Commitment Policy ENUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommitmentPolicy {
    /// ESDK format commitment policies.
    Esdk(Esdk),
}

/// ESDK Format Commitment Policy ENUM. Its variants correspond 1:1 to the
/// rows of the ESDK Commitment Policy ENUM table in `commitment-policy.md`.
//= spec/framework/commitment-policy.md#supported-format-commitment-policy-enum
//= type=implication
//# The Material Providers Library MUST provide
//# a distinct commitment policy ENUM for each format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        match self {
            //= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
            //# - `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF` MUST be the default algorithm suite
            Self::Esdk(Esdk::ForbidEncryptAllowDecrypt) => {
                AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
            }
            //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
            //# - `05 78` MUST be the default algorithm suite
            Self::Esdk(Esdk::RequireEncryptAllowDecrypt) => {
                AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
            }
            //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
            //# - `05 78` MUST be the default algorithm suite
            Self::Esdk(Esdk::RequireEncryptRequireDecrypt) => {
                AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
            }
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for encryption (the Get Encryption Materials path).
    pub const fn allows_for_encrypt(self, id: AlgorithmSuiteId) -> bool {
        match self {
            //= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
            //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of False
            Self::Esdk(Esdk::ForbidEncryptAllowDecrypt) => !id.specification().key_commitment(),
            //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
            //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
            Self::Esdk(Esdk::RequireEncryptAllowDecrypt) => id.specification().key_commitment(),
            //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
            //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
            Self::Esdk(Esdk::RequireEncryptRequireDecrypt) => id.specification().key_commitment(),
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for decryption (the Decrypt Materials path).
    pub const fn allows_for_decrypt(self, id: AlgorithmSuiteId) -> bool {
        match self {
            //= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
            //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites
            Self::Esdk(Esdk::ForbidEncryptAllowDecrypt) => true,
            //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
            //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites
            Self::Esdk(Esdk::RequireEncryptAllowDecrypt) => true,
            //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
            //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
            Self::Esdk(Esdk::RequireEncryptRequireDecrypt) => id.specification().key_commitment(),
        }
    }
}
