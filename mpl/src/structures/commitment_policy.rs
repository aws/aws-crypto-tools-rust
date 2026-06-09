// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commitment policy enum and per-policy algorithm-suite predicates.

use super::algorithm_suite::AlgorithmSuiteId;

// Only the ESDK format is implemented. The DBE.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
// commitment policy is excluded by the same rationale that excludes DBE/S3EC
// algorithm suites in `algorithm_suite.rs`.

//= ../spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - `67 01` MUST be the default algorithm suite

//= ../spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= ../spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

// Only the ESDK format is implemented in this MPL. The single enum below
// simultaneously fulfills (a) the ESDK Format Commitment Policy ENUM (its
// three variants are the ESDK-row entries) and (b) the union Commitment
// Policy ENUM (because there is no second format whose values would collide).
// The MAY about duplicate Format Commitment Policy ENUM is vacuously
// satisfied: with one format implemented, no two formats can collide.

//= ../spec/framework/commitment-policy.md#supported-format-commitment-policy-enum
//# The Material Providers Library MUST provide
//# a distinct commitment policy ENUM for each format.
//
//= ../spec/framework/commitment-policy.md#supported-commitment-policy-enum
//# The Material Providers Library also MUST provide
//# a union ENUM for all distinct commitment policy ENUMs
//# called the Commitment Policy ENUM.
//
//= ../spec/framework/commitment-policy.md#supported-commitment-policy-enum
//# This means that different formats MAY have duplicate Format Commitment Policy ENUM.
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
            //= ../spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
            //# - `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF` MUST be the default algorithm suite
            Self::EsdkForbidEncryptAllowDecrypt => AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
            //= ../spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
            //# - `05 78` MUST be the default algorithm suite
            Self::EsdkRequireEncryptAllowDecrypt => {
                AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
            }
            //= ../spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
            //# - `05 78` MUST be the default algorithm suite
            Self::EsdkRequireEncryptRequireDecrypt => {
                AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
            }
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for encryption (the Get Encryption Materials path).
    pub const fn allows_for_encrypt(self, id: AlgorithmSuiteId) -> bool {
        match self {
            //= ../spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
            //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of False
            Self::EsdkForbidEncryptAllowDecrypt => !id.specification().key_commitment(),
            //= ../spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
            //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
            Self::EsdkRequireEncryptAllowDecrypt => id.specification().key_commitment(),
            //= ../spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
            //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
            Self::EsdkRequireEncryptRequireDecrypt => id.specification().key_commitment(),
        }
    }

    /// Returns true when this commitment policy permits the given algorithm
    /// suite to be used for decryption (the Decrypt Materials path).
    pub const fn allows_for_decrypt(self, id: AlgorithmSuiteId) -> bool {
        match self {
            //= ../spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
            //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites
            Self::EsdkForbidEncryptAllowDecrypt => true,
            //= ../spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
            //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites
            Self::EsdkRequireEncryptAllowDecrypt => true,
            //= ../spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
            //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
            Self::EsdkRequireEncryptRequireDecrypt => id.specification().key_commitment(),
        }
    }
}
