// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commitment policy enums for the Material Providers Library.

/// ESDK commitment policy values.
//= spec/framework/commitment-policy.md#supported-format-commitment-policy-enum
//# The Material Providers Library MUST provide
//# a distinct commitment policy ENUM for each format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EsdkCommitmentPolicy {
    /// Forbid encryption with key commitment, allow decryption of all suites.
    ForbidEncryptAllowDecrypt,
    /// Require encryption with key commitment, allow decryption of all suites.
    RequireEncryptAllowDecrypt,
    /// Require key commitment for both encryption and decryption.
    RequireEncryptRequireDecrypt,
}

/// DBE commitment policy values.
///
/// DBE only supports `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DbeCommitmentPolicy {
    /// Require key commitment for both encryption and decryption.
    RequireEncryptRequireDecrypt,
}

/// Union enum for all commitment policy types across supported formats.
//= spec/framework/commitment-policy.md#supported-commitment-policy-enum
//# The Material Providers Library also MUST provide
//# a union ENUM for all distinct commitment policy ENUMs
//# called the Commitment Policy ENUM.
//
//= spec/framework/commitment-policy.md#supported-commitment-policy-enum
//# This means that different formats MAY have duplicate Format Commitment Policy ENUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitmentPolicy {
    /// ESDK commitment policy.
    Esdk(EsdkCommitmentPolicy),
    /// DBE commitment policy.
    Dbe(DbeCommitmentPolicy),
}

impl Default for CommitmentPolicy {
    fn default() -> Self {
        Self::Esdk(EsdkCommitmentPolicy::RequireEncryptRequireDecrypt)
    }
}

// --- Behavioral requirements: out of scope, tracked as todo ---

//= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF` MUST be the default algorithm suite

//= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of False

//= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites

//= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - `05 78` MUST be the default algorithm suite

//= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites

//= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - `05 78` MUST be the default algorithm suite

//= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - `67 01` MUST be the default algorithm suite

//= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=todo
//= tracking-issue=commitment-policy-behavior
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
