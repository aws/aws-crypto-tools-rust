// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Algorithm-suite helpers shared by the encrypt, decrypt, and message layers.
//!
//! The Material Providers Library (`aws_crypto_mpl`) exposes an
//! [`AlgorithmSuiteId`](aws_crypto_mpl::structures::AlgorithmSuiteId) enum and an
//! opaque [`AlgorithmSuite`](aws_crypto_mpl::structures::AlgorithmSuite)
//! specification (fields private, read via accessor methods). The MPL only
//! provides the forward `id -> specification` mapping; the ESDK message format
//! carries the 2-byte suite id on the wire, so this module supplies the reverse
//! `bytes -> id` lookup and small accessors that adapt the MPL suite shape to the
//! values the ESDK serialization and key-derivation code needs.

use crate::error::{Error, esdk_err, val_err};
use aws_crypto_mpl::structures::{
    AlgorithmSuite, AlgorithmSuiteId, AsymmetricSignatureAlgorithm, KeyDerivationAlgorithm,
};
use aws_mpl_primitives::{DigestAlg, EcdsaSignatureAlgorithm};

/// Every ESDK algorithm suite id, used to build the reverse `[u8; 2] -> id` lookup.
///
/// Kept in step with the MPL by `exhaustive_over_algorithm_suite_id` below.
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

// Ties `ALL_SUITES` to the MPL enum at compile time. The match has no wildcard
// arm, so a suite added to `AlgorithmSuiteId` fails to compile until it is
// mapped here; each arm indexes `ALL_SUITES`, so the array must grow to match or
// the index fails const evaluation. Never called -- the coupling is the point.
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

/// Resolve a 2-byte on-wire algorithm suite id to its [`AlgorithmSuiteId`].
///
/// The MPL exposes only the forward `id -> [u8; 2]` direction, so the ESDK
/// scans the supported-suites table to invert it.
///
/// # Errors
/// Returns an error if `bytes` is not a supported ESDK algorithm suite id.
pub fn algorithm_suite_id_from_bytes(bytes: [u8; 2]) -> Result<AlgorithmSuiteId, Error> {
    //= spec/data-format/message-header.md#algorithm-suite-id
    //# The value (hex) of this field MUST be a value that exists in the
    //# [Supported Algorithm Suites](../framework/algorithm-suites.md#supported-algorithm-suites) table.
    //
    //= spec/data-format/message-header.md#algorithm-suite-id
    //# This algorithm suite MUST be [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum).
    ALL_SUITES
        .into_iter()
        .find(|id| id.id_bytes() == bytes)
        .ok_or_else(|| {
            esdk_err(format!(
                "Unrecognized or unsupported algorithm suite ID: 0x{:02X}{:02X}",
                bytes[0], bytes[1]
            ))
        })
}

/// Resolve a 2-byte on-wire algorithm suite id to its [`AlgorithmSuite`] specification.
///
/// # Errors
/// Returns an error if `bytes` is not a supported ESDK algorithm suite id.
pub fn algorithm_suite_from_bytes(bytes: [u8; 2]) -> Result<AlgorithmSuite, Error> {
    Ok(algorithm_suite_id_from_bytes(bytes)?.specification())
}

/// Maps an MPL [`KeyDerivationAlgorithm`] to the primitives [`DigestAlg`] that
/// drives its HKDF, or an error if the KDF is the identity KDF (no hash).
///
/// # Errors
/// Returns an error if `kdf` is the identity KDF.
pub(crate) fn kdf_digest(kdf: KeyDerivationAlgorithm) -> Result<DigestAlg, Error> {
    match kdf {
        KeyDerivationAlgorithm::HkdfSha256 => Ok(DigestAlg::Sha256),
        KeyDerivationAlgorithm::HkdfSha384 => Ok(DigestAlg::Sha384),
        KeyDerivationAlgorithm::HkdfSha512 => Ok(DigestAlg::Sha512),
        KeyDerivationAlgorithm::IdentityKdf => Err(val_err("Identity KDF has no hash function")),
    }
}

/// Extracts the ECDSA signature algorithm for a signing suite, mapping the MPL
/// [`AsymmetricSignatureAlgorithm`] to the primitives [`EcdsaSignatureAlgorithm`].
///
/// # Errors
/// Returns an error if the suite has no asymmetric signature algorithm.
pub fn get_ecdsa_alg(suite: &AlgorithmSuite) -> Result<EcdsaSignatureAlgorithm, Error> {
    match suite.asymmetric_signature_algorithm() {
        Some(AsymmetricSignatureAlgorithm::EcdsaP256) => Ok(EcdsaSignatureAlgorithm::EcdsaP256),
        Some(AsymmetricSignatureAlgorithm::EcdsaP384) => Ok(EcdsaSignatureAlgorithm::EcdsaP384),
        None => Err(val_err("Algorithm suite has no ECDSA signature algorithm")),
    }
}
